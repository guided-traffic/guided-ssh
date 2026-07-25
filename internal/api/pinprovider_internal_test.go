package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guided-traffic/guided-ssh/internal/pintls"
)

// testLogger liefert einen Logger samt Puffer, damit Tests die Warnungen der
// Quellen-Präzedenz prüfen können.
func testLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewTextHandler(&buf, nil)), &buf
}

// testCertPEM erzeugt ein selbstsigniertes Zertifikat als PEM samt Pin.
func testCertPEM(t *testing.T, commonName string) (pemBytes []byte, pin string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pintls.FromCertificate(cert)
}

// writeCertFile legt ein Zertifikat unter path ab und liefert dessen Pin.
func writeCertFile(t *testing.T, path, commonName string) string {
	t.Helper()
	pemBytes, pin := testCertPEM(t, commonName)
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return pin
}

// TestPinProviderPräzedenz: statisch schlägt Datei schlägt Dial, und die
// verdrängten Quellen werden mit Warnung protokolliert.
func TestPinProviderPräzedenz(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls.crt")
	filePin := writeCertFile(t, certPath, "datei")
	staticPin := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

	t.Run("statisch gewinnt", func(t *testing.T) {
		logger, buf := testLogger()
		p := NewPinProvider(PinProviderConfig{
			StaticPin: staticPin, CertFile: certPath, DialURL: "https://gssh.example.com",
		}, logger)
		st := p.Status(context.Background())
		if st.Pin != staticPin || st.Source != PinSourceStatic {
			t.Fatalf("status = %+v, erwartet statischer pin", st)
		}
		if !strings.Contains(buf.String(), "mehrere pin-quellen") {
			t.Error("warnung über verdrängte quellen fehlt")
		}
	})

	t.Run("datei schlägt dial", func(t *testing.T) {
		logger, buf := testLogger()
		p := NewPinProvider(PinProviderConfig{CertFile: certPath, DialURL: "https://gssh.example.com"}, logger)
		st := p.Status(context.Background())
		if st.Pin != filePin || st.Source != PinSourceFile {
			t.Fatalf("status = %+v, erwartet datei-pin %s", st, filePin)
		}
		if !strings.Contains(buf.String(), "mehrere pin-quellen") {
			t.Error("warnung über verdrängte dial-quelle fehlt")
		}
	})

	t.Run("dial ist default", func(t *testing.T) {
		logger, _ := testLogger()
		p := NewPinProvider(PinProviderConfig{DialURL: "https://gssh.example.com"}, logger)
		if p.Source() != PinSourceDial {
			t.Fatalf("source = %q, erwartet %q", p.Source(), PinSourceDial)
		}
	})
}

// TestPinProviderDateiQuelle: die Datei wird bei jedem Servieren frisch
// gelesen (Secret-Rotation wirkt sofort), Fehler halten das Gate zu.
func TestPinProviderDateiQuelle(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls.crt")
	firstPin := writeCertFile(t, certPath, "erst")

	logger, _ := testLogger()
	p := NewPinProvider(PinProviderConfig{CertFile: certPath}, logger)
	if st := p.Status(context.Background()); st.Pin != firstPin {
		t.Fatalf("pin = %q, erwartet %q", st.Pin, firstPin)
	}

	secondPin := writeCertFile(t, certPath, "zweit")
	if secondPin == firstPin {
		t.Fatal("testaufbau: beide zertifikate haben denselben pin")
	}
	if st := p.Status(context.Background()); st.Pin != secondPin {
		t.Fatalf("pin nach rotation = %q, erwartet %q (kein caching)", st.Pin, secondPin)
	}

	// Leaf ist der erste CERTIFICATE-Block (cert-manager-Konvention).
	leafPEM, leafPin := testCertPEM(t, "leaf")
	chainPEM, _ := testCertPEM(t, "intermediate")
	if err := os.WriteFile(certPath, append(leafPEM, chainPEM...), 0o600); err != nil {
		t.Fatal(err)
	}
	if st := p.Status(context.Background()); st.Pin != leafPin {
		t.Fatalf("pin der kette = %q, erwartet leaf-pin %q", st.Pin, leafPin)
	}

	for name, content := range map[string][]byte{
		"kein pem":    []byte("kein zertifikat"),
		"leere datei": nil,
	} {
		if err := os.WriteFile(certPath, content, 0o600); err != nil {
			t.Fatal(err)
		}
		st := p.Status(context.Background())
		if st.Pin != "" || st.Err == "" {
			t.Errorf("%s: status = %+v, erwartet kein pin mit fehlergrund", name, st)
		}
	}

	missing := NewPinProvider(PinProviderConfig{CertFile: filepath.Join(dir, "fehlt.crt")}, logger)
	if st := missing.Status(context.Background()); st.Pin != "" || st.Err == "" {
		t.Errorf("fehlende datei: status = %+v, erwartet kein pin mit fehlergrund", st)
	}
}

// TestPinProviderDialQuelle: der Selbst-Dial liefert den Pin des
// Leaf-Zertifikats, verifiziert dabei aber fail-closed die Kette.
func TestPinProviderDialQuelle(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	wantPin := pintls.FromCertificate(server.Certificate())

	t.Run("vertraute kette liefert pin", func(t *testing.T) {
		logger, _ := testLogger()
		p := NewPinProvider(PinProviderConfig{DialURL: server.URL, Refresh: time.Nanosecond}, logger)
		p.dialRoots = trustPool(server.Certificate())

		st := p.Status(context.Background())
		if st.Pin != wantPin || st.Source != PinSourceDial {
			t.Fatalf("status = %+v, erwartet dial-pin %s", st, wantPin)
		}
	})

	t.Run("nicht vertraute ca liefert keinen pin", func(t *testing.T) {
		logger, _ := testLogger()
		// Ohne dialRoots gelten die System-Roots; das selbstsignierte
		// Test-Zertifikat muss abgelehnt werden (kein Insecure-Fallback).
		p := NewPinProvider(PinProviderConfig{DialURL: server.URL, Refresh: time.Nanosecond}, logger)

		st := p.Status(context.Background())
		if st.Pin != "" || st.Err == "" {
			t.Fatalf("status = %+v, erwartet kein pin mit fehlergrund", st)
		}
	})

	t.Run("letzter pin überlebt fehlgeschlagenen refresh", func(t *testing.T) {
		failing := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
		logger, _ := testLogger()
		p := NewPinProvider(PinProviderConfig{DialURL: failing.URL, Refresh: time.Nanosecond}, logger)
		p.dialRoots = trustPool(failing.Certificate())

		first := p.Status(context.Background())
		if first.Pin == "" {
			t.Fatalf("erster dial lieferte keinen pin: %+v", first)
		}
		failing.Close()

		st := p.Status(context.Background())
		if st.Pin != first.Pin || st.Source != PinSourceDial {
			t.Fatalf("status = %+v, erwartet weiterhin pin %s", st, first.Pin)
		}
		if st.Err == "" {
			t.Error("fehlgeschlagener refresh wird nicht als grund gemeldet")
		}
	})

	t.Run("ohne pin wird trotz intervall erneut gedialt", func(t *testing.T) {
		logger, _ := testLogger()
		// Langes Intervall: der zweite Versuch darf nicht am Cache hängen
		// bleiben, sonst bliebe das Gate nach einem Startfehler minutenlang zu.
		p := NewPinProvider(PinProviderConfig{DialURL: server.URL, Refresh: time.Hour}, logger)

		if st := p.Status(context.Background()); st.Pin != "" {
			t.Fatalf("status = %+v, erwartet kein pin (system-roots)", st)
		}
		p.dialRoots = trustPool(server.Certificate())
		if st := p.Status(context.Background()); st.Pin != wantPin {
			t.Fatalf("status = %+v, erwartet pin %s beim nächsten versuch", st, wantPin)
		}
	})

	t.Run("ohne public-url kein pin", func(t *testing.T) {
		logger, _ := testLogger()
		p := NewPinProvider(PinProviderConfig{Refresh: time.Nanosecond}, logger)
		if st := p.Status(context.Background()); st.Pin != "" || st.Err == "" {
			t.Fatalf("status = %+v, erwartet kein pin mit fehlergrund", st)
		}
	})

	t.Run("http-url wird abgelehnt", func(t *testing.T) {
		logger, _ := testLogger()
		p := NewPinProvider(PinProviderConfig{DialURL: "http://gssh.example.com", Refresh: time.Nanosecond}, logger)
		st := p.Status(context.Background())
		if st.Pin != "" || !strings.Contains(st.Err, "https") {
			t.Fatalf("status = %+v, erwartet https-fehler", st)
		}
	})
}

// trustPool baut einen Root-Pool, der genau dieses Zertifikat akzeptiert.
func trustPool(cert *x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pool
}

// TestPinProviderRunBeendetSich: für statische und Datei-Quelle gibt es nichts
// zu refreshen — Run kehrt sofort zurück.
func TestPinProviderRunBeendetSich(t *testing.T) {
	logger, _ := testLogger()
	p := NewPinProvider(PinProviderConfig{StaticPin: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}, logger)

	done := make(chan struct{})
	go func() {
		p.Run(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run blockiert bei statischer quelle")
	}
}
