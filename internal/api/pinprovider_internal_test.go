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
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
		if st.Pin != "" || st.Err == "" || st.ErrCode != PinErrCertFileUnreadable {
			t.Errorf("%s: status = %+v, erwartet kein pin mit kategorie %q", name, st, PinErrCertFileUnreadable)
		}
	}

	missing := NewPinProvider(PinProviderConfig{CertFile: filepath.Join(dir, "fehlt.crt")}, logger)
	if st := missing.Status(context.Background()); st.Pin != "" || st.ErrCode != PinErrCertFileUnreadable {
		t.Errorf("fehlende datei: status = %+v, erwartet kein pin mit kategorie %q", st, PinErrCertFileUnreadable)
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
		if st.ErrCode != PinErrChainUntrusted {
			t.Errorf("errcode = %q, erwartet %q", st.ErrCode, PinErrChainUntrusted)
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
		// Der Backoff zwischen Fehlversuchen ist im Test praktisch aus.
		p := NewPinProvider(PinProviderConfig{DialURL: server.URL, Refresh: time.Hour}, logger)
		p.backoff = time.Nanosecond

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
		st := p.Status(context.Background())
		if st.Pin != "" || st.Err == "" {
			t.Fatalf("status = %+v, erwartet kein pin mit fehlergrund", st)
		}
		if st.ErrCode != PinErrNoPublicURL {
			t.Errorf("errcode = %q, erwartet %q", st.ErrCode, PinErrNoPublicURL)
		}
	})

	t.Run("http-url wird abgelehnt", func(t *testing.T) {
		logger, _ := testLogger()
		p := NewPinProvider(PinProviderConfig{DialURL: "http://gssh.example.com", Refresh: time.Nanosecond}, logger)
		st := p.Status(context.Background())
		if st.Pin != "" || !strings.Contains(st.Err, "https") {
			t.Fatalf("status = %+v, erwartet https-fehler", st)
		}
		if st.ErrCode != PinErrNoPublicURL {
			t.Errorf("errcode = %q, erwartet %q", st.ErrCode, PinErrNoPublicURL)
		}
	})
}

// failingDialTarget ist ein TCP-Ziel, das jede Verbindung nach delay ohne
// TLS-Handshake schließt (der Selbst-Dial scheitert damit), und zählt die
// Verbindungsversuche.
func failingDialTarget(t *testing.T, delay time.Duration) (dialURL string, dials func() int) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	var mu sync.Mutex
	count := 0
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			count++
			mu.Unlock()
			time.Sleep(delay)
			_ = conn.Close()
		}
	}()
	return "https://" + listener.Addr().String(), func() int {
		mu.Lock()
		defer mu.Unlock()
		return count
	}
}

// TestPinProviderDialBackoff: ohne je gelesenen Pin darf nicht jeder Request
// einen eigenen Outbound-Handshake auslösen — zwischen Fehlversuchen liegt der
// Backoff, parallele Aufrufer teilen sich einen Dial.
func TestPinProviderDialBackoff(t *testing.T) {
	t.Run("zweiter aufruf im backoff dialt nicht", func(t *testing.T) {
		dialURL, dials := failingDialTarget(t, 0)
		logger, _ := testLogger()
		p := NewPinProvider(PinProviderConfig{DialURL: dialURL}, logger)
		p.backoff = time.Hour

		for i := range 2 {
			if st := p.Status(context.Background()); st.Pin != "" || st.ErrCode != PinErrDialFailed {
				t.Fatalf("aufruf %d: status = %+v, erwartet kein pin mit kategorie %q", i, st, PinErrDialFailed)
			}
		}
		if got := dials(); got != 1 {
			t.Errorf("dials = %d, erwartet 1 (backoff greift)", got)
		}
	})

	t.Run("nach ablauf des backoffs wird erneut gedialt", func(t *testing.T) {
		dialURL, dials := failingDialTarget(t, 0)
		logger, _ := testLogger()
		p := NewPinProvider(PinProviderConfig{DialURL: dialURL}, logger)
		p.backoff = time.Nanosecond

		p.Status(context.Background())
		p.Status(context.Background())
		if got := dials(); got != 2 {
			t.Errorf("dials = %d, erwartet 2 (backoff abgelaufen)", got)
		}
	})

	t.Run("parallele aufrufer teilen sich einen dial", func(t *testing.T) {
		// Der Dial hängt lange genug, dass die übrigen Aufrufer währenddessen
		// eintreffen; ohne Singleflight dialte jeder von ihnen selbst.
		dialURL, dials := failingDialTarget(t, 150*time.Millisecond)
		logger, _ := testLogger()
		p := NewPinProvider(PinProviderConfig{DialURL: dialURL}, logger)
		p.backoff = time.Hour

		var wg sync.WaitGroup
		for range 5 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				p.Status(context.Background())
			}()
		}
		wg.Wait()
		if got := dials(); got != 1 {
			t.Errorf("dials = %d, erwartet 1 (singleflight)", got)
		}
	})
}

// TestPinProviderStatusIgnoriertClientAbbruch: der Lazy-Dial läuft mit einem
// vom Request entkoppelten Context — ein (auch absichtlich) sofort
// abgebrochener Request darf das gemeinsame Dial-Ergebnis nicht als
// Fehlversuch cachen und damit das Backoff-Fenster verbrennen.
func TestPinProviderStatusIgnoriertClientAbbruch(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	logger, _ := testLogger()
	p := NewPinProvider(PinProviderConfig{DialURL: server.URL}, logger)
	p.dialRoots = trustPool(server.Certificate())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	st := p.Status(ctx)
	if want := pintls.FromCertificate(server.Certificate()); st.Pin != want {
		t.Fatalf("status mit abgebrochenem request-context = %+v, erwartet pin %s", st, want)
	}
}

// TestPinProviderRunDrosseltNicht: der Run-Loop ist der geplante Refresh —
// jeder Tick dialt, unabhängig vom Fehler-Backoff der Request-Pfade und ohne
// Fälligkeitsprüfung (die den Tick sonst regelmäßig knapp verfehlte).
func TestPinProviderRunDrosseltNicht(t *testing.T) {
	dialURL, dials := failingDialTarget(t, 0)
	logger, _ := testLogger()
	// Backoff im Default (10 s): mit Fälligkeitsprüfung wäre nach dem ersten
	// Fehlversuch kein weiterer Tick „due" und der Loop dialte nie wieder.
	p := NewPinProvider(PinProviderConfig{DialURL: dialURL, Refresh: 10 * time.Millisecond}, logger)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		p.Run(ctx)
		close(done)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for dials() < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	if got := dials(); got < 3 {
		t.Errorf("dials = %d, erwartet ≥ 3 (run-loop wird gedrosselt)", got)
	}
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
