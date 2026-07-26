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

// testLogger returns a logger with a buffer, so tests can check the
// warnings of source precedence.
func testLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewTextHandler(&buf, nil)), &buf
}

// testCertPEM creates a self-signed certificate as PEM plus its pin.
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

// writeCertFile writes a certificate under path and returns its pin.
func writeCertFile(t *testing.T, path, commonName string) string {
	t.Helper()
	pemBytes, pin := testCertPEM(t, commonName)
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return pin
}

// TestPinProviderPrecedence: static beats file beats dial, and the
// displaced sources are logged with a warning.
func TestPinProviderPrecedence(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls.crt")
	filePin := writeCertFile(t, certPath, "file")
	staticPin := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

	t.Run("static wins", func(t *testing.T) {
		logger, buf := testLogger()
		p := NewPinProvider(PinProviderConfig{
			StaticPin: staticPin, CertFile: certPath, DialURL: "https://gssh.example.com",
		}, logger)
		st := p.Status(context.Background())
		if st.Pin != staticPin || st.Source != PinSourceStatic {
			t.Fatalf("status = %+v, expected static pin", st)
		}
		if !strings.Contains(buf.String(), "multiple pin sources") {
			t.Error("warning about displaced sources missing")
		}
	})

	t.Run("file beats dial", func(t *testing.T) {
		logger, buf := testLogger()
		p := NewPinProvider(PinProviderConfig{CertFile: certPath, DialURL: "https://gssh.example.com"}, logger)
		st := p.Status(context.Background())
		if st.Pin != filePin || st.Source != PinSourceFile {
			t.Fatalf("status = %+v, expected file pin %s", st, filePin)
		}
		if !strings.Contains(buf.String(), "multiple pin sources") {
			t.Error("warning about displaced dial source missing")
		}
	})

	t.Run("dial is default", func(t *testing.T) {
		logger, _ := testLogger()
		p := NewPinProvider(PinProviderConfig{DialURL: "https://gssh.example.com"}, logger)
		if p.Source() != PinSourceDial {
			t.Fatalf("source = %q, expected %q", p.Source(), PinSourceDial)
		}
	})
}

// TestPinProviderFileSource: the file is read fresh on every serve
// (secret rotation takes effect immediately), errors keep the gate closed.
func TestPinProviderFileSource(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls.crt")
	firstPin := writeCertFile(t, certPath, "first")

	logger, _ := testLogger()
	p := NewPinProvider(PinProviderConfig{CertFile: certPath}, logger)
	if st := p.Status(context.Background()); st.Pin != firstPin {
		t.Fatalf("pin = %q, expected %q", st.Pin, firstPin)
	}

	secondPin := writeCertFile(t, certPath, "second")
	if secondPin == firstPin {
		t.Fatal("test setup: both certificates have the same pin")
	}
	if st := p.Status(context.Background()); st.Pin != secondPin {
		t.Fatalf("pin after rotation = %q, expected %q (no caching)", st.Pin, secondPin)
	}

	// The leaf is the first CERTIFICATE block (cert-manager convention).
	leafPEM, leafPin := testCertPEM(t, "leaf")
	chainPEM, _ := testCertPEM(t, "intermediate")
	if err := os.WriteFile(certPath, append(leafPEM, chainPEM...), 0o600); err != nil {
		t.Fatal(err)
	}
	if st := p.Status(context.Background()); st.Pin != leafPin {
		t.Fatalf("pin of the chain = %q, expected leaf pin %q", st.Pin, leafPin)
	}

	for name, content := range map[string][]byte{
		"no pem":     []byte("not a certificate"),
		"empty file": nil,
	} {
		if err := os.WriteFile(certPath, content, 0o600); err != nil {
			t.Fatal(err)
		}
		st := p.Status(context.Background())
		if st.Pin != "" || st.Err == "" || st.ErrCode != PinErrCertFileUnreadable {
			t.Errorf("%s: status = %+v, expected no pin with category %q", name, st, PinErrCertFileUnreadable)
		}
	}

	missing := NewPinProvider(PinProviderConfig{CertFile: filepath.Join(dir, "missing.crt")}, logger)
	if st := missing.Status(context.Background()); st.Pin != "" || st.ErrCode != PinErrCertFileUnreadable {
		t.Errorf("missing file: status = %+v, expected no pin with category %q", st, PinErrCertFileUnreadable)
	}
}

// TestPinProviderDialSource: the self-dial returns the pin of the leaf
// certificate, but verifies the chain fail-closed while doing so.
func TestPinProviderDialSource(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	wantPin := pintls.FromCertificate(server.Certificate())

	t.Run("trusted chain returns a pin", func(t *testing.T) {
		logger, _ := testLogger()
		p := NewPinProvider(PinProviderConfig{DialURL: server.URL, Refresh: time.Nanosecond}, logger)
		p.dialRoots = trustPool(server.Certificate())

		st := p.Status(context.Background())
		if st.Pin != wantPin || st.Source != PinSourceDial {
			t.Fatalf("status = %+v, expected dial pin %s", st, wantPin)
		}
	})

	t.Run("untrusted ca returns no pin", func(t *testing.T) {
		logger, _ := testLogger()
		// Without dialRoots, the system roots apply; the self-signed test
		// certificate must be rejected (no insecure fallback).
		p := NewPinProvider(PinProviderConfig{DialURL: server.URL, Refresh: time.Nanosecond}, logger)

		st := p.Status(context.Background())
		if st.Pin != "" || st.Err == "" {
			t.Fatalf("status = %+v, expected no pin with an error reason", st)
		}
		if st.ErrCode != PinErrChainUntrusted {
			t.Errorf("errcode = %q, expected %q", st.ErrCode, PinErrChainUntrusted)
		}
	})

	t.Run("last pin survives a failed refresh", func(t *testing.T) {
		failing := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
		logger, _ := testLogger()
		p := NewPinProvider(PinProviderConfig{DialURL: failing.URL, Refresh: time.Nanosecond}, logger)
		p.dialRoots = trustPool(failing.Certificate())

		first := p.Status(context.Background())
		if first.Pin == "" {
			t.Fatalf("first dial returned no pin: %+v", first)
		}
		failing.Close()

		st := p.Status(context.Background())
		if st.Pin != first.Pin || st.Source != PinSourceDial {
			t.Fatalf("status = %+v, expected pin %s to still be present", st, first.Pin)
		}
		if st.Err == "" {
			t.Error("failed refresh is not reported as a reason")
		}
	})

	t.Run("without a pin, dials again despite the interval", func(t *testing.T) {
		logger, _ := testLogger()
		// Long interval: the second attempt must not get stuck on the
		// cache, otherwise the gate would stay closed for minutes after a
		// startup error. The backoff between failed attempts is
		// effectively disabled in the test.
		p := NewPinProvider(PinProviderConfig{DialURL: server.URL, Refresh: time.Hour}, logger)
		p.backoff = time.Nanosecond

		if st := p.Status(context.Background()); st.Pin != "" {
			t.Fatalf("status = %+v, expected no pin (system roots)", st)
		}
		p.dialRoots = trustPool(server.Certificate())
		if st := p.Status(context.Background()); st.Pin != wantPin {
			t.Fatalf("status = %+v, expected pin %s on the next attempt", st, wantPin)
		}
	})

	t.Run("no pin without a public url", func(t *testing.T) {
		logger, _ := testLogger()
		p := NewPinProvider(PinProviderConfig{Refresh: time.Nanosecond}, logger)
		st := p.Status(context.Background())
		if st.Pin != "" || st.Err == "" {
			t.Fatalf("status = %+v, expected no pin with an error reason", st)
		}
		if st.ErrCode != PinErrNoPublicURL {
			t.Errorf("errcode = %q, expected %q", st.ErrCode, PinErrNoPublicURL)
		}
	})

	t.Run("http url is rejected", func(t *testing.T) {
		logger, _ := testLogger()
		p := NewPinProvider(PinProviderConfig{DialURL: "http://gssh.example.com", Refresh: time.Nanosecond}, logger)
		st := p.Status(context.Background())
		if st.Pin != "" || !strings.Contains(st.Err, "https") {
			t.Fatalf("status = %+v, expected an https error", st)
		}
		if st.ErrCode != PinErrNoPublicURL {
			t.Errorf("errcode = %q, expected %q", st.ErrCode, PinErrNoPublicURL)
		}
	})
}

// failingDialTarget is a TCP target that closes every connection after
// delay without a TLS handshake (the self-dial thus fails), and counts the
// connection attempts.
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

// TestPinProviderDialBackoff: without a pin ever having been read, not
// every request may trigger its own outbound handshake — the backoff sits
// between failed attempts, concurrent callers share one dial.
func TestPinProviderDialBackoff(t *testing.T) {
	t.Run("second call within backoff does not dial", func(t *testing.T) {
		dialURL, dials := failingDialTarget(t, 0)
		logger, _ := testLogger()
		p := NewPinProvider(PinProviderConfig{DialURL: dialURL}, logger)
		p.backoff = time.Hour

		for i := range 2 {
			if st := p.Status(context.Background()); st.Pin != "" || st.ErrCode != PinErrDialFailed {
				t.Fatalf("call %d: status = %+v, expected no pin with category %q", i, st, PinErrDialFailed)
			}
		}
		if got := dials(); got != 1 {
			t.Errorf("dials = %d, expected 1 (backoff applies)", got)
		}
	})

	t.Run("dials again once the backoff has elapsed", func(t *testing.T) {
		dialURL, dials := failingDialTarget(t, 0)
		logger, _ := testLogger()
		p := NewPinProvider(PinProviderConfig{DialURL: dialURL}, logger)
		p.backoff = time.Nanosecond

		p.Status(context.Background())
		p.Status(context.Background())
		if got := dials(); got != 2 {
			t.Errorf("dials = %d, expected 2 (backoff elapsed)", got)
		}
	})

	t.Run("concurrent callers share one dial", func(t *testing.T) {
		// The dial hangs long enough that the other callers arrive in the
		// meantime; without singleflight each of them would dial on its own.
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
			t.Errorf("dials = %d, expected 1 (singleflight)", got)
		}
	})
}

// TestPinProviderStatusIgnoresClientAbort: the lazy dial runs with a
// context decoupled from the request — a (even deliberately) immediately
// canceled request must not cache the shared dial result as a failed
// attempt and thereby burn the backoff window.
func TestPinProviderStatusIgnoresClientAbort(t *testing.T) {
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
		t.Fatalf("status with canceled request context = %+v, expected pin %s", st, want)
	}
}

// TestPinProviderRunDoesNotThrottle: the Run loop is the scheduled refresh —
// every tick dials, regardless of the request paths' error backoff and
// without a due check (which would otherwise regularly just miss the tick).
func TestPinProviderRunDoesNotThrottle(t *testing.T) {
	dialURL, dials := failingDialTarget(t, 0)
	logger, _ := testLogger()
	// Backoff at its default (10s): with a due check, no further tick
	// would be "due" after the first failed attempt and the loop would
	// never dial again.
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
		t.Errorf("dials = %d, expected ≥ 3 (run loop is being throttled)", got)
	}
}

// trustPool builds a root pool that accepts exactly this certificate.
func trustPool(cert *x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pool
}

// TestPinProviderRunTerminates: for the static and file sources there is
// nothing to refresh — Run returns immediately.
func TestPinProviderRunTerminates(t *testing.T) {
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
		t.Fatal("Run blocks with a static source")
	}
}
