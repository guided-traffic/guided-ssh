package agentd

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testPKI baut eine Wegwerf-PKI (CA, Server-Zertifikat, Client-Zertifikat)
// und legt das Client-Material wie nach einem Enrollment ins State-Verzeichnis.
func testPKI(t *testing.T, stateDir string) (serverTLS tls.Certificate, caPEM []byte) {
	t.Helper()
	caPub, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPub, caPriv)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	issue := func(cn string, usage x509.ExtKeyUsage) (tls.Certificate, []byte, []byte) {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(2),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    time.Now().Add(-time.Minute),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{usage},
			IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		}
		der, err := x509.CreateCertificate(rand.Reader, template, caCert, pub, caPriv)
		if err != nil {
			t.Fatal(err)
		}
		keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			t.Fatal(err)
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
		pair, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatal(err)
		}
		return pair, certPEM, keyPEM
	}

	serverTLS, _, _ = issue("server", x509.ExtKeyUsageServerAuth)
	_, clientCertPEM, clientKeyPEM := issue("host-id-1", x509.ExtKeyUsageClientAuth)

	paths := Paths{StateDir: stateDir}
	mustWrite := func(path string, data []byte) {
		t.Helper()
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite(paths.AgentCertFile(), clientCertPEM)
	mustWrite(paths.AgentKeyFile(), clientKeyPEM)
	mustWrite(paths.ServerCAFile(), caPEM)
	return serverTLS, caPEM
}

// newTestAgentAPI startet einen mTLS-Server mit Agent-Endpunkt-Fakes und
// liefert den fertig verdrahteten apiClient.
func newTestAgentAPI(t *testing.T, handler http.Handler) *apiClient {
	t.Helper()
	stateDir := t.TempDir()
	serverTLS, caPEM := testPKI(t, stateDir)

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{serverTLS},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	server.StartTLS()
	t.Cleanup(server.Close)

	client, err := newAPIClient(&Config{AgentURL: server.URL}, Paths{StateDir: stateDir})
	if err != nil {
		t.Fatalf("newAPIClient: %v", err)
	}
	return client
}

func TestAPIClientRoundtrip(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/agent/renew", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			PublicKey string `json:"public_key"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.PublicKey == "" {
			http.Error(w, "body", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"certificate": "ssh-ed25519-cert AAAA"})
	})
	mux.HandleFunc("GET /v1/agent/principals", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string][]string{"principals": {"alice", "bob"}})
	})
	mux.HandleFunc("GET /v1/agent/bundle/user", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ssh-ed25519 AAAA ca\n"))
	})
	client := newTestAgentAPI(t, mux)
	ctx := context.Background()

	cert, err := client.Renew(ctx, "ssh-ed25519 AAAA host")
	if err != nil || cert != "ssh-ed25519-cert AAAA" {
		t.Errorf("Renew: %q %v", cert, err)
	}
	principals, err := client.Principals(ctx, "deploy")
	if err != nil || len(principals) != 2 {
		t.Errorf("Principals: %v %v", principals, err)
	}
	bundle, err := client.Bundle(ctx)
	if err != nil || bundle != "ssh-ed25519 AAAA ca\n" {
		t.Errorf("Bundle: %q %v", bundle, err)
	}
}

func TestAPIClientFehlerfaelle(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/agent/renew", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{}) // kein certificate
	})
	mux.HandleFunc("GET /v1/agent/principals", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "host unbekannt", http.StatusUnauthorized)
	})
	mux.HandleFunc("GET /v1/agent/bundle/user", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "kaputt", http.StatusInternalServerError)
	})
	client := newTestAgentAPI(t, mux)
	ctx := context.Background()

	if _, err := client.Renew(ctx, "key"); err == nil {
		t.Error("renew ohne zertifikat: fehler erwartet")
	}
	if _, err := client.Principals(ctx, "deploy"); err == nil {
		t.Error("principals 401: fehler erwartet")
	}
	if _, err := client.Bundle(ctx); err == nil {
		t.Error("bundle 500: fehler erwartet")
	}
}

func TestNewAPIClientFehlendesMaterial(t *testing.T) {
	if _, err := newAPIClient(&Config{AgentURL: "https://x"}, Paths{StateDir: t.TempDir()}); err == nil {
		t.Fatal("fehler erwartet (kein mtls-material)")
	}
	// Zertifikat + Key da, aber kaputte Server-CA.
	stateDir := t.TempDir()
	testPKI(t, stateDir)
	paths := Paths{StateDir: stateDir}
	if err := os.WriteFile(paths.ServerCAFile(), []byte("kein pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newAPIClient(&Config{AgentURL: "https://x"}, paths); err == nil {
		t.Fatal("fehler erwartet (kaputte ca)")
	}
}

func TestRunReloadCommand(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "reloaded")
	api := &fakeAPI{}
	d := newTestDaemon(t, api)
	d.cfg.ReloadCommand = "touch " + marker
	d.runReloadCommand()
	if _, err := os.Stat(marker); err != nil {
		t.Errorf("reload-kommando lief nicht: %v", err)
	}
	// Fehlerpfad: Kommando schlägt fehl (nur Logging, kein Panik).
	d.cfg.ReloadCommand = "false"
	d.runReloadCommand()
}

func TestLoadCache(t *testing.T) {
	d := newTestDaemon(t, &fakeAPI{})
	// Gültiger Cache wird geladen.
	entry := map[string]cacheEntry{"deploy": {Principals: []string{"alice"}, FetchedAt: time.Now()}}
	raw, _ := json.Marshal(entry)
	if err := os.WriteFile(d.paths.CacheFile(), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	d.loadCache()
	d.mu.Lock()
	got := d.cache["deploy"]
	d.mu.Unlock()
	if len(got.Principals) != 1 {
		t.Errorf("cache nicht geladen: %+v", got)
	}
	// Kaputter Cache wird ignoriert.
	if err := os.WriteFile(d.paths.CacheFile(), []byte("müll"), 0o600); err != nil {
		t.Fatal(err)
	}
	d.loadCache()
}
