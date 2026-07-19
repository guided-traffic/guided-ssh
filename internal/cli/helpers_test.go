package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// startAgent startet einen In-Memory-ssh-agent (Keyring) auf einem
// Unix-Socket, setzt SSH_AUTH_SOCK und liefert den Keyring für direkte
// Assertions.
func startAgent(t *testing.T) agent.Agent {
	t.Helper()
	// Kurzer Temp-Pfad statt t.TempDir(): sun_path ist auf ~104 Zeichen
	// begrenzt (darwin) und lange Testnamen sprengen das Limit.
	dir, err := os.MkdirTemp("", "gssh")
	if err != nil {
		t.Fatalf("tempdir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "a.sock")
	listener, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("agent-socket: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	keyring := agent.NewKeyring()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { _ = agent.ServeAgent(keyring, conn) }()
		}
	}()
	t.Setenv("SSH_AUTH_SOCK", sock)
	return keyring
}

// fakeIDP ist ein minimaler OIDC-Provider für CLI-Tests: Discovery, Authorize
// (Redirect mit Code), Token- und Device-Endpoint. auth.Flow prüft die
// Signatur des id_token nicht — ein statischer Wert genügt.
type fakeIDP struct {
	server     *httptest.Server
	idToken    string
	tokenCalls atomic.Int32
}

func newFakeIDP(t *testing.T) *fakeIDP {
	t.Helper()
	idp := &fakeIDP{idToken: "test-id-token"}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, map[string]any{
			"issuer":                        idp.server.URL,
			"authorization_endpoint":        idp.server.URL + "/auth",
			"token_endpoint":                idp.server.URL + "/token",
			"jwks_uri":                      idp.server.URL + "/keys",
			"device_authorization_endpoint": idp.server.URL + "/device",
		})
	})
	mux.HandleFunc("GET /auth", func(w http.ResponseWriter, r *http.Request) {
		redirect, err := url.Parse(r.URL.Query().Get("redirect_uri"))
		if err != nil {
			http.Error(w, "redirect_uri fehlt", http.StatusBadRequest)
			return
		}
		q := redirect.Query()
		q.Set("code", "test-code")
		q.Set("state", r.URL.Query().Get("state"))
		redirect.RawQuery = q.Encode()
		http.Redirect(w, r, redirect.String(), http.StatusFound)
	})
	mux.HandleFunc("POST /device", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, map[string]any{
			"device_code":               "test-device",
			"user_code":                 "AB-CD",
			"verification_uri":          idp.server.URL + "/verify",
			"verification_uri_complete": idp.server.URL + "/verify?user_code=AB-CD",
			"expires_in":                300,
			"interval":                  1,
		})
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, _ *http.Request) {
		idp.tokenCalls.Add(1)
		writeJSON(t, w, map[string]any{
			"access_token": "test-access",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"id_token":     idp.idToken,
		})
	})
	idp.server = httptest.NewServer(mux)
	t.Cleanup(idp.server.Close)
	return idp
}

// fakeSign ist ein Fake des Sign-Endpoints: signiert eingereichte Public Keys
// mit einer Wegwerf-CA und protokolliert die angefragte Laufzeit.
type fakeSign struct {
	server       *httptest.Server
	signer       ssh.Signer
	wantToken    string
	validity     time.Duration
	lastValidity atomic.Int64
}

// newFakeSign startet den Fake-Sign-Endpoint; tlsMode schaltet HTTPS ein
// (für Pinning-Tests).
func newFakeSign(t *testing.T, wantToken string, validity time.Duration, tlsMode bool) *fakeSign {
	t.Helper()
	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ca-key erzeugen: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatalf("ca-signer: %v", err)
	}
	fs := &fakeSign{signer: signer, wantToken: wantToken, validity: validity}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/sign/user", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+fs.wantToken {
			http.Error(w, "id-token ungültig", http.StatusUnauthorized)
			return
		}
		var req signUserRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "request-body ungültig", http.StatusBadRequest)
			return
		}
		fs.lastValidity.Store(req.ValiditySeconds)
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.PublicKey))
		if err != nil {
			http.Error(w, "public_key ungültig", http.StatusBadRequest)
			return
		}
		validity := fs.validity
		if req.ValiditySeconds > 0 {
			validity = time.Duration(req.ValiditySeconds) * time.Second
		}
		cert := testSignCert(t, fs.signer, pub, validity)
		writeJSON(t, w, map[string]any{
			"certificate": strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert))),
			"serial":      cert.Serial,
			"key_id":      cert.KeyId,
			"principals":  cert.ValidPrincipals,
		})
	})

	if tlsMode {
		fs.server = httptest.NewTLSServer(mux)
	} else {
		fs.server = httptest.NewServer(mux)
	}
	t.Cleanup(fs.server.Close)
	return fs
}

// testSignCert baut und signiert ein Benutzerzertifikat mit der Test-CA;
// negative validity erzeugt ein bereits abgelaufenes Zertifikat.
func testSignCert(t *testing.T, signer ssh.Signer, pub ssh.PublicKey, validity time.Duration) *ssh.Certificate {
	t.Helper()
	now := time.Now()
	cert := &ssh.Certificate{
		Key:             pub,
		Serial:          42,
		CertType:        ssh.UserCert,
		KeyId:           "user:alice@fake-idp",
		ValidPrincipals: []string{"alice", "alice@example.com"},
		ValidAfter:      uint64(now.Add(-2 * time.Minute).Unix()), //nolint:gosec // Unix-Zeit nach 1970, nie negativ
		ValidBefore:     uint64(now.Add(validity).Unix()),         //nolint:gosec // dito
	}
	if err := cert.SignCert(rand.Reader, signer); err != nil {
		t.Fatalf("zertifikat signieren: %v", err)
	}
	return cert
}

// testKeyPair erzeugt ein Ed25519-Schlüsselpaar samt SSH-Public-Key.
func testKeyPair(t *testing.T) (ed25519.PrivateKey, ssh.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("schlüsselpaar: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh-public-key: %v", err)
	}
	return priv, sshPub
}

// writeConfig legt eine Konfigurationsdatei im Temp-Verzeichnis an.
func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("config schreiben: %v", err)
	}
	return path
}

// minimalConfig baut eine gültige Konfiguration für idp + sign-endpoint.
func minimalConfig(t *testing.T, idp *fakeIDP, sign *fakeSign) string {
	t.Helper()
	return writeConfig(t, fmt.Sprintf("api_url: %s\nissuer: %s\nclient_id: gssh-cli\n",
		sign.server.URL, idp.server.URL))
}

// stubBrowser ersetzt openBrowser: folgt der Authorize-URL wie ein Browser
// (inkl. Redirect zum Localhost-Callback).
func stubBrowser(t *testing.T) {
	t.Helper()
	orig := openBrowser
	openBrowser = func(authURL string) error {
		resp, err := http.Get(authURL) //nolint:gosec // Test-URL vom Fake-IdP
		if err != nil {
			return err
		}
		return resp.Body.Close()
	}
	t.Cleanup(func() { openBrowser = orig })
}

// stubExecSSH ersetzt execSSH und liefert die aufgezeichneten Argumente.
func stubExecSSH(t *testing.T, fail error) *[]string {
	t.Helper()
	orig := execSSH
	var got []string
	execSSH = func(argv []string) error {
		got = argv
		return fail
	}
	t.Cleanup(func() { execSSH = orig })
	return &got
}

func writeJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Errorf("json schreiben: %v", err)
	}
}
