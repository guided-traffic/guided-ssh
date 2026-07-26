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

// startAgent starts an in-memory ssh-agent (keyring) on a unix socket, sets
// SSH_AUTH_SOCK, and returns the keyring for direct assertions.
func startAgent(t *testing.T) agent.Agent {
	t.Helper()
	// Short temp path instead of t.TempDir(): sun_path is limited to ~104
	// characters (darwin), and long test names exceed that limit.
	dir, err := os.MkdirTemp("", "gssh")
	if err != nil {
		t.Fatalf("tempdir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "a.sock")
	listener, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("agent socket: %v", err)
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

// fakeIDP is a minimal OIDC provider for CLI tests: discovery, authorize
// (redirect with code), token, and device endpoint. auth.Flow does not
// verify the id_token's signature — a static value is enough.
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
			http.Error(w, "redirect_uri missing", http.StatusBadRequest)
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

// fakeSign is a fake of the sign endpoint: signs submitted public keys with
// a throwaway CA and records the requested validity.
type fakeSign struct {
	server       *httptest.Server
	signer       ssh.Signer
	wantToken    string
	validity     time.Duration
	lastValidity atomic.Int64
}

// newFakeSign starts the fake sign endpoint; tlsMode enables HTTPS (for
// pinning tests).
func newFakeSign(t *testing.T, wantToken string, validity time.Duration, tlsMode bool) *fakeSign {
	t.Helper()
	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating ca key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatalf("ca signer: %v", err)
	}
	fs := &fakeSign{signer: signer, wantToken: wantToken, validity: validity}

	mux := http.NewServeMux()
	signHandler := func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+fs.wantToken {
			http.Error(w, "id token invalid", http.StatusUnauthorized)
			return
		}
		var req signUserRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "request body invalid", http.StatusBadRequest)
			return
		}
		fs.lastValidity.Store(req.ValiditySeconds)
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.PublicKey))
		if err != nil {
			http.Error(w, "public_key invalid", http.StatusBadRequest)
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
	}
	mux.HandleFunc("POST /v1/sign/user", signHandler)
	mux.HandleFunc("POST /v1/sign/ci", signHandler)

	if tlsMode {
		fs.server = httptest.NewTLSServer(mux)
	} else {
		fs.server = httptest.NewServer(mux)
	}
	t.Cleanup(fs.server.Close)
	return fs
}

// testSignCert builds and signs a user certificate with the test CA;
// negative validity produces an already-expired certificate.
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
		t.Fatalf("signing certificate: %v", err)
	}
	return cert
}

// testKeyPair generates an Ed25519 key pair along with the SSH public key.
func testKeyPair(t *testing.T) (ed25519.PrivateKey, ssh.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key pair: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh public key: %v", err)
	}
	return priv, sshPub
}

// writeConfig creates a configuration file in the temp directory.
func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	return path
}

// minimalConfig builds a valid configuration for idp + sign endpoint.
func minimalConfig(t *testing.T, idp *fakeIDP, sign *fakeSign) string {
	t.Helper()
	return writeConfig(t, fmt.Sprintf("api_url: %s\nissuer: %s\nclient_id: gssh-cli\n",
		sign.server.URL, idp.server.URL))
}

// stubBrowser replaces openBrowser: follows the authorize URL like a
// browser (including the redirect to the localhost callback).
func stubBrowser(t *testing.T) {
	t.Helper()
	orig := openBrowser
	openBrowser = func(authURL string) error {
		resp, err := http.Get(authURL) //nolint:gosec // test URL from the fake IdP
		if err != nil {
			return err
		}
		return resp.Body.Close()
	}
	t.Cleanup(func() { openBrowser = orig })
}

// stubExecSSH replaces execSSH and returns the recorded arguments.
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
		t.Errorf("writing json: %v", err)
	}
}
