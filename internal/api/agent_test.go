package api_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/guided-traffic/guided-ssh/internal/api"
	"github.com/guided-traffic/guided-ssh/internal/ca"
	"github.com/guided-traffic/guided-ssh/internal/store"
)

// newAgentHandler builds the agent handler with a fresh test CA.
func newAgentHandler(t *testing.T, hosts *fakeHostStore) http.Handler {
	t.Helper()
	fs := &fakeStore{}
	masterKey := make([]byte, ca.MasterKeySize)
	certAuthority, err := ca.New(fs, masterKey, ca.NewPolicyEngine(ca.DefaultPolicies()))
	if err != nil {
		t.Fatalf("ca.New: %v", err)
	}
	if err := certAuthority.EnsureCAKeys(context.Background()); err != nil {
		t.Fatalf("EnsureCAKeys: %v", err)
	}
	if err := certAuthority.EnsureMTLSCA(context.Background()); err != nil {
		t.Fatalf("EnsureMTLSCA: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return api.NewAgent(api.AgentDeps{CA: certAuthority, Hosts: hosts, Logger: logger})
}

// agentRequest builds a request with a simulated mTLS client certificate
// (CN = host ID) — the TLS verification itself is tested by internal/ca.
func agentRequest(method, target, body string, hostID string) *http.Request {
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, reader)
	if hostID != "" {
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: hostID}}},
		}
	}
	return req
}

// enrolledHost creates a host in the fake store.
func enrolledHost(hosts *fakeHostStore) *store.Host {
	host := &store.Host{ID: uuid.New(), Name: "web1.example.com"}
	hosts.hosts[host.ID] = host
	return host
}

func TestAgentRenew(t *testing.T) {
	hosts := newFakeHostStore()
	host := enrolledHost(hosts)
	handler := newAgentHandler(t, hosts)

	body, _ := json.Marshal(map[string]string{"public_key": testPublicKey(t)})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, agentRequest(http.MethodPost, "/v1/agent/renew", string(body), host.ID.String()))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Certificate string    `json:"certificate"`
		ValidBefore time.Time `json:"valid_before"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response: %v", err)
	}
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(resp.Certificate))
	if err != nil {
		t.Fatalf("certificate: %v", err)
	}
	cert := parsed.(*ssh.Certificate)
	if cert.CertType != ssh.HostCert || cert.ValidPrincipals[0] != "web1.example.com" {
		t.Errorf("certificate wrong: type=%d principals=%v", cert.CertType, cert.ValidPrincipals)
	}
	if resp.ValidBefore.Before(time.Now().Add(29 * 24 * time.Hour)) {
		t.Errorf("validity too short: %s", resp.ValidBefore)
	}
}

func TestAgentRenewErrorCases(t *testing.T) {
	hosts := newFakeHostStore()
	host := enrolledHost(hosts)
	handler := newAgentHandler(t, hosts)

	cases := []struct {
		name   string
		req    *http.Request
		status int
	}{
		{"without client certificate", agentRequest(http.MethodPost, "/v1/agent/renew", "{}", ""), http.StatusUnauthorized},
		{"cn not a uuid", agentRequest(http.MethodPost, "/v1/agent/renew", "{}", "not-a-uuid"), http.StatusUnauthorized},
		{"host unknown", agentRequest(http.MethodPost, "/v1/agent/renew", "{}", uuid.NewString()), http.StatusUnauthorized},
		{"broken body", agentRequest(http.MethodPost, "/v1/agent/renew", "not json", host.ID.String()), http.StatusBadRequest},
		{"broken key", agentRequest(http.MethodPost, "/v1/agent/renew", `{"public_key":"nope"}`, host.ID.String()), http.StatusBadRequest},
	}
	for _, tc := range cases {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, tc.req)
		if rec.Code != tc.status {
			t.Errorf("%s: status %d, expected %d", tc.name, rec.Code, tc.status)
		}
	}
}

func TestAgentRenewMTLS(t *testing.T) {
	hosts := newFakeHostStore()
	host := enrolledHost(hosts)
	handler := newAgentHandler(t, hosts)

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, priv)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))

	body, _ := json.Marshal(map[string]string{"csr": csrPEM})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, agentRequest(http.MethodPost, "/v1/agent/renew-mtls", string(body), host.ID.String()))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Certificate string `json:"certificate"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response: %v", err)
	}
	block, _ := pem.Decode([]byte(resp.Certificate))
	if block == nil {
		t.Fatalf("no pem certificate: %q", resp.Certificate)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}
	// Identity comes from the mTLS peer certificate, never from the CSR.
	if cert.Subject.CommonName != host.ID.String() {
		t.Errorf("cn = %q, expected host id", cert.Subject.CommonName)
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("extkeyusage = %v, expected clientauth", cert.ExtKeyUsage)
	}

	// Error cases: broken body, broken CSR, without client certificate.
	cases := []struct {
		name   string
		req    *http.Request
		status int
	}{
		{"broken body", agentRequest(http.MethodPost, "/v1/agent/renew-mtls", "not json", host.ID.String()), http.StatusBadRequest},
		{"broken csr", agentRequest(http.MethodPost, "/v1/agent/renew-mtls", `{"csr":"nope"}`, host.ID.String()), http.StatusBadRequest},
		{"without client certificate", agentRequest(http.MethodPost, "/v1/agent/renew-mtls", string(body), ""), http.StatusUnauthorized},
	}
	for _, tc := range cases {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, tc.req)
		if rec.Code != tc.status {
			t.Errorf("%s: status %d, expected %d", tc.name, rec.Code, tc.status)
		}
	}
}

func TestAgentPrincipals(t *testing.T) {
	hosts := newFakeHostStore()
	host := enrolledHost(hosts)
	hosts.principals["deploy"] = []string{"alice", "alice@example.com"}
	handler := newAgentHandler(t, hosts)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, agentRequest(http.MethodGet, "/v1/agent/principals?user=deploy", "", host.ID.String()))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Principals []string `json:"principals"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response: %v", err)
	}
	if strings.Join(resp.Principals, ",") != "alice,alice@example.com" {
		t.Errorf("principals = %v", resp.Principals)
	}

	// Without grants: empty list, no error.
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, agentRequest(http.MethodGet, "/v1/agent/principals?user=root", "", host.ID.String()))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}

	// Missing user parameter.
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, agentRequest(http.MethodGet, "/v1/agent/principals", "", host.ID.String()))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("without user: status %d, expected 400", rec.Code)
	}

	// Store error ⇒ 500 (agent treats this fail-closed).
	hosts.principalsErr = context.DeadlineExceeded
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, agentRequest(http.MethodGet, "/v1/agent/principals?user=deploy", "", host.ID.String()))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("store error: status %d, expected 500", rec.Code)
	}
}

func TestAgentBundle(t *testing.T) {
	hosts := newFakeHostStore()
	host := enrolledHost(hosts)
	handler := newAgentHandler(t, hosts)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, agentRequest(http.MethodGet, "/v1/agent/bundle/user", "", host.ID.String()))
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Body.String(), "ssh-ed25519 ") {
		t.Fatalf("bundle: %d %q", rec.Code, rec.Body.String())
	}
}
