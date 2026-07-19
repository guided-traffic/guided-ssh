package api_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
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

// newAgentHandler baut den Agent-Handler mit frischer Test-CA.
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
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return api.NewAgent(api.AgentDeps{CA: certAuthority, Hosts: hosts, Logger: logger})
}

// agentRequest baut einen Request mit simuliertem mTLS-Client-Zertifikat
// (CN = Host-ID) — die TLS-Verifikation selbst testet internal/ca.
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

// enrolledHost legt einen Host im Fake-Store an.
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
		t.Fatalf("antwort: %v", err)
	}
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(resp.Certificate))
	if err != nil {
		t.Fatalf("zertifikat: %v", err)
	}
	cert := parsed.(*ssh.Certificate)
	if cert.CertType != ssh.HostCert || cert.ValidPrincipals[0] != "web1.example.com" {
		t.Errorf("zertifikat falsch: typ=%d principals=%v", cert.CertType, cert.ValidPrincipals)
	}
	if resp.ValidBefore.Before(time.Now().Add(29 * 24 * time.Hour)) {
		t.Errorf("laufzeit zu kurz: %s", resp.ValidBefore)
	}
}

func TestAgentRenewFehlerfaelle(t *testing.T) {
	hosts := newFakeHostStore()
	host := enrolledHost(hosts)
	handler := newAgentHandler(t, hosts)

	cases := []struct {
		name   string
		req    *http.Request
		status int
	}{
		{"ohne client-zertifikat", agentRequest(http.MethodPost, "/v1/agent/renew", "{}", ""), http.StatusUnauthorized},
		{"cn keine uuid", agentRequest(http.MethodPost, "/v1/agent/renew", "{}", "kein-uuid"), http.StatusUnauthorized},
		{"host unbekannt", agentRequest(http.MethodPost, "/v1/agent/renew", "{}", uuid.NewString()), http.StatusUnauthorized},
		{"kaputter body", agentRequest(http.MethodPost, "/v1/agent/renew", "kein json", host.ID.String()), http.StatusBadRequest},
		{"kaputter key", agentRequest(http.MethodPost, "/v1/agent/renew", `{"public_key":"nix"}`, host.ID.String()), http.StatusBadRequest},
	}
	for _, tc := range cases {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, tc.req)
		if rec.Code != tc.status {
			t.Errorf("%s: status %d, erwartet %d", tc.name, rec.Code, tc.status)
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
		t.Fatalf("antwort: %v", err)
	}
	if strings.Join(resp.Principals, ",") != "alice,alice@example.com" {
		t.Errorf("principals = %v", resp.Principals)
	}

	// Ohne Grants: leere Liste, kein Fehler.
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, agentRequest(http.MethodGet, "/v1/agent/principals?user=root", "", host.ID.String()))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}

	// Fehlender user-Parameter.
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, agentRequest(http.MethodGet, "/v1/agent/principals", "", host.ID.String()))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("ohne user: status %d, erwartet 400", rec.Code)
	}

	// Store-Fehler ⇒ 500 (Agent behandelt das fail-closed).
	hosts.principalsErr = context.DeadlineExceeded
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, agentRequest(http.MethodGet, "/v1/agent/principals?user=deploy", "", host.ID.String()))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("store-fehler: status %d, erwartet 500", rec.Code)
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
