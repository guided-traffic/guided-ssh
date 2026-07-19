package api_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
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

// fakeHostStore implementiert api.HostStore in-memory.
type fakeHostStore struct {
	tokens     map[string]*store.EnrollmentToken // hex(hash) → token
	hosts      map[uuid.UUID]*store.Host
	principals map[string][]string // localUser → principals

	principalsErr error
}

func newFakeHostStore() *fakeHostStore {
	return &fakeHostStore{
		tokens:     map[string]*store.EnrollmentToken{},
		hosts:      map[uuid.UUID]*store.Host{},
		principals: map[string][]string{},
	}
}

// addToken registriert ein Klartext-Token wie CreateEnrollmentToken (Hash).
func (f *fakeHostStore) addToken(token string, hostName *string, expires time.Time) {
	hash := sha256.Sum256([]byte(token))
	f.tokens[string(hash[:])] = &store.EnrollmentToken{
		ID: uuid.New(), TokenHash: hash[:], HostName: hostName, ExpiresAt: expires,
	}
}

func (f *fakeHostStore) EnrollHost(_ context.Context, p store.EnrollHostParams) (*store.Host, error) {
	token, ok := f.tokens[string(p.TokenHash)]
	if !ok || token.UsedAt != nil || token.ExpiresAt.Before(time.Now()) {
		return nil, store.ErrNotFound
	}
	if token.HostName != nil && *token.HostName != p.Name {
		return nil, store.ErrTokenHostMismatch
	}
	now := time.Now()
	token.UsedAt = &now
	host := &store.Host{ID: uuid.New(), Name: p.Name, PublicKey: &p.PublicKey}
	f.hosts[host.ID] = host
	return host, nil
}

func (f *fakeHostStore) GetHost(_ context.Context, id uuid.UUID) (*store.Host, error) {
	host, ok := f.hosts[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return host, nil
}

func (f *fakeHostStore) TouchHostLastSeen(_ context.Context, id uuid.UUID) error {
	if _, ok := f.hosts[id]; !ok {
		return store.ErrNotFound
	}
	return nil
}

func (f *fakeHostStore) ListAuthorizedPrincipals(_ context.Context, _ uuid.UUID, localUser string) ([]string, error) {
	if f.principalsErr != nil {
		return nil, f.principalsErr
	}
	return f.principals[localUser], nil
}

// newEnrollServer baut CA + Server mit Enrollment und liefert beide; ein
// optionales hostValidity übersteuert die Laufzeit der Host-Zertifikate.
func newEnrollServer(t *testing.T, hosts *fakeHostStore, hostValidity ...time.Duration) (*httptest.Server, *ca.CA) {
	t.Helper()
	fs := &fakeStore{}
	masterKey := make([]byte, ca.MasterKeySize)
	certAuthority, err := ca.New(fs, masterKey, ca.NewPolicyEngine(ca.DefaultPolicies()))
	if err != nil {
		t.Fatalf("ca.New: %v", err)
	}
	ctx := context.Background()
	if err := certAuthority.EnsureCAKeys(ctx); err != nil {
		t.Fatalf("EnsureCAKeys: %v", err)
	}
	if err := certAuthority.EnsureMTLSCA(ctx); err != nil {
		t.Fatalf("EnsureMTLSCA: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	deps := api.Deps{CA: certAuthority, Hosts: hosts, Logger: logger}
	if len(hostValidity) > 0 {
		deps.HostCertValidity = hostValidity[0]
	}
	srv := httptest.NewServer(api.New(deps))
	t.Cleanup(srv.Close)
	return srv, certAuthority
}

// enrollBody baut einen gültigen Enroll-Request-Body.
func enrollBody(t *testing.T, token, hostname string) []byte {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("hostkey: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh-pub: %v", err)
	}
	_, csrPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("csr-key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, csrPriv)
	if err != nil {
		t.Fatalf("csr: %v", err)
	}
	body, err := json.Marshal(map[string]any{
		"token":          token,
		"hostname":       hostname,
		"ssh_public_key": strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))),
		"mtls_csr":       string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})),
	})
	if err != nil {
		t.Fatalf("body: %v", err)
	}
	return body
}

func postEnroll(t *testing.T, url string, body []byte) (int, string) {
	t.Helper()
	resp, err := http.Post(url+"/v1/enroll", "application/json", bytes.NewReader(body)) //nolint:gosec // Test-URL
	if err != nil {
		t.Fatalf("POST /v1/enroll: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw)
}

func TestEnrollErfolg(t *testing.T) {
	hosts := newFakeHostStore()
	hosts.addToken("tok-1", nil, time.Now().Add(time.Hour))
	srv, certAuthority := newEnrollServer(t, hosts)

	status, body := postEnroll(t, srv.URL, enrollBody(t, "tok-1", "web1.example.com"))
	if status != http.StatusOK {
		t.Fatalf("status %d: %s", status, body)
	}
	var resp struct {
		HostID          string `json:"host_id"`
		HostCertificate string `json:"host_certificate"`
		UserCABundle    string `json:"user_ca_bundle"`
		MTLSCertificate string `json:"mtls_certificate"`
		MTLSCA          string `json:"mtls_ca"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("antwort: %v", err)
	}

	// Host-Zertifikat: Typ, Principals (voll + kurz), von Host-CA signiert.
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(resp.HostCertificate))
	if err != nil {
		t.Fatalf("host-zertifikat parsen: %v", err)
	}
	cert := parsed.(*ssh.Certificate)
	if cert.CertType != ssh.HostCert {
		t.Errorf("certtype = %d", cert.CertType)
	}
	want := []string{"web1.example.com", "web1"}
	if strings.Join(cert.ValidPrincipals, ",") != strings.Join(want, ",") {
		t.Errorf("principals = %v, erwartet %v", cert.ValidPrincipals, want)
	}
	if !strings.HasPrefix(resp.UserCABundle, "ssh-ed25519 ") {
		t.Errorf("user-ca-bundle: %q", resp.UserCABundle)
	}

	// mTLS-Zertifikat gegen die CA prüfbar, CN = Host-ID.
	block, _ := pem.Decode([]byte(resp.MTLSCertificate))
	mtlsCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("mtls-zertifikat: %v", err)
	}
	if mtlsCert.Subject.CommonName != resp.HostID {
		t.Errorf("cn = %q, host_id = %q", mtlsCert.Subject.CommonName, resp.HostID)
	}
	pool, err := certAuthority.MTLSCAPool(context.Background())
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	if _, err := mtlsCert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Errorf("mtls-kette: %v", err)
	}
	if !strings.Contains(resp.MTLSCA, "BEGIN CERTIFICATE") {
		t.Errorf("mtls_ca fehlt: %q", resp.MTLSCA)
	}
}

func TestEnrollHostCertValidityOverride(t *testing.T) {
	hosts := newFakeHostStore()
	hosts.addToken("tok-1", nil, time.Now().Add(time.Hour))
	srv, _ := newEnrollServer(t, hosts, time.Hour)

	status, body := postEnroll(t, srv.URL, enrollBody(t, "tok-1", "web1.example.com"))
	if status != http.StatusOK {
		t.Fatalf("status %d: %s", status, body)
	}
	var resp struct {
		HostCertificate string `json:"host_certificate"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("antwort: %v", err)
	}
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(resp.HostCertificate))
	if err != nil {
		t.Fatalf("host-zertifikat parsen: %v", err)
	}
	cert := parsed.(*ssh.Certificate)
	if lifetime := time.Duration(cert.ValidBefore-cert.ValidAfter) * time.Second; lifetime != time.Hour {
		t.Errorf("laufzeit = %s, erwartet %s", lifetime, time.Hour)
	}
}

func TestEnrollTokenEinmalig(t *testing.T) {
	hosts := newFakeHostStore()
	hosts.addToken("tok-1", nil, time.Now().Add(time.Hour))
	srv, _ := newEnrollServer(t, hosts)

	if status, body := postEnroll(t, srv.URL, enrollBody(t, "tok-1", "a.example.com")); status != http.StatusOK {
		t.Fatalf("erstes enrollment: %d %s", status, body)
	}
	if status, _ := postEnroll(t, srv.URL, enrollBody(t, "tok-1", "b.example.com")); status != http.StatusForbidden {
		t.Fatalf("zweites enrollment: status %d, erwartet 403", status)
	}
}

func TestEnrollFehlerfaelle(t *testing.T) {
	hosts := newFakeHostStore()
	bound := "richtig.example.com"
	hosts.addToken("gebunden", &bound, time.Now().Add(time.Hour))
	hosts.addToken("abgelaufen", nil, time.Now().Add(-time.Hour))
	srv, _ := newEnrollServer(t, hosts)

	cases := []struct {
		name   string
		body   []byte
		status int
	}{
		{"unbekanntes token", enrollBody(t, "gibtsnicht", "x.example.com"), http.StatusForbidden},
		{"abgelaufenes token", enrollBody(t, "abgelaufen", "x.example.com"), http.StatusForbidden},
		{"falscher hostname", enrollBody(t, "gebunden", "falsch.example.com"), http.StatusForbidden},
		{"kaputter body", []byte("kein json"), http.StatusBadRequest},
	}
	for _, tc := range cases {
		if status, body := postEnroll(t, srv.URL, tc.body); status != tc.status {
			t.Errorf("%s: status %d, erwartet %d (%s)", tc.name, status, tc.status, body)
		}
	}
}

func TestEnrollOhnePflichtfelder(t *testing.T) {
	hosts := newFakeHostStore()
	srv, _ := newEnrollServer(t, hosts)
	body, _ := json.Marshal(map[string]any{"hostname": "x"})
	if status, _ := postEnroll(t, srv.URL, body); status != http.StatusBadRequest {
		t.Fatalf("status %d, erwartet 400", status)
	}
}

func TestEnrollKaputterSSHKey(t *testing.T) {
	hosts := newFakeHostStore()
	hosts.addToken("tok-1", nil, time.Now().Add(time.Hour))
	srv, _ := newEnrollServer(t, hosts)
	body, _ := json.Marshal(map[string]any{
		"token": "tok-1", "hostname": "x.example.com", "ssh_public_key": "kein key",
	})
	if status, _ := postEnroll(t, srv.URL, body); status != http.StatusBadRequest {
		t.Fatalf("status %d, erwartet 400", status)
	}
}

func TestEnrollKaputterCSR(t *testing.T) {
	hosts := newFakeHostStore()
	hosts.addToken("tok-1", nil, time.Now().Add(time.Hour))
	srv, _ := newEnrollServer(t, hosts)

	var req map[string]any
	if err := json.Unmarshal(enrollBody(t, "tok-1", "x.example.com"), &req); err != nil {
		t.Fatal(err)
	}
	req["mtls_csr"] = "kein csr"
	body, _ := json.Marshal(req)
	if status, _ := postEnroll(t, srv.URL, body); status != http.StatusBadRequest {
		t.Fatalf("status %d, erwartet 400", status)
	}
}

func TestEnrollOhneHostsDeaktiviert(t *testing.T) {
	srv := newTestServer(t, &fakeStore{})
	resp, err := http.Post(srv.URL+"/v1/enroll", "application/json", strings.NewReader("{}")) //nolint:gosec // Test-URL
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status %d, erwartet 404 (route nicht registriert)", resp.StatusCode)
	}
}
