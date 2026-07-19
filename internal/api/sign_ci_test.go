package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/guided-traffic/guided-ssh/internal/api"
	"github.com/guided-traffic/guided-ssh/internal/auth"
	"github.com/guided-traffic/guided-ssh/internal/ca"
	"github.com/guided-traffic/guided-ssh/internal/store"
)

const ciTestToken = "gueltiges-ci-token" //#nosec G101 -- Testwert, kein Credential

// fakeCIVerifier akzeptiert genau ein Token und liefert feste CI-Claims.
type fakeCIVerifier struct {
	token  string
	claims *auth.CIClaims
}

func (f *fakeCIVerifier) Verify(_ context.Context, rawToken string) (*auth.CIClaims, error) {
	if rawToken != f.token {
		return nil, fmt.Errorf("%w: token unbekannt", auth.ErrInvalidToken)
	}
	copied := *f.claims
	return &copied, nil
}

// fakeCIStore ist ein In-Memory-CIStore: Grants werden über die echte
// Matching-Logik ausgewertet, Service-Accounts pro Projekt vorgehalten.
type fakeCIStore struct {
	grants   []store.CIGrant
	inactive bool
}

func (f *fakeCIStore) MatchCIGrants(_ context.Context, m store.CIMatch) ([]store.CIGrant, error) {
	var matched []store.CIGrant
	for _, g := range f.grants {
		if g.Matches(m) {
			matched = append(matched, g)
		}
	}
	return matched, nil
}

func (f *fakeCIStore) EnsureCIServiceAccount(_ context.Context, issuer, projectPath string) (*store.ServiceAccount, error) {
	return &store.ServiceAccount{
		ID: uuid.New(), Name: projectPath, Kind: store.KindGitLabCI,
		Issuer: issuer, Active: !f.inactive,
	}, nil
}

func ciTestClaims() *auth.CIClaims {
	return &auth.CIClaims{
		Issuer:        "https://gitlab.example.com",
		Subject:       "project_path:infra/ansible:ref_type:branch:ref:main",
		ProjectPath:   "infra/ansible",
		NamespacePath: "infra",
		Ref:           "main",
		RefType:       "branch",
		RefProtected:  true,
		PipelineID:    "4711",
		JobID:         "815",
		UserLogin:     "alice",
		ExpiresAt:     time.Now().Add(2 * time.Hour),
	}
}

func ciTestGrant() store.CIGrant {
	return store.CIGrant{
		ID: uuid.New(), ProjectPath: "infra/ansible", ProtectedOnly: true,
		Principals: []string{"deploy"}, MaxValiditySeconds: 3600,
	}
}

// newCISignServer baut den Testserver mit CI-Sign-Endpoint (echte CA über fakeStore).
func newCISignServer(t *testing.T, ciStore api.CIStore, verifier api.CITokenVerifier) *httptest.Server {
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
	srv := httptest.NewServer(api.New(api.Deps{
		CA: certAuthority, CIStore: ciStore, CIVerifier: verifier, Logger: logger,
	}))
	t.Cleanup(srv.Close)
	return srv
}

// postSignCI ruft den CI-Sign-Endpoint auf.
func postSignCI(t *testing.T, url, token string, body any) (int, []byte) {
	t.Helper()
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("body marshalen: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, url+"/v1/sign/ci", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("request bauen: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("body lesen: %v", err)
	}
	return resp.StatusCode, data
}

func TestSignCIErfolg(t *testing.T) {
	ciStore := &fakeCIStore{grants: []store.CIGrant{ciTestGrant()}}
	srv := newCISignServer(t, ciStore, &fakeCIVerifier{token: ciTestToken, claims: ciTestClaims()})

	status, body := postSignCI(t, srv.URL, ciTestToken, map[string]any{"public_key": testPublicKey(t)})
	if status != http.StatusOK {
		t.Fatalf("status %d: %s", status, body)
	}
	var resp struct {
		Certificate string    `json:"certificate"`
		KeyID       string    `json:"key_id"`
		Principals  []string  `json:"principals"`
		ValidAfter  time.Time `json:"valid_after"`
		ValidBefore time.Time `json:"valid_before"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("antwort dekodieren: %v", err)
	}

	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(resp.Certificate))
	if err != nil {
		t.Fatalf("zertifikat parsen: %v", err)
	}
	cert, ok := parsed.(*ssh.Certificate)
	if !ok {
		t.Fatalf("kein zertifikat: %T", parsed)
	}
	// KeyID ci:<project>:<pipeline>:<job> (Audit-Zuordnung pro Job).
	if want := "ci:infra/ansible:4711:815"; cert.KeyId != want || resp.KeyID != want {
		t.Errorf("keyid: %q / %q, erwartet %q", cert.KeyId, resp.KeyID, want)
	}
	// Projekt-Identitäts-Principals inkl. Namespace-Vorfahr (ADR-019).
	if want := []string{"ci:infra/ansible", "ci:infra"}; !slices.Equal(cert.ValidPrincipals, want) {
		t.Errorf("principals: %v, erwartet %v", cert.ValidPrincipals, want)
	}
	// Nur permit-pty (CI-Policy).
	if _, ok := cert.Extensions["permit-pty"]; !ok || len(cert.Extensions) != 1 {
		t.Errorf("extensions: %v", cert.Extensions)
	}
	// Default-Laufzeit 1 h.
	if lifetime := resp.ValidBefore.Sub(resp.ValidAfter); lifetime != time.Hour {
		t.Errorf("laufzeit %s, erwartet 1h", lifetime)
	}
}

func TestSignCILaufzeitDurchGrantGedeckelt(t *testing.T) {
	grant := ciTestGrant()
	grant.MaxValiditySeconds = 600 // Grant erlaubt nur 10 m
	ciStore := &fakeCIStore{grants: []store.CIGrant{grant}}
	srv := newCISignServer(t, ciStore, &fakeCIVerifier{token: ciTestToken, claims: ciTestClaims()})

	status, body := postSignCI(t, srv.URL, ciTestToken, map[string]any{
		"public_key": testPublicKey(t), "validity_seconds": 3600,
	})
	if status != http.StatusOK {
		t.Fatalf("status %d: %s", status, body)
	}
	var resp struct {
		ValidAfter  time.Time `json:"valid_after"`
		ValidBefore time.Time `json:"valid_before"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatal(err)
	}
	if lifetime := resp.ValidBefore.Sub(resp.ValidAfter); lifetime != 10*time.Minute {
		t.Errorf("laufzeit %s, erwartet 10m (grant-maximum)", lifetime)
	}
}

func TestSignCILaufzeitDurchTokenAblaufGedeckelt(t *testing.T) {
	claims := ciTestClaims()
	claims.ExpiresAt = time.Now().Add(10 * time.Minute) // Job-Timeout in 10 m
	ciStore := &fakeCIStore{grants: []store.CIGrant{ciTestGrant()}}
	srv := newCISignServer(t, ciStore, &fakeCIVerifier{token: ciTestToken, claims: claims})

	status, body := postSignCI(t, srv.URL, ciTestToken, map[string]any{"public_key": testPublicKey(t)})
	if status != http.StatusOK {
		t.Fatalf("status %d: %s", status, body)
	}
	var resp struct {
		ValidBefore time.Time `json:"valid_before"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.ValidBefore.After(claims.ExpiresAt.Add(time.Second)) {
		t.Errorf("valid_before %s liegt nach token-ablauf %s", resp.ValidBefore, claims.ExpiresAt)
	}
}

func TestSignCIFehlerfaelle(t *testing.T) {
	validKey := testPublicKey(t)

	protectedClaims := ciTestClaims()
	protectedClaims.RefProtected = false // Grant verlangt protected

	wrongProject := ciTestClaims()
	wrongProject.ProjectPath = "andere/app"
	wrongProject.NamespacePath = "andere"

	expired := ciTestClaims()
	expired.ExpiresAt = time.Now().Add(-time.Minute)

	cases := []struct {
		name       string
		token      string
		claims     *auth.CIClaims
		inactive   bool
		body       any
		wantStatus int
	}{
		{"ohne token", "", ciTestClaims(), false, map[string]any{"public_key": validKey}, http.StatusUnauthorized},
		{"falsches token", "falsch", ciTestClaims(), false, map[string]any{"public_key": validKey}, http.StatusUnauthorized},
		{"kaputter body", ciTestToken, ciTestClaims(), false, "kein-json", http.StatusBadRequest},
		{"kaputter key", ciTestToken, ciTestClaims(), false, map[string]any{"public_key": "kein-key"}, http.StatusBadRequest},
		{"unprotected ref ohne grant", ciTestToken, protectedClaims, false, map[string]any{"public_key": validKey}, http.StatusForbidden},
		{"fremdes projekt", ciTestToken, wrongProject, false, map[string]any{"public_key": validKey}, http.StatusForbidden},
		{"service-account deaktiviert", ciTestToken, ciTestClaims(), true, map[string]any{"public_key": validKey}, http.StatusForbidden},
		{"token bereits abgelaufen", ciTestToken, expired, false, map[string]any{"public_key": validKey}, http.StatusBadRequest},
	}
	for _, c := range cases {
		ciStore := &fakeCIStore{grants: []store.CIGrant{ciTestGrant()}, inactive: c.inactive}
		srv := newCISignServer(t, ciStore, &fakeCIVerifier{token: ciTestToken, claims: c.claims})
		if status, body := postSignCI(t, srv.URL, c.token, c.body); status != c.wantStatus {
			t.Errorf("%s: status %d (erwartet %d): %s", c.name, status, c.wantStatus, body)
		}
	}
}

func TestSignCIZertifikatAlsKeyAbgelehnt(t *testing.T) {
	ciStore := &fakeCIStore{grants: []store.CIGrant{ciTestGrant()}}
	srv := newCISignServer(t, ciStore, &fakeCIVerifier{token: ciTestToken, claims: ciTestClaims()})

	status, body := postSignCI(t, srv.URL, ciTestToken, map[string]any{"public_key": testPublicKey(t)})
	if status != http.StatusOK {
		t.Fatalf("setup-zertifikat: status %d", status)
	}
	var resp struct {
		Certificate string `json:"certificate"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatal(err)
	}
	if status, _ := postSignCI(t, srv.URL, ciTestToken, map[string]any{"public_key": resp.Certificate}); status != http.StatusBadRequest {
		t.Errorf("zertifikat als key: status %d, erwartet 400", status)
	}
}

func TestSignCIOhneKonfiguration(t *testing.T) {
	srv := newTestServer(t, &fakeStore{}) // ohne CIVerifier/CIStore
	status, _ := postSignCI(t, srv.URL, ciTestToken, map[string]any{"public_key": testPublicKey(t)})
	if status != http.StatusServiceUnavailable {
		t.Errorf("status %d, erwartet 503", status)
	}
}
