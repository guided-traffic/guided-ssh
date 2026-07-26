package api_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/guided-traffic/guided-ssh/internal/api"
	"github.com/guided-traffic/guided-ssh/internal/auth"
	"github.com/guided-traffic/guided-ssh/internal/ca"
)

// devClaims mirrors the identity main builds for GSSH_DEV_UI_AUTH=insecure.
func devClaims(adminGroup string) *auth.Claims {
	return &auth.Claims{
		Issuer:            "gssh-dev",
		Subject:           "dev-user",
		Email:             "dev@localhost",
		PreferredUsername: "dev",
		Groups:            []string{adminGroup},
	}
}

// newDevServer builds the test server in developer mode: no verifier, no
// UIAuth — only DevUser (like a local server without any OIDC config).
func newDevServer(t *testing.T, fs *fakeAuthStore, admin api.AdminStore, adminGroup string) *httptest.Server {
	t.Helper()
	masterKey := make([]byte, ca.MasterKeySize)
	certAuthority, err := ca.New(&fs.fakeStore, masterKey, ca.NewPolicyEngine(ca.DefaultPolicies()))
	if err != nil {
		t.Fatalf("ca.New: %v", err)
	}
	if err := certAuthority.EnsureCAKeys(context.Background()); err != nil {
		t.Fatalf("EnsureCAKeys: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := httptest.NewServer(api.New(api.Deps{
		CA: certAuthority, Store: fs, Grants: fs, Admin: admin,
		Logger: logger, AdminGroup: adminGroup,
		DevUser: devClaims(adminGroup),
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestDevModeMeReportsAdmin(t *testing.T) {
	fs := newFakeAuthStore()
	srv := newDevServer(t, fs, newFakeAdminStore(fs), "gssh-dev-admins")

	resp, err := http.Get(srv.URL + "/v1/auth/me")
	if err != nil {
		t.Fatalf("GET /v1/auth/me: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d (expected 200)", resp.StatusCode)
	}
	var me struct {
		Authenticated bool     `json:"authenticated"`
		Username      string   `json:"username"`
		Roles         []string `json:"roles"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&me); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if !me.Authenticated || me.Username != "dev" {
		t.Errorf("me = %+v (expected authenticated dev user)", me)
	}
	for _, role := range []string{"admin", "auditor", "readonly"} {
		if !slices.Contains(me.Roles, role) {
			t.Errorf("role %q missing: %v", role, me.Roles)
		}
	}
}

func TestDevModeAdminAPIWithoutToken(t *testing.T) {
	fs := newFakeAuthStore()
	srv := newDevServer(t, fs, newFakeAdminStore(fs), "gssh-dev-admins")

	// Without X-Requested-With the CSRF check rejects the request, exactly
	// like with a real session cookie.
	resp, err := http.Get(srv.URL + "/v1/admin/grants")
	if err != nil {
		t.Fatalf("GET /v1/admin/grants: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status without header %d (expected 403)", resp.StatusCode)
	}

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/v1/admin/grants", nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /v1/admin/grants: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("status with header %d (expected 200): %s", resp.StatusCode, body)
	}
}

func TestDevModeLoginRedirectsLocally(t *testing.T) {
	fs := newFakeAuthStore()
	srv := newDevServer(t, fs, newFakeAdminStore(fs), "gssh-dev-admins")

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Get(srv.URL + "/v1/auth/login?redirect=%2Fhosts")
	if err != nil {
		t.Fatalf("GET /v1/auth/login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status %d (expected 302)", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/hosts" {
		t.Errorf("Location = %q (expected /hosts)", loc)
	}

	// Open redirects stay blocked in developer mode too.
	resp, err = client.Get(srv.URL + "/v1/auth/login?redirect=https%3A%2F%2Fevil.example")
	if err != nil {
		t.Fatalf("GET /v1/auth/login: %v", err)
	}
	resp.Body.Close()
	if loc := resp.Header.Get("Location"); loc != "/" {
		t.Errorf("Location = %q (expected /)", loc)
	}
}
