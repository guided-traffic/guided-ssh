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

	"github.com/google/uuid"

	"github.com/guided-traffic/guided-ssh/internal/api"
	"github.com/guided-traffic/guided-ssh/internal/auth"
	"github.com/guided-traffic/guided-ssh/internal/ca"
	"github.com/guided-traffic/guided-ssh/internal/store"
)

// adminGroupName is the configured admin group for the tests.
const adminGroupName = "gssh-admins"

// fakeAdminStore is an in-memory AdminStore; groups come from the
// embedded fakeAuthStore (shared state with the mapper).
type fakeAdminStore struct {
	*fakeAuthStore
	grants       map[uuid.UUID]*store.AccessGrant
	ciGrants     map[uuid.UUID]*store.CIGrant
	applySpecs   []store.GrantSpec
	applyCISpecs []store.CIGrantSpec
	applyResult  *store.ApplyResult
	applyErr     error
}

func newFakeAdminStore(fs *fakeAuthStore) *fakeAdminStore {
	return &fakeAdminStore{
		fakeAuthStore: fs,
		grants:        map[uuid.UUID]*store.AccessGrant{},
		ciGrants:      map[uuid.UUID]*store.CIGrant{},
	}
}

func (f *fakeAdminStore) withGroup(g *store.AccessGrant) (*store.GrantWithGroup, error) {
	group, ok := f.groups[g.GroupID]
	if !ok {
		return nil, fmt.Errorf("group %s missing", g.GroupID) //nolint:err113
	}
	return &store.GrantWithGroup{AccessGrant: *g, GroupName: group.Name, GroupIssuer: group.Issuer}, nil
}

func (f *fakeAdminStore) ListGrantsDetailed(context.Context) ([]store.GrantWithGroup, error) {
	var out []store.GrantWithGroup
	for _, g := range f.grants {
		detailed, err := f.withGroup(g)
		if err != nil {
			return nil, err
		}
		out = append(out, *detailed)
	}
	return out, nil
}

func (f *fakeAdminStore) GetGrantDetailed(_ context.Context, id uuid.UUID) (*store.GrantWithGroup, error) {
	g, ok := f.grants[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return f.withGroup(g)
}

func (f *fakeAdminStore) CreateGrant(_ context.Context, actor string, g *store.AccessGrant) error {
	if actor == "" {
		return fmt.Errorf("actor missing") //nolint:err113
	}
	g.ID = uuid.New()
	copied := *g
	f.grants[g.ID] = &copied
	return nil
}

func (f *fakeAdminStore) UpdateGrant(_ context.Context, _ string, g *store.AccessGrant) error {
	if _, ok := f.grants[g.ID]; !ok {
		return store.ErrNotFound
	}
	copied := *g
	f.grants[g.ID] = &copied
	return nil
}

func (f *fakeAdminStore) DeleteGrant(_ context.Context, _ string, id uuid.UUID) error {
	if _, ok := f.grants[id]; !ok {
		return store.ErrNotFound
	}
	delete(f.grants, id)
	return nil
}

func (f *fakeAdminStore) ApplyGrants(_ context.Context, _, _ string, specs []store.GrantSpec) (*store.ApplyResult, error) {
	f.applySpecs = specs
	if f.applyErr != nil {
		return nil, f.applyErr
	}
	if f.applyResult != nil {
		return f.applyResult, nil
	}
	return &store.ApplyResult{Created: len(specs)}, nil
}

// adminClaims are claims of an admin user.
func adminClaims() *auth.Claims {
	claims := testClaims()
	claims.Subject = "admin-id"
	claims.PreferredUsername = "admin"
	claims.Email = "admin@example.com"
	claims.Groups = []string{adminGroupName, "dev"}
	return claims
}

// newAdminServer builds the test server including the admin API with in-app
// rule editing enabled; the gates of GITOPS_EXTERNAL_RULES have their own
// tests (newAdminServerRules, TestAdminRuleWriteGates).
func newAdminServer(t *testing.T, fs *fakeAuthStore, admin api.AdminStore, verifier api.TokenVerifier, adminGroup string) *httptest.Server {
	t.Helper()
	return newAdminServerRules(t, fs, admin, verifier, adminGroup, api.RulesConfig{ManualRules: true})
}

// newAdminServerRules builds the test server with an explicit rules
// configuration (manual provisioning / file ownership per domain).
func newAdminServerRules(t *testing.T, fs *fakeAuthStore, admin api.AdminStore, verifier api.TokenVerifier, adminGroup string, rules api.RulesConfig) *httptest.Server {
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
		Verifier: verifier, Logger: logger, AdminGroup: adminGroup,
		Rules: rules,
	}))
	t.Cleanup(srv.Close)
	return srv
}

// adminCall executes an admin API request and returns status and body.
func adminCall(t *testing.T, method, url, token string, payload any) (int, []byte) {
	t.Helper()
	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshaling payload: %v", err)
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	return resp.StatusCode, data
}

func TestAdminNotConfigured(t *testing.T) {
	fs := newFakeAuthStore()
	// Without AdminGroup, the admin API stays disabled (503).
	srv := newAdminServer(t, fs, newFakeAdminStore(fs), &fakeVerifier{token: testToken, claims: adminClaims()}, "")
	status, body := adminCall(t, http.MethodGet, srv.URL+"/v1/admin/grants", testToken, nil)
	if status != http.StatusServiceUnavailable {
		t.Errorf("status %d (expected 503): %s", status, body)
	}
}

func TestAdminAuth(t *testing.T) {
	fs := newFakeAuthStore()
	admin := newFakeAdminStore(fs)
	verifier := &fakeVerifier{token: testToken, claims: testClaims()} // not an admin (group admins)
	srv := newAdminServer(t, fs, admin, verifier, adminGroupName)

	if status, _ := adminCall(t, http.MethodGet, srv.URL+"/v1/admin/grants", "", nil); status != http.StatusUnauthorized {
		t.Errorf("without token: status %d, expected 401", status)
	}
	if status, _ := adminCall(t, http.MethodGet, srv.URL+"/v1/admin/grants", "wrong", nil); status != http.StatusUnauthorized {
		t.Errorf("wrong token: status %d, expected 401", status)
	}
	if status, _ := adminCall(t, http.MethodGet, srv.URL+"/v1/admin/grants", testToken, nil); status != http.StatusForbidden {
		t.Errorf("non-admin: status %d, expected 403", status)
	}
}

func TestAdminInactiveUser(t *testing.T) {
	fs := newFakeAuthStore()
	admin := newFakeAdminStore(fs)
	srv := newAdminServer(t, fs, admin, &fakeVerifier{token: testToken, claims: adminClaims()}, adminGroupName)

	// First access creates the user, then deactivate them.
	if status, _ := adminCall(t, http.MethodGet, srv.URL+"/v1/admin/grants", testToken, nil); status != http.StatusOK {
		t.Fatal("setup failed")
	}
	for _, u := range fs.users {
		u.Active = false
	}
	if status, _ := adminCall(t, http.MethodGet, srv.URL+"/v1/admin/grants", testToken, nil); status != http.StatusForbidden {
		t.Errorf("inactive admin: status %d, expected 403", status)
	}
}

func TestAdminGrantCRUD(t *testing.T) {
	fs := newFakeAuthStore()
	admin := newFakeAdminStore(fs)
	srv := newAdminServer(t, fs, admin, &fakeVerifier{token: testToken, claims: adminClaims()}, adminGroupName)
	base := srv.URL + "/v1/admin/grants"

	// Create: group does not exist yet and gets created.
	status, body := adminCall(t, http.MethodPost, base, testToken, map[string]any{
		"group":                "deployers",
		"tag_selector":         map[string]string{"env": "prod"},
		"principals":           []string{"deploy"},
		"sudo":                 true,
		"max_validity_seconds": 3600,
	})
	if status != http.StatusCreated {
		t.Fatalf("create: status %d: %s", status, body)
	}
	var created struct {
		ID     string `json:"id"`
		Group  string `json:"group"`
		Issuer string `json:"issuer"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatalf("create response: %v", err)
	}
	if created.Group != "deployers" || created.Issuer != adminClaims().Issuer {
		t.Errorf("create: group=%q issuer=%q", created.Group, created.Issuer)
	}

	// List and get.
	status, body = adminCall(t, http.MethodGet, base, testToken, nil)
	var list []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &list); err != nil || status != http.StatusOK || len(list) != 1 {
		t.Fatalf("list: status %d, %d entries (%v): %s", status, len(list), err, body)
	}
	if status, _ = adminCall(t, http.MethodGet, base+"/"+created.ID, testToken, nil); status != http.StatusOK {
		t.Errorf("get: status %d", status)
	}

	// Update.
	status, body = adminCall(t, http.MethodPut, base+"/"+created.ID, testToken, map[string]any{
		"principals":           []string{"deploy", "root"},
		"max_validity_seconds": 7200,
	})
	if status != http.StatusOK {
		t.Fatalf("update: status %d: %s", status, body)
	}
	var updated struct {
		Principals         []string `json:"principals"`
		MaxValiditySeconds int64    `json:"max_validity_seconds"`
		Sudo               bool     `json:"sudo"`
	}
	if err := json.Unmarshal(body, &updated); err != nil {
		t.Fatalf("update response: %v", err)
	}
	if !slices.Equal(updated.Principals, []string{"deploy", "root"}) || updated.MaxValiditySeconds != 7200 || updated.Sudo {
		t.Errorf("update not applied: %+v", updated)
	}

	// Delete.
	if status, _ = adminCall(t, http.MethodDelete, base+"/"+created.ID, testToken, nil); status != http.StatusNoContent {
		t.Errorf("delete: status %d", status)
	}
	if status, _ = adminCall(t, http.MethodGet, base+"/"+created.ID, testToken, nil); status != http.StatusNotFound {
		t.Errorf("get after delete: status %d, expected 404", status)
	}
}

func TestAdminGrantValidation(t *testing.T) {
	fs := newFakeAuthStore()
	admin := newFakeAdminStore(fs)
	srv := newAdminServer(t, fs, admin, &fakeVerifier{token: testToken, claims: adminClaims()}, adminGroupName)
	base := srv.URL + "/v1/admin/grants"

	cases := []struct {
		name       string
		method     string
		url        string
		payload    any
		wantStatus int
	}{
		{"create without group", http.MethodPost, base, map[string]any{
			"principals": []string{"deploy"}, "max_validity_seconds": 3600,
		}, http.StatusBadRequest},
		{"create without principals", http.MethodPost, base, map[string]any{
			"group": "x", "max_validity_seconds": 3600,
		}, http.StatusBadRequest},
		{"create without validity", http.MethodPost, base, map[string]any{
			"group": "x", "principals": []string{"deploy"},
		}, http.StatusBadRequest},
		{"broken body", http.MethodPost, base, "not-json", http.StatusBadRequest},
		{"update unknown id", http.MethodPut, base + "/" + uuid.NewString(), map[string]any{
			"principals": []string{"deploy"}, "max_validity_seconds": 3600,
		}, http.StatusNotFound},
		{"broken id", http.MethodGet, base + "/not-a-uuid", nil, http.StatusNotFound},
		{"delete unknown id", http.MethodDelete, base + "/" + uuid.NewString(), nil, http.StatusNotFound},
	}
	for _, c := range cases {
		if status, body := adminCall(t, c.method, c.url, testToken, c.payload); status != c.wantStatus {
			t.Errorf("%s: status %d (expected %d): %s", c.name, status, c.wantStatus, body)
		}
	}
}

func TestAdminApply(t *testing.T) {
	fs := newFakeAuthStore()
	admin := newFakeAdminStore(fs)
	admin.applyResult = &store.ApplyResult{Created: 1, Updated: 1, Deleted: 2, Unchanged: 3}
	srv := newAdminServer(t, fs, admin, &fakeVerifier{token: testToken, claims: adminClaims()}, adminGroupName)

	status, body := adminCall(t, http.MethodPost, srv.URL+"/v1/admin/grants/apply", testToken, map[string]any{
		"grants": []map[string]any{
			{"group": "deployers", "principals": []string{"deploy"}, "max_validity_seconds": 3600},
			{
				"group": "admins", "tag_selector": map[string]string{"env": "prod"},
				"principals": []string{"root"}, "sudo": true, "max_validity_seconds": 7200,
			},
		},
	})
	if status != http.StatusOK {
		t.Fatalf("apply: status %d: %s", status, body)
	}
	var result store.ApplyResult
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("apply response: %v", err)
	}
	if result != *admin.applyResult {
		t.Errorf("result = %+v", result)
	}
	if len(admin.applySpecs) != 2 || admin.applySpecs[1].Group != "admins" || !admin.applySpecs[1].Sudo {
		t.Errorf("specs = %+v", admin.applySpecs)
	}

	// Validation errors from the store become 400.
	admin.applyErr = fmt.Errorf("%w: check", store.ErrInvalidGrantSpec)
	if status, _ := adminCall(t, http.MethodPost, srv.URL+"/v1/admin/grants/apply", testToken,
		map[string]any{"grants": []map[string]any{}}); status != http.StatusBadRequest {
		t.Errorf("apply validation: status %d, expected 400", status)
	}
}
