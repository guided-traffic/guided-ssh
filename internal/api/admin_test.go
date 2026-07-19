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

// adminGroupName ist die konfigurierte Admin-Gruppe der Tests.
const adminGroupName = "gssh-admins"

// fakeAdminStore ist ein In-Memory-AdminStore; Gruppen kommen aus dem
// eingebetteten fakeAuthStore (gemeinsamer Zustand mit dem Mapper).
type fakeAdminStore struct {
	*fakeAuthStore
	grants      map[uuid.UUID]*store.AccessGrant
	applySpecs  []store.GrantSpec
	applyResult *store.ApplyResult
	applyErr    error
}

func newFakeAdminStore(fs *fakeAuthStore) *fakeAdminStore {
	return &fakeAdminStore{
		fakeAuthStore: fs,
		grants:        map[uuid.UUID]*store.AccessGrant{},
	}
}

func (f *fakeAdminStore) withGroup(g *store.AccessGrant) (*store.GrantWithGroup, error) {
	group, ok := f.groups[g.GroupID]
	if !ok {
		return nil, fmt.Errorf("gruppe %s fehlt", g.GroupID) //nolint:err113
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
		return fmt.Errorf("actor fehlt") //nolint:err113
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

// adminClaims sind Claims eines Admin-Benutzers.
func adminClaims() *auth.Claims {
	claims := testClaims()
	claims.Subject = "admin-id"
	claims.PreferredUsername = "admin"
	claims.Email = "admin@example.com"
	claims.Groups = []string{adminGroupName, "dev"}
	return claims
}

// newAdminServer baut den Testserver inklusive Admin-API.
func newAdminServer(t *testing.T, fs *fakeAuthStore, admin api.AdminStore, verifier api.TokenVerifier, adminGroup string) *httptest.Server {
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
	}))
	t.Cleanup(srv.Close)
	return srv
}

// adminCall führt einen Admin-API-Request aus und liefert Status und Body.
func adminCall(t *testing.T, method, url, token string, payload any) (int, []byte) {
	t.Helper()
	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("payload marshalen: %v", err)
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		t.Fatalf("request bauen: %v", err)
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
		t.Fatalf("body lesen: %v", err)
	}
	return resp.StatusCode, data
}

func TestAdminNichtKonfiguriert(t *testing.T) {
	fs := newFakeAuthStore()
	// Ohne AdminGroup bleibt die Admin-API deaktiviert (503).
	srv := newAdminServer(t, fs, newFakeAdminStore(fs), &fakeVerifier{token: testToken, claims: adminClaims()}, "")
	status, body := adminCall(t, http.MethodGet, srv.URL+"/v1/admin/grants", testToken, nil)
	if status != http.StatusServiceUnavailable {
		t.Errorf("status %d (erwartet 503): %s", status, body)
	}
}

func TestAdminAuth(t *testing.T) {
	fs := newFakeAuthStore()
	admin := newFakeAdminStore(fs)
	verifier := &fakeVerifier{token: testToken, claims: testClaims()} // kein Admin (Gruppe admins)
	srv := newAdminServer(t, fs, admin, verifier, adminGroupName)

	if status, _ := adminCall(t, http.MethodGet, srv.URL+"/v1/admin/grants", "", nil); status != http.StatusUnauthorized {
		t.Errorf("ohne token: status %d, erwartet 401", status)
	}
	if status, _ := adminCall(t, http.MethodGet, srv.URL+"/v1/admin/grants", "falsch", nil); status != http.StatusUnauthorized {
		t.Errorf("falsches token: status %d, erwartet 401", status)
	}
	if status, _ := adminCall(t, http.MethodGet, srv.URL+"/v1/admin/grants", testToken, nil); status != http.StatusForbidden {
		t.Errorf("nicht-admin: status %d, erwartet 403", status)
	}
}

func TestAdminInaktiverBenutzer(t *testing.T) {
	fs := newFakeAuthStore()
	admin := newFakeAdminStore(fs)
	srv := newAdminServer(t, fs, admin, &fakeVerifier{token: testToken, claims: adminClaims()}, adminGroupName)

	// Erster Zugriff legt den Benutzer an, dann deaktivieren.
	if status, _ := adminCall(t, http.MethodGet, srv.URL+"/v1/admin/grants", testToken, nil); status != http.StatusOK {
		t.Fatal("setup fehlgeschlagen")
	}
	for _, u := range fs.users {
		u.Active = false
	}
	if status, _ := adminCall(t, http.MethodGet, srv.URL+"/v1/admin/grants", testToken, nil); status != http.StatusForbidden {
		t.Errorf("inaktiver admin: status %d, erwartet 403", status)
	}
}

func TestAdminGrantCRUD(t *testing.T) {
	fs := newFakeAuthStore()
	admin := newFakeAdminStore(fs)
	srv := newAdminServer(t, fs, admin, &fakeVerifier{token: testToken, claims: adminClaims()}, adminGroupName)
	base := srv.URL + "/v1/admin/grants"

	// Create: Gruppe existiert noch nicht und wird angelegt.
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
		t.Fatalf("create-antwort: %v", err)
	}
	if created.Group != "deployers" || created.Issuer != adminClaims().Issuer {
		t.Errorf("create: group=%q issuer=%q", created.Group, created.Issuer)
	}

	// List und Get.
	status, body = adminCall(t, http.MethodGet, base, testToken, nil)
	var list []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &list); err != nil || status != http.StatusOK || len(list) != 1 {
		t.Fatalf("list: status %d, %d einträge (%v): %s", status, len(list), err, body)
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
		t.Fatalf("update-antwort: %v", err)
	}
	if !slices.Equal(updated.Principals, []string{"deploy", "root"}) || updated.MaxValiditySeconds != 7200 || updated.Sudo {
		t.Errorf("update nicht übernommen: %+v", updated)
	}

	// Delete.
	if status, _ = adminCall(t, http.MethodDelete, base+"/"+created.ID, testToken, nil); status != http.StatusNoContent {
		t.Errorf("delete: status %d", status)
	}
	if status, _ = adminCall(t, http.MethodGet, base+"/"+created.ID, testToken, nil); status != http.StatusNotFound {
		t.Errorf("get nach delete: status %d, erwartet 404", status)
	}
}

func TestAdminGrantValidierung(t *testing.T) {
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
		{"create ohne group", http.MethodPost, base, map[string]any{
			"principals": []string{"deploy"}, "max_validity_seconds": 3600,
		}, http.StatusBadRequest},
		{"create ohne principals", http.MethodPost, base, map[string]any{
			"group": "x", "max_validity_seconds": 3600,
		}, http.StatusBadRequest},
		{"create ohne laufzeit", http.MethodPost, base, map[string]any{
			"group": "x", "principals": []string{"deploy"},
		}, http.StatusBadRequest},
		{"kaputter body", http.MethodPost, base, "kein-json", http.StatusBadRequest},
		{"update unbekannte id", http.MethodPut, base + "/" + uuid.NewString(), map[string]any{
			"principals": []string{"deploy"}, "max_validity_seconds": 3600,
		}, http.StatusNotFound},
		{"kaputte id", http.MethodGet, base + "/keine-uuid", nil, http.StatusNotFound},
		{"delete unbekannte id", http.MethodDelete, base + "/" + uuid.NewString(), nil, http.StatusNotFound},
	}
	for _, c := range cases {
		if status, body := adminCall(t, c.method, c.url, testToken, c.payload); status != c.wantStatus {
			t.Errorf("%s: status %d (erwartet %d): %s", c.name, status, c.wantStatus, body)
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
		t.Fatalf("apply-antwort: %v", err)
	}
	if result != *admin.applyResult {
		t.Errorf("result = %+v", result)
	}
	if len(admin.applySpecs) != 2 || admin.applySpecs[1].Group != "admins" || !admin.applySpecs[1].Sudo {
		t.Errorf("specs = %+v", admin.applySpecs)
	}

	// Validierungsfehler aus dem Store werden 400.
	admin.applyErr = fmt.Errorf("%w: prüfung", store.ErrInvalidGrantSpec)
	if status, _ := adminCall(t, http.MethodPost, srv.URL+"/v1/admin/grants/apply", testToken,
		map[string]any{"grants": []map[string]any{}}); status != http.StatusBadRequest {
		t.Errorf("apply-validierung: status %d, erwartet 400", status)
	}
}
