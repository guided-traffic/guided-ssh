package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"testing"

	"github.com/google/uuid"

	"github.com/guided-traffic/guided-ssh/internal/store"
)

// CI-Grant-Anteil des fakeAdminStore (Phase 7).

func (f *fakeAdminStore) ListCIGrants(context.Context) ([]store.CIGrant, error) {
	out := make([]store.CIGrant, 0, len(f.ciGrants))
	for _, g := range f.ciGrants {
		out = append(out, *g)
	}
	return out, nil
}

func (f *fakeAdminStore) GetCIGrant(_ context.Context, id uuid.UUID) (*store.CIGrant, error) {
	g, ok := f.ciGrants[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	copied := *g
	return &copied, nil
}

func (f *fakeAdminStore) CreateCIGrant(_ context.Context, actor string, g *store.CIGrant) error {
	if actor == "" {
		return fmt.Errorf("actor fehlt") //nolint:err113
	}
	g.ID = uuid.New()
	copied := *g
	f.ciGrants[g.ID] = &copied
	return nil
}

func (f *fakeAdminStore) UpdateCIGrant(_ context.Context, _ string, g *store.CIGrant) error {
	if _, ok := f.ciGrants[g.ID]; !ok {
		return store.ErrNotFound
	}
	copied := *g
	f.ciGrants[g.ID] = &copied
	return nil
}

func (f *fakeAdminStore) DeleteCIGrant(_ context.Context, _ string, id uuid.UUID) error {
	if _, ok := f.ciGrants[id]; !ok {
		return store.ErrNotFound
	}
	delete(f.ciGrants, id)
	return nil
}

func (f *fakeAdminStore) ApplyCIGrants(_ context.Context, _ string, specs []store.CIGrantSpec) (*store.ApplyResult, error) {
	f.applyCISpecs = specs
	if f.applyErr != nil {
		return nil, f.applyErr
	}
	return &store.ApplyResult{Created: len(specs)}, nil
}

func TestAdminCIGrantCRUD(t *testing.T) {
	fs := newFakeAuthStore()
	admin := newFakeAdminStore(fs)
	srv := newAdminServer(t, fs, admin, &fakeVerifier{token: testToken, claims: adminClaims()}, adminGroupName)
	base := srv.URL + "/v1/admin/ci-grants"

	// Create: protected_only defaultet auf true.
	status, body := adminCall(t, http.MethodPost, base, testToken, map[string]any{
		"project":              "infra/ansible",
		"ref_pattern":          "main",
		"tag_selector":         map[string]string{"env": "prod"},
		"principals":           []string{"deploy"},
		"max_validity_seconds": 3600,
	})
	if status != http.StatusCreated {
		t.Fatalf("create: status %d: %s", status, body)
	}
	var created struct {
		ID            string `json:"id"`
		Project       string `json:"project"`
		ProtectedOnly bool   `json:"protected_only"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatalf("create-antwort: %v", err)
	}
	if created.Project != "infra/ansible" || !created.ProtectedOnly {
		t.Errorf("create: %+v", created)
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

	// Update: protected_only explizit aus, neue principals.
	status, body = adminCall(t, http.MethodPut, base+"/"+created.ID, testToken, map[string]any{
		"ref_pattern":          "release/*",
		"protected_only":       false,
		"principals":           []string{"deploy", "ansible"},
		"max_validity_seconds": 1800,
	})
	if status != http.StatusOK {
		t.Fatalf("update: status %d: %s", status, body)
	}
	var updated struct {
		RefPattern         string   `json:"ref_pattern"`
		ProtectedOnly      bool     `json:"protected_only"`
		Principals         []string `json:"principals"`
		MaxValiditySeconds int64    `json:"max_validity_seconds"`
	}
	if err := json.Unmarshal(body, &updated); err != nil {
		t.Fatalf("update-antwort: %v", err)
	}
	if updated.RefPattern != "release/*" || updated.ProtectedOnly ||
		!slices.Equal(updated.Principals, []string{"deploy", "ansible"}) || updated.MaxValiditySeconds != 1800 {
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

func TestAdminCIGrantValidierung(t *testing.T) {
	fs := newFakeAuthStore()
	admin := newFakeAdminStore(fs)
	srv := newAdminServer(t, fs, admin, &fakeVerifier{token: testToken, claims: adminClaims()}, adminGroupName)
	base := srv.URL + "/v1/admin/ci-grants"

	cases := []struct {
		name       string
		method     string
		url        string
		payload    any
		wantStatus int
	}{
		{"create ohne project", http.MethodPost, base, map[string]any{
			"principals": []string{"deploy"}, "max_validity_seconds": 3600,
		}, http.StatusBadRequest},
		{"create ohne principals", http.MethodPost, base, map[string]any{
			"project": "x", "max_validity_seconds": 3600,
		}, http.StatusBadRequest},
		{"create ohne laufzeit", http.MethodPost, base, map[string]any{
			"project": "x", "principals": []string{"deploy"},
		}, http.StatusBadRequest},
		{"kaputter body", http.MethodPost, base, "kein-json", http.StatusBadRequest},
		{"update unbekannte id", http.MethodPut, base + "/" + uuid.NewString(), map[string]any{
			"principals": []string{"deploy"}, "max_validity_seconds": 3600,
		}, http.StatusNotFound},
		{"delete unbekannte id", http.MethodDelete, base + "/" + uuid.NewString(), nil, http.StatusNotFound},
	}
	for _, c := range cases {
		if status, body := adminCall(t, c.method, c.url, testToken, c.payload); status != c.wantStatus {
			t.Errorf("%s: status %d (erwartet %d): %s", c.name, status, c.wantStatus, body)
		}
	}
}

func TestAdminCIApply(t *testing.T) {
	fs := newFakeAuthStore()
	admin := newFakeAdminStore(fs)
	srv := newAdminServer(t, fs, admin, &fakeVerifier{token: testToken, claims: adminClaims()}, adminGroupName)

	status, body := adminCall(t, http.MethodPost, srv.URL+"/v1/admin/ci-grants/apply", testToken, map[string]any{
		"ci_grants": []map[string]any{
			{"project": "infra/ansible", "principals": []string{"deploy"}, "max_validity_seconds": 3600},
			{
				"project": "infra", "ref_pattern": "main", "protected_only": false,
				"principals": []string{"ansible"}, "max_validity_seconds": 1800,
			},
		},
	})
	if status != http.StatusOK {
		t.Fatalf("apply: status %d: %s", status, body)
	}
	if len(admin.applyCISpecs) != 2 {
		t.Fatalf("specs = %+v", admin.applyCISpecs)
	}
	if admin.applyCISpecs[0].ProjectPath != "infra/ansible" || !admin.applyCISpecs[0].ProtectedOnly {
		t.Errorf("spec 0 (protected_only muss defaulten): %+v", admin.applyCISpecs[0])
	}
	if admin.applyCISpecs[1].ProtectedOnly {
		t.Errorf("spec 1 (protected_only explizit false): %+v", admin.applyCISpecs[1])
	}

	// Validierungsfehler aus dem Store werden 400.
	admin.applyErr = fmt.Errorf("%w: prüfung", store.ErrInvalidGrantSpec)
	if status, _ := adminCall(t, http.MethodPost, srv.URL+"/v1/admin/ci-grants/apply", testToken,
		map[string]any{"ci_grants": []map[string]any{}}); status != http.StatusBadRequest {
		t.Errorf("apply-validierung: status %d, erwartet 400", status)
	}
}
