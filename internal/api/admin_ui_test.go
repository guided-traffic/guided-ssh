package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/guided-traffic/guided-ssh/internal/api"
	"github.com/guided-traffic/guided-ssh/internal/auth"
	"github.com/guided-traffic/guided-ssh/internal/ca"
	"github.com/guided-traffic/guided-ssh/internal/store"
)

// Role groups for the UI tests.
const (
	auditorGroupName  = "gssh-auditors"
	readonlyGroupName = "gssh-readonly"
)

// roleVerifier accepts several tokens each with their own claims (for role
// tests with admin, auditor, and read-only side by side).
type roleVerifier struct {
	claims map[string]*auth.Claims
}

func (v *roleVerifier) Verify(_ context.Context, rawToken string) (*auth.Claims, error) {
	claims, ok := v.claims[rawToken]
	if !ok {
		return nil, fmt.Errorf("%w: unknown token", auth.ErrInvalidToken)
	}
	copied := *claims
	return &copied, nil
}

// claimsWithGroups builds claims for a user with the given groups.
func claimsWithGroups(subject string, groups ...string) *auth.Claims {
	return &auth.Claims{
		Issuer:            "https://idp.example.com/realms/gssh",
		Subject:           subject,
		Email:             subject + "@example.com",
		PreferredUsername: subject,
		Groups:            groups,
	}
}

// fakeUIStore is an in-memory UIStore; it records the last seen audit
// filter and the actor of the service account change.
type fakeUIStore struct {
	hosts      []store.HostDetailed
	users      []store.UserDetailed
	groups     []store.Group
	accounts   map[uuid.UUID]*store.ServiceAccount
	certs      []store.Certificate
	events     []store.AuditEvent
	lastFilter store.AuditFilter
	saActor    string
	// tokens are the minted enrollment token records (phase C); tokenErr
	// forces a store error.
	tokens   []store.EnrollmentToken
	tokenErr error
}

func (f *fakeUIStore) ListHostsDetailed(context.Context) ([]store.HostDetailed, error) {
	return f.hosts, nil
}

func (f *fakeUIStore) ListUsersDetailed(context.Context) ([]store.UserDetailed, error) {
	return f.users, nil
}

func (f *fakeUIStore) ListGroups(context.Context) ([]store.Group, error) { return f.groups, nil }

func (f *fakeUIStore) ListServiceAccounts(context.Context) ([]store.ServiceAccount, error) {
	var out []store.ServiceAccount
	for _, a := range f.accounts {
		out = append(out, *a)
	}
	return out, nil
}

func (f *fakeUIStore) SetServiceAccountActive(_ context.Context, actor string, id uuid.UUID, active bool) (*store.ServiceAccount, error) {
	account, ok := f.accounts[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	f.saActor = actor
	account.Active = active
	copied := *account
	return &copied, nil
}

func (f *fakeUIStore) ListCertificates(_ context.Context, limit int) ([]store.Certificate, error) {
	if limit < len(f.certs) {
		return f.certs[:limit], nil
	}
	return f.certs, nil
}

func (f *fakeUIStore) ListAuditEvents(_ context.Context, filter store.AuditFilter) ([]store.AuditEvent, error) {
	f.lastFilter = filter
	return f.events, nil
}

func (f *fakeUIStore) CountAuditEvents(_ context.Context, _ store.AuditFilter) (int64, error) {
	return int64(len(f.events)), nil
}

func (f *fakeUIStore) CreateEnrollmentToken(_ context.Context, t *store.EnrollmentToken) error {
	if f.tokenErr != nil {
		return f.tokenErr
	}
	if t.Tags == nil {
		t.Tags = map[string]string{}
	}
	t.ID = uuid.New()
	f.tokens = append(f.tokens, *t)
	return nil
}

func (f *fakeUIStore) AppendAuditEvent(_ context.Context, e *store.AuditEvent) error {
	f.events = append(f.events, *e)
	return nil
}

// uiTestEnv bundles the server, the store, and the tokens of the three roles.
type uiTestEnv struct {
	srv           *httptest.Server
	ui            *fakeUIStore
	adminToken    string
	auditorToken  string
	readonlyToken string
	noRoleToken   string
}

// newUIServer builds the test server with all three role groups and a UIStore.
func newUIServer(t *testing.T) *uiTestEnv {
	t.Helper()
	return newUIServerWithDeps(t, nil)
}

// newUIServerWithDeps additionally allows adjusting Deps before startup
// (e.g. the rollout conditions of token minting).
func newUIServerWithDeps(t *testing.T, mutate func(*api.Deps)) *uiTestEnv {
	t.Helper()
	fs := newFakeAuthStore()
	masterKey := make([]byte, ca.MasterKeySize)
	certAuthority, err := ca.New(&fs.fakeStore, masterKey, ca.NewPolicyEngine(ca.DefaultPolicies()))
	if err != nil {
		t.Fatalf("ca.New: %v", err)
	}
	if err := certAuthority.EnsureCAKeys(context.Background()); err != nil {
		t.Fatalf("EnsureCAKeys: %v", err)
	}

	ui := &fakeUIStore{accounts: map[uuid.UUID]*store.ServiceAccount{}}
	verifier := &roleVerifier{claims: map[string]*auth.Claims{
		"admin-token":    claimsWithGroups("admin", adminGroupName),
		"auditor-token":  claimsWithGroups("auditor", auditorGroupName),
		"readonly-token": claimsWithGroups("viewer", readonlyGroupName),
		"norole-token":   claimsWithGroups("nobody", "dev"),
	}}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	deps := api.Deps{
		CA: certAuthority, Store: fs, Grants: fs, Admin: newFakeAdminStore(fs), UI: ui,
		Verifier: verifier, Logger: logger,
		AdminGroup: adminGroupName, AuditorGroup: auditorGroupName, ReadOnlyGroup: readonlyGroupName,
		UIConfig: api.UIConfig{OIDCIssuer: "https://idp.example.com/realms/gssh", OIDCClientID: "gssh-cli"},
	}
	if mutate != nil {
		mutate(&deps)
	}
	srv := httptest.NewServer(api.New(deps))
	t.Cleanup(srv.Close)
	return &uiTestEnv{
		srv: srv, ui: ui,
		adminToken: "admin-token", auditorToken: "auditor-token",
		readonlyToken: "readonly-token", noRoleToken: "norole-token",
	}
}

func TestUIConfigPublic(t *testing.T) {
	env := newUIServer(t)
	status, body := adminCall(t, http.MethodGet, env.srv.URL+"/v1/ui/config", "", nil)
	if status != http.StatusOK {
		t.Fatalf("status %d, expected 200", status)
	}
	var cfg map[string]string
	if err := json.Unmarshal(body, &cfg); err != nil {
		t.Fatalf("parsing response: %v", err)
	}
	if cfg["oidc_issuer"] != "https://idp.example.com/realms/gssh" || cfg["oidc_client_id"] != "gssh-cli" {
		t.Errorf("oidc configuration wrong: %v", cfg)
	}
	if cfg["admin_group"] != adminGroupName || cfg["auditor_group"] != auditorGroupName || cfg["readonly_group"] != readonlyGroupName {
		t.Errorf("role groups wrong: %v", cfg)
	}
}

func TestUIRoles(t *testing.T) {
	env := newUIServer(t)
	saID := uuid.New()
	env.ui.accounts[saID] = &store.ServiceAccount{ID: saID, Name: "infra/ansible", Kind: store.KindGitLabCI, Active: true}

	cases := []struct {
		name, method, path, token string
		payload                   any
		want                      int
	}{
		{"readonly reads hosts", http.MethodGet, "/v1/admin/hosts", env.readonlyToken, nil, http.StatusOK},
		{"readonly reads grants", http.MethodGet, "/v1/admin/grants", env.readonlyToken, nil, http.StatusOK},
		{"readonly cannot read audit", http.MethodGet, "/v1/admin/audit", env.readonlyToken, nil, http.StatusForbidden},
		{"readonly no export", http.MethodGet, "/v1/admin/audit/export", env.readonlyToken, nil, http.StatusForbidden},
		{"readonly does not mutate", http.MethodPatch, "/v1/admin/service-accounts/" + saID.String(), env.readonlyToken, map[string]any{"active": false}, http.StatusForbidden},
		{"auditor reads audit", http.MethodGet, "/v1/admin/audit", env.auditorToken, nil, http.StatusOK},
		{"auditor reads hosts", http.MethodGet, "/v1/admin/hosts", env.auditorToken, nil, http.StatusOK},
		{"auditor does not mutate", http.MethodPatch, "/v1/admin/service-accounts/" + saID.String(), env.auditorToken, map[string]any{"active": false}, http.StatusForbidden},
		{"admin reads audit", http.MethodGet, "/v1/admin/audit", env.adminToken, nil, http.StatusOK},
		{"admin mutates", http.MethodPatch, "/v1/admin/service-accounts/" + saID.String(), env.adminToken, map[string]any{"active": false}, http.StatusOK},
		{"no role gets nothing", http.MethodGet, "/v1/admin/hosts", env.noRoleToken, nil, http.StatusForbidden},
		{"no token 401", http.MethodGet, "/v1/admin/hosts", "", nil, http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, body := adminCall(t, tc.method, env.srv.URL+tc.path, tc.token, tc.payload)
			if status != tc.want {
				t.Fatalf("status %d, expected %d (body %s)", status, tc.want, body)
			}
		})
	}
}

func TestUIHostsList(t *testing.T) {
	env := newUIServer(t)
	expiry := time.Now().Add(20 * 24 * time.Hour).UTC().Truncate(time.Second)
	env.ui.hosts = []store.HostDetailed{{
		Host:            store.Host{ID: uuid.New(), Name: "web-1"},
		Tags:            map[string]string{"env": "prod", "role": "web"},
		CertValidBefore: &expiry,
	}}

	status, body := adminCall(t, http.MethodGet, env.srv.URL+"/v1/admin/hosts", env.readonlyToken, nil)
	if status != http.StatusOK {
		t.Fatalf("status %d, expected 200 (body %s)", status, body)
	}
	var hosts []struct {
		Name            string            `json:"name"`
		Tags            map[string]string `json:"tags"`
		CertValidBefore *time.Time        `json:"cert_valid_before"`
	}
	if err := json.Unmarshal(body, &hosts); err != nil {
		t.Fatalf("parsing response: %v", err)
	}
	if len(hosts) != 1 || hosts[0].Name != "web-1" || hosts[0].Tags["env"] != "prod" {
		t.Errorf("hosts wrong: %+v", hosts)
	}
	if hosts[0].CertValidBefore == nil || !hosts[0].CertValidBefore.Equal(expiry) {
		t.Errorf("cert_valid_before wrong: %v", hosts[0].CertValidBefore)
	}
}

func TestUIUsersWithGroups(t *testing.T) {
	env := newUIServer(t)
	env.ui.users = []store.UserDetailed{{
		User:   store.User{ID: uuid.New(), Username: "alice", Email: "alice@example.com", Active: true},
		Groups: []string{"admins", "dev"},
	}}
	status, body := adminCall(t, http.MethodGet, env.srv.URL+"/v1/admin/users", env.readonlyToken, nil)
	if status != http.StatusOK {
		t.Fatalf("status %d, expected 200", status)
	}
	var users []struct {
		Username string   `json:"username"`
		Groups   []string `json:"groups"`
	}
	if err := json.Unmarshal(body, &users); err != nil {
		t.Fatalf("parsing response: %v", err)
	}
	if len(users) != 1 || users[0].Username != "alice" || len(users[0].Groups) != 2 {
		t.Errorf("user wrong: %+v", users)
	}
}

func TestUIAuditFilter(t *testing.T) {
	env := newUIServer(t)
	env.ui.events = []store.AuditEvent{
		{ID: 2, EventType: "ca.cert_issued", Actor: "user:alice@idp", Payload: []byte(`{"host":"web-1"}`)},
	}

	url := env.srv.URL + "/v1/admin/audit?event_type=ca.cert_issued&actor=user:alice@idp&q=web-1" +
		"&since=2026-07-01T00:00:00Z&until=2026-07-19T00:00:00Z&limit=9999&offset=10"
	status, body := adminCall(t, http.MethodGet, url, env.auditorToken, nil)
	if status != http.StatusOK {
		t.Fatalf("status %d, expected 200 (body %s)", status, body)
	}
	var result struct {
		Events []json.RawMessage `json:"events"`
		Total  int64             `json:"total"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("parsing response: %v", err)
	}
	if len(result.Events) != 1 || result.Total != 1 {
		t.Errorf("events/total wrong: %d/%d", len(result.Events), result.Total)
	}

	filter := env.ui.lastFilter
	if filter.EventType != "ca.cert_issued" || filter.Actor != "user:alice@idp" || filter.Search != "web-1" {
		t.Errorf("filter wrong: %+v", filter)
	}
	if filter.Limit != 500 {
		t.Errorf("limit %d, expected clamp to 500", filter.Limit)
	}
	if filter.Offset != 10 || filter.Since.IsZero() || filter.Until.IsZero() {
		t.Errorf("offset/range wrong: %+v", filter)
	}

	// Invalid timestamp ⇒ 400.
	status, _ = adminCall(t, http.MethodGet, env.srv.URL+"/v1/admin/audit?since=yesterday", env.auditorToken, nil)
	if status != http.StatusBadRequest {
		t.Fatalf("status %d, expected 400", status)
	}
}

func TestUIAuditExport(t *testing.T) {
	env := newUIServer(t)
	env.ui.events = []store.AuditEvent{
		{ID: 1, OccurredAt: time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC), EventType: "grant.created", Actor: "user:admin@idp", Payload: []byte(`{"grant_id":"g1"}`)},
		{ID: 2, OccurredAt: time.Date(2026, 7, 18, 13, 0, 0, 0, time.UTC), EventType: "ca.cert_issued", Actor: "ci:infra:42:7", Payload: []byte(`{}`)},
	}

	req, _ := http.NewRequest(http.MethodGet, env.srv.URL+"/v1/admin/audit/export?format=csv", nil)
	req.Header.Set("Authorization", "Bearer "+env.auditorToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, expected 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Errorf("content-type %q, expected text/csv", ct)
	}
	if cd := resp.Header.Get("Content-Disposition"); !strings.Contains(cd, "audit-export.csv") {
		t.Errorf("content-disposition %q", cd)
	}
	data, _ := io.ReadAll(resp.Body)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 3 { // header + 2 events
		t.Fatalf("%d lines, expected 3: %q", len(lines), string(data))
	}
	if lines[0] != "id,occurred_at,event_type,actor,payload" {
		t.Errorf("csv header wrong: %q", lines[0])
	}
	if !strings.Contains(lines[1], "grant.created") || !strings.Contains(lines[2], "ci:infra:42:7") {
		t.Errorf("csv lines wrong: %q", lines)
	}

	// JSON export as a download; export enforces the export limit.
	status, body := adminCall(t, http.MethodGet, env.srv.URL+"/v1/admin/audit/export?limit=1&offset=5", env.auditorToken, nil)
	if status != http.StatusOK {
		t.Fatalf("status %d, expected 200", status)
	}
	var events []json.RawMessage
	if err := json.Unmarshal(body, &events); err != nil {
		t.Fatalf("parsing json export: %v", err)
	}
	if len(events) != 2 {
		t.Errorf("%d events, expected 2", len(events))
	}
	if env.ui.lastFilter.Limit != 100_000 || env.ui.lastFilter.Offset != 0 {
		t.Errorf("export filter wrong: %+v", env.ui.lastFilter)
	}
}

func TestUIServiceAccountPatch(t *testing.T) {
	env := newUIServer(t)
	saID := uuid.New()
	env.ui.accounts[saID] = &store.ServiceAccount{ID: saID, Name: "infra/ansible", Kind: store.KindGitLabCI, Active: true}

	status, body := adminCall(t, http.MethodPatch,
		env.srv.URL+"/v1/admin/service-accounts/"+saID.String(), env.adminToken,
		map[string]any{"active": false})
	if status != http.StatusOK {
		t.Fatalf("status %d, expected 200 (body %s)", status, body)
	}
	var updated struct {
		Active bool `json:"active"`
	}
	if err := json.Unmarshal(body, &updated); err != nil {
		t.Fatalf("parsing response: %v", err)
	}
	if updated.Active || env.ui.accounts[saID].Active {
		t.Error("active not set to false")
	}
	if env.ui.saActor == "" {
		t.Error("actor missing (no audit context)")
	}

	// Body without active ⇒ 400; unknown ID ⇒ 404.
	status, _ = adminCall(t, http.MethodPatch, env.srv.URL+"/v1/admin/service-accounts/"+saID.String(), env.adminToken, map[string]any{})
	if status != http.StatusBadRequest {
		t.Fatalf("status %d, expected 400", status)
	}
	status, _ = adminCall(t, http.MethodPatch, env.srv.URL+"/v1/admin/service-accounts/"+uuid.NewString(), env.adminToken, map[string]any{"active": true})
	if status != http.StatusNotFound {
		t.Fatalf("status %d, expected 404", status)
	}
}

func TestUICertificatesLimit(t *testing.T) {
	env := newUIServer(t)
	for i := range 5 {
		env.ui.certs = append(env.ui.certs, store.Certificate{
			ID: uuid.New(), Serial: int64(i + 1), KeyID: fmt.Sprintf("user:key-%d", i), CertType: store.CertTypeUser,
		})
	}
	status, body := adminCall(t, http.MethodGet, env.srv.URL+"/v1/admin/certificates?limit=2", env.readonlyToken, nil)
	if status != http.StatusOK {
		t.Fatalf("status %d, expected 200", status)
	}
	var certs []json.RawMessage
	if err := json.Unmarshal(body, &certs); err != nil {
		t.Fatalf("parsing response: %v", err)
	}
	if len(certs) != 2 {
		t.Errorf("%d certificates, expected 2", len(certs))
	}
}
