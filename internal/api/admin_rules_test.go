package api_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/guided-traffic/guided-ssh/internal/api"
)

// ruleWrite is one write request of the gate matrix.
type ruleWrite struct {
	name   string
	method string
	path   string
	body   map[string]any
}

// hostWrites/ciWrites cover every write endpoint of a domain: CRUD and the
// declarative apply. The gates run before the handlers, so the bodies only
// need to be valid enough for the ungated case.
func hostWrites(id string) []ruleWrite {
	return []ruleWrite{
		{"create", http.MethodPost, "/v1/admin/grants", map[string]any{
			"group": "deployers", "principals": []string{"deploy"}, "max_validity_seconds": 3600,
		}},
		{"update", http.MethodPut, "/v1/admin/grants/" + id, map[string]any{
			"principals": []string{"deploy"}, "max_validity_seconds": 3600,
		}},
		{"delete", http.MethodDelete, "/v1/admin/grants/" + id, nil},
	}
}

func ciWrites(id string) []ruleWrite {
	return []ruleWrite{
		{"create", http.MethodPost, "/v1/admin/ci-grants", map[string]any{
			"project": "infra/ansible", "principals": []string{"deploy"}, "max_validity_seconds": 3600,
		}},
		{"update", http.MethodPut, "/v1/admin/ci-grants/" + id, map[string]any{
			"principals": []string{"deploy"}, "max_validity_seconds": 3600,
		}},
		{"delete", http.MethodDelete, "/v1/admin/ci-grants/" + id, nil},
	}
}

var (
	hostApply = ruleWrite{"apply", http.MethodPost, "/v1/admin/grants/apply", map[string]any{"grants": []any{}}}
	ciApply   = ruleWrite{"apply", http.MethodPost, "/v1/admin/ci-grants/apply", map[string]any{"ci_grants": []any{}}}
)

// assertBlocked expects a 403 with the given machine-readable code (D6).
func assertBlocked(t *testing.T, srv string, write ruleWrite, code string) {
	t.Helper()
	status, body := adminCall(t, write.method, srv+write.path, testToken, write.body)
	if status != http.StatusForbidden {
		t.Errorf("%s %s: status %d, expected 403: %s", write.method, write.path, status, body)
		return
	}
	var payload struct {
		Error string `json:"error"`
		Code  string `json:"code"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Errorf("%s %s: response is not json: %s", write.method, write.path, body)
		return
	}
	if payload.Code != code {
		t.Errorf("%s %s: code %q, expected %q", write.method, write.path, payload.Code, code)
	}
	if payload.Error == "" {
		t.Errorf("%s %s: message missing: %s", write.method, write.path, body)
	}
}

// assertAllowed expects the gate to pass the request through; what the
// handler then answers (404 for an unknown ID, 201 for a create) is the
// business of the CRUD tests.
func assertAllowed(t *testing.T, srv string, write ruleWrite) {
	t.Helper()
	status, body := adminCall(t, write.method, srv+write.path, testToken, write.body)
	if status == http.StatusForbidden {
		t.Errorf("%s %s: blocked with 403, expected to pass the gate: %s", write.method, write.path, body)
	}
}

// TestAdminRuleWriteGatesDefault covers the default row of the D1 matrix:
// manual provisioning off, no file source — CRUD blocked, apply open.
func TestAdminRuleWriteGatesDefault(t *testing.T) {
	fs := newFakeAuthStore()
	srv := newAdminServerRules(t, fs, newFakeAdminStore(fs),
		&fakeVerifier{token: testToken, claims: adminClaims()}, adminGroupName, api.RulesConfig{})
	id := uuid.New().String()

	for _, write := range append(hostWrites(id), ciWrites(id)...) {
		t.Run(write.name+"-"+write.method, func(t *testing.T) {
			assertBlocked(t, srv.URL, write, "manual_rules_disabled")
		})
	}
	assertAllowed(t, srv.URL, hostApply)
	assertAllowed(t, srv.URL, ciApply)
}

// TestAdminRuleWriteGatesManual covers the opt-in row: everything behaves
// like before the GitOps switch.
func TestAdminRuleWriteGatesManual(t *testing.T) {
	fs := newFakeAuthStore()
	admin := newFakeAdminStore(fs)
	srv := newAdminServerRules(t, fs, admin, &fakeVerifier{token: testToken, claims: adminClaims()},
		adminGroupName, api.RulesConfig{ManualRules: true})
	id := uuid.New().String()

	for _, write := range append(hostWrites(id), ciWrites(id)...) {
		assertAllowed(t, srv.URL, write)
	}
	assertAllowed(t, srv.URL, hostApply)
	assertAllowed(t, srv.URL, ciApply)
}

// TestAdminRuleWriteGatesFileOwned covers the file rows: a file-owned domain
// rejects CRUD *and* apply, regardless of the manual flag, while the other
// domain keeps its own rules — the two switches are independent.
func TestAdminRuleWriteGatesFileOwned(t *testing.T) {
	for _, manual := range []bool{false, true} {
		t.Run("manual-"+map[bool]string{false: "off", true: "on"}[manual], func(t *testing.T) {
			fs := newFakeAuthStore()
			srv := newAdminServerRules(t, fs, newFakeAdminStore(fs),
				&fakeVerifier{token: testToken, claims: adminClaims()}, adminGroupName,
				api.RulesConfig{ManualRules: manual, HostFile: "/etc/guided-ssh/rules/host/rules.yaml"})
			id := uuid.New().String()

			for _, write := range append(hostWrites(id), hostApply) {
				assertBlocked(t, srv.URL, write, "rules_file_managed")
			}
			// CI has no file source: it follows the manual flag alone.
			for _, write := range ciWrites(id) {
				if manual {
					assertAllowed(t, srv.URL, write)
				} else {
					assertBlocked(t, srv.URL, write, "manual_rules_disabled")
				}
			}
			assertAllowed(t, srv.URL, ciApply)
		})
	}
}

// TestAdminRuleReadsStayOpen makes sure the gates never touch reads — the
// pages stay visible for auditors and admins in every mode.
func TestAdminRuleReadsStayOpen(t *testing.T) {
	fs := newFakeAuthStore()
	srv := newAdminServerRules(t, fs, newFakeAdminStore(fs),
		&fakeVerifier{token: testToken, claims: adminClaims()}, adminGroupName,
		api.RulesConfig{HostFile: "host.yaml", CIFile: "ci.yaml"})

	for _, path := range []string{"/v1/admin/grants", "/v1/admin/ci-grants"} {
		if status, body := adminCall(t, http.MethodGet, srv.URL+path, testToken, nil); status != http.StatusOK {
			t.Errorf("GET %s: status %d, expected 200: %s", path, status, body)
		}
	}
}
