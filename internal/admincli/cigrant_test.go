package admincli

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func boolPtr(b bool) *bool { return &b }

func TestCIGrantList(t *testing.T) {
	api := &fakeAdminAPI{t: t, ciGrants: []CIGrant{{
		ID: "ci-1", Project: "infra/ansible", RefPattern: "main",
		ProtectedOnly: boolPtr(true), TagSelector: map[string]string{"env": "prod"},
		Principals: []string{"deploy"}, MaxValiditySeconds: 3600,
	}}}
	code, stdout, stderr := runCLI(t, api, "ci-grant", "list")
	if code != 0 {
		t.Fatalf("code %d: %s", code, stderr)
	}
	for _, want := range []string{"infra/ansible", "main", "env=prod", "deploy", "1h0m0s"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("ausgabe ohne %q:\n%s", want, stdout)
		}
	}
}

func TestCIGrantCreate(t *testing.T) {
	api := &fakeAdminAPI{t: t}
	code, stdout, stderr := runCLI(t, api,
		"ci-grant", "create", "--project", "infra/ansible", "--principals", "deploy",
		"--ref", "main", "--environment", "prod", "--tags", "env=prod", "--max-validity", "30m")
	if code != 0 {
		t.Fatalf("code %d: %s", code, stderr)
	}
	if api.method != http.MethodPost || api.lastPath != "/v1/admin/ci-grants" {
		t.Errorf("request: %s %s", api.method, api.lastPath)
	}
	if api.lastBody["project"] != "infra/ansible" || api.lastBody["ref_pattern"] != "main" ||
		api.lastBody["protected_only"] != true || api.lastBody["environment_pattern"] != "prod" ||
		api.lastBody["max_validity_seconds"] != float64(1800) {
		t.Errorf("body = %v", api.lastBody)
	}
	if !strings.Contains(stdout, "ci-neu-1") {
		t.Errorf("ausgabe ohne id: %s", stdout)
	}
}

func TestCIGrantCreatePflichtfelder(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run(&stdout, &stderr, []string{"ci-grant", "create", "--project", "x"}); code != 2 {
		t.Errorf("ohne principals: code %d, erwartet 2", code)
	}
	if code := Run(&stdout, &stderr, []string{"ci-grant", "create", "--principals", "deploy"}); code != 2 {
		t.Errorf("ohne project: code %d, erwartet 2", code)
	}
	if code := Run(&stdout, &stderr, []string{"ci-grant"}); code != 2 {
		t.Errorf("ohne subkommando: code %d, erwartet 2", code)
	}
	if code := Run(&stdout, &stderr, []string{"ci-grant", "quatsch"}); code != 2 {
		t.Errorf("unbekanntes subkommando: code %d, erwartet 2", code)
	}
}

func TestCIGrantUpdate(t *testing.T) {
	api := &fakeAdminAPI{t: t, ciGrants: []CIGrant{{
		ID: "ci-1", Project: "infra/ansible", RefPattern: "main",
		ProtectedOnly: boolPtr(true), Principals: []string{"deploy"}, MaxValiditySeconds: 3600,
	}}}
	code, _, stderr := runCLI(t, api,
		"ci-grant", "update", "ci-1", "--principals", "deploy,ansible", "--protected-only=false")
	if code != 0 {
		t.Fatalf("code %d: %s", code, stderr)
	}
	if api.method != http.MethodPut || api.lastPath != "/v1/admin/ci-grants/ci-1" {
		t.Errorf("request: %s %s", api.method, api.lastPath)
	}
	// Nicht angegebene Felder bleiben erhalten, principals/protected sind neu.
	principals, _ := api.lastBody["principals"].([]any)
	if len(principals) != 2 || api.lastBody["protected_only"] != false ||
		api.lastBody["ref_pattern"] != "main" || api.lastBody["max_validity_seconds"] != float64(3600) {
		t.Errorf("body = %v", api.lastBody)
	}

	var stdout, errOut bytes.Buffer
	if code := Run(&stdout, &errOut, []string{"ci-grant", "update"}); code != 2 {
		t.Errorf("update ohne id: code %d, erwartet 2", code)
	}
}

func TestCIGrantDelete(t *testing.T) {
	api := &fakeAdminAPI{t: t}
	code, stdout, stderr := runCLI(t, api, "ci-grant", "delete", "ci-1")
	if code != 0 {
		t.Fatalf("code %d: %s", code, stderr)
	}
	if api.method != http.MethodDelete || api.lastPath != "/v1/admin/ci-grants/ci-1" {
		t.Errorf("request: %s %s", api.method, api.lastPath)
	}
	if !strings.Contains(stdout, "ci-1") {
		t.Errorf("ausgabe: %s", stdout)
	}

	var out, errOut bytes.Buffer
	if code := Run(&out, &errOut, []string{"ci-grant", "delete"}); code != 2 {
		t.Errorf("delete ohne id: code %d, erwartet 2", code)
	}
}

func TestApplyMitCIGrants(t *testing.T) {
	yaml := `grants:
  - group: deployers
    principals: [deploy]
    max_validity: 8h
ci_grants:
  - project: infra/ansible
    ref: main
    environment: prod
    tags:
      env: prod
    principals: [deploy]
    max_validity: 1h
  - project: infra
    protected_only: false
    principals: [ansible]
    max_validity: 30m
`
	path := filepath.Join(t.TempDir(), "grants.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	api := &fakeAdminAPI{t: t}
	code, stdout, stderr := runCLI(t, api, "apply", "-f", path)
	if code != 0 {
		t.Fatalf("code %d: %s", code, stderr)
	}
	// Letzter Request ist der CI-Abgleich.
	if api.lastPath != "/v1/admin/ci-grants/apply" {
		t.Errorf("pfad: %s", api.lastPath)
	}
	ciGrants, _ := api.lastBody["ci_grants"].([]any)
	if len(ciGrants) != 2 {
		t.Fatalf("ci-apply-body: %v", api.lastBody)
	}
	first, _ := ciGrants[0].(map[string]any)
	if first["project"] != "infra/ansible" || first["ref_pattern"] != "main" ||
		first["environment_pattern"] != "prod" || first["max_validity_seconds"] != float64(3600) {
		t.Errorf("erster ci-grant: %v", first)
	}
	second, _ := ciGrants[1].(map[string]any)
	if second["protected_only"] != false {
		t.Errorf("zweiter ci-grant (protected_only): %v", second)
	}
	if !strings.Contains(stdout, "ci-abgleich fertig: 1 angelegt") {
		t.Errorf("zusammenfassung: %s", stdout)
	}
}

func TestApplyOhneCIAbschnittLaesstCIGrantsUnberuehrt(t *testing.T) {
	yaml := "grants:\n  - group: deployers\n    principals: [deploy]\n    max_validity: 8h\n"
	path := filepath.Join(t.TempDir(), "grants.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	api := &fakeAdminAPI{t: t}
	code, stdout, stderr := runCLI(t, api, "apply", "-f", path)
	if code != 0 {
		t.Fatalf("code %d: %s", code, stderr)
	}
	// Kein zweiter Request: letzter Pfad bleibt der Grant-Abgleich.
	if api.lastPath != "/v1/admin/grants/apply" {
		t.Errorf("pfad: %s (ci-abgleich darf nicht laufen)", api.lastPath)
	}
	if strings.Contains(stdout, "ci-abgleich") {
		t.Errorf("unerwarteter ci-abgleich: %s", stdout)
	}
}
