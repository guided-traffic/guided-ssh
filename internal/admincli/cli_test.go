package admincli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testToken = "test-token" //#nosec G101 -- Testwert, kein Credential

// writeConfig legt eine minimale CLI-Konfiguration an und liefert den Pfad.
func writeConfig(t *testing.T, apiURL string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	content := "api_url: " + apiURL + "\nissuer: https://idp.example/realms/x\nclient_id: gssh-cli\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("config schreiben: %v", err)
	}
	return path
}

// fakeAdminAPI ist ein Fake der Admin-API; er prüft das Bearer-Token und
// zeichnet Requests auf.
type fakeAdminAPI struct {
	t        *testing.T
	grants   []Grant
	ciGrants []CIGrant
	lastBody map[string]any
	lastPath string
	method   string
}

func (f *fakeAdminAPI) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		f.lastPath = r.URL.Path
		f.method = r.Method
		if r.Body != nil {
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err == nil {
				f.lastBody = body
			}
		}
		isCI := strings.HasPrefix(r.URL.Path, "/v1/admin/ci-grants")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/admin/grants":
			_ = json.NewEncoder(w).Encode(f.grants)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/admin/ci-grants":
			_ = json.NewEncoder(w).Encode(f.ciGrants)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/admin/grants/apply":
			_ = json.NewEncoder(w).Encode(ApplyResult{Created: 2, Deleted: 1})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/admin/ci-grants/apply":
			_ = json.NewEncoder(w).Encode(ApplyResult{Created: 1, Unchanged: 1})
		case r.Method == http.MethodPost && isCI:
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(CIGrant{ID: "ci-neu-1", Project: "infra/ansible"})
		case r.Method == http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(Grant{ID: "neu-1", Group: "deployers"})
		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPut && isCI:
			_ = json.NewEncoder(w).Encode(CIGrant{ID: strings.TrimPrefix(r.URL.Path, "/v1/admin/ci-grants/"), Project: "infra/ansible"})
		case r.Method == http.MethodPut:
			_ = json.NewEncoder(w).Encode(Grant{ID: strings.TrimPrefix(r.URL.Path, "/v1/admin/grants/"), Group: "deployers"})
		case r.Method == http.MethodGet && isCI:
			if len(f.ciGrants) == 0 {
				http.Error(w, "nicht gefunden", http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(f.ciGrants[0])
		case r.Method == http.MethodGet:
			if len(f.grants) == 0 {
				http.Error(w, "nicht gefunden", http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(f.grants[0])
		default:
			http.Error(w, "unerwartet", http.StatusTeapot)
		}
	})
}

// runCLI führt Run mit Testservern aus und liefert Exit-Code und Ausgaben.
func runCLI(t *testing.T, api *fakeAdminAPI, args ...string) (int, string, string) {
	t.Helper()
	srv := httptest.NewServer(api.handler())
	t.Cleanup(srv.Close)
	config := writeConfig(t, srv.URL)
	var stdout, stderr bytes.Buffer
	full := append(args, "--config", config, "--token", testToken)
	code := Run(&stdout, &stderr, full)
	return code, stdout.String(), stderr.String()
}

func TestUsageUndUnbekanntesKommando(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run(&stdout, &stderr, nil); code != 2 {
		t.Errorf("ohne argumente: code %d, erwartet 2", code)
	}
	if code := Run(&stdout, &stderr, []string{"help"}); code != 0 {
		t.Errorf("help: code %d", code)
	}
	if code := Run(&stdout, &stderr, []string{"quatsch"}); code != 2 {
		t.Errorf("unbekanntes kommando: code %d, erwartet 2", code)
	}
	if code := Run(&stdout, &stderr, []string{"grant"}); code != 2 {
		t.Errorf("grant ohne subkommando: code %d, erwartet 2", code)
	}
	stdout.Reset()
	if code := Run(&stdout, &stderr, []string{"version"}); code != 0 || stdout.Len() == 0 {
		t.Errorf("version: code %d, ausgabe %q", code, stdout.String())
	}
}

func TestGrantList(t *testing.T) {
	api := &fakeAdminAPI{t: t, grants: []Grant{{
		ID: "id-1", Group: "deployers",
		TagSelector: map[string]string{"env": "prod", "role": "web"},
		Principals:  []string{"deploy"}, Sudo: true, MaxValiditySeconds: 3600,
	}}}
	code, stdout, stderr := runCLI(t, api, "grant", "list")
	if code != 0 {
		t.Fatalf("code %d: %s", code, stderr)
	}
	for _, want := range []string{"deployers", "env=prod,role=web", "deploy", "1h0m0s"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("ausgabe ohne %q:\n%s", want, stdout)
		}
	}
}

func TestGrantCreate(t *testing.T) {
	api := &fakeAdminAPI{t: t}
	code, stdout, stderr := runCLI(t, api,
		"grant", "create", "--group", "deployers", "--principals", "deploy,root",
		"--tags", "env=prod", "--sudo", "--max-validity", "8h")
	if code != 0 {
		t.Fatalf("code %d: %s", code, stderr)
	}
	if api.method != http.MethodPost || api.lastPath != "/v1/admin/grants" {
		t.Errorf("request: %s %s", api.method, api.lastPath)
	}
	if api.lastBody["group"] != "deployers" || api.lastBody["sudo"] != true ||
		api.lastBody["max_validity_seconds"] != float64(8*3600) {
		t.Errorf("body = %v", api.lastBody)
	}
	if !strings.Contains(stdout, "neu-1") {
		t.Errorf("ausgabe ohne id: %s", stdout)
	}
}

func TestGrantCreatePflichtfelder(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run(&stdout, &stderr, []string{"grant", "create", "--group", "x"}); code != 2 {
		t.Errorf("ohne principals: code %d, erwartet 2", code)
	}
	if code := Run(&stdout, &stderr, []string{"grant", "create", "--principals", "deploy"}); code != 2 {
		t.Errorf("ohne group: code %d, erwartet 2", code)
	}
}

func TestGrantUpdate(t *testing.T) {
	api := &fakeAdminAPI{t: t, grants: []Grant{{
		ID: "id-1", Group: "deployers", TagSelector: map[string]string{"env": "prod"},
		Principals: []string{"deploy"}, MaxValiditySeconds: 3600,
	}}}
	code, _, stderr := runCLI(t, api, "grant", "update", "id-1", "--principals", "deploy,root")
	if code != 0 {
		t.Fatalf("code %d: %s", code, stderr)
	}
	if api.method != http.MethodPut || api.lastPath != "/v1/admin/grants/id-1" {
		t.Errorf("request: %s %s", api.method, api.lastPath)
	}
	// Nicht angegebene Felder bleiben erhalten, principals sind neu.
	principals, _ := api.lastBody["principals"].([]any)
	if len(principals) != 2 || api.lastBody["max_validity_seconds"] != float64(3600) {
		t.Errorf("body = %v", api.lastBody)
	}
	tags, _ := api.lastBody["tag_selector"].(map[string]any)
	if tags["env"] != "prod" {
		t.Errorf("tag_selector = %v", tags)
	}

	var stdout, errOut bytes.Buffer
	if code := Run(&stdout, &errOut, []string{"grant", "update"}); code != 2 {
		t.Errorf("update ohne id: code %d, erwartet 2", code)
	}
}

func TestGrantDelete(t *testing.T) {
	api := &fakeAdminAPI{t: t}
	code, stdout, stderr := runCLI(t, api, "grant", "delete", "id-1")
	if code != 0 {
		t.Fatalf("code %d: %s", code, stderr)
	}
	if api.method != http.MethodDelete || api.lastPath != "/v1/admin/grants/id-1" {
		t.Errorf("request: %s %s", api.method, api.lastPath)
	}
	if !strings.Contains(stdout, "id-1") {
		t.Errorf("ausgabe: %s", stdout)
	}
}

func TestApply(t *testing.T) {
	yaml := `grants:
  - group: deployers
    tags:
      env: prod
    principals: [deploy]
    max_validity: 8h
  - group: admins
    principals: [root]
    sudo: true
    max_validity: 1h
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
	if api.lastPath != "/v1/admin/grants/apply" {
		t.Errorf("pfad: %s", api.lastPath)
	}
	grants, _ := api.lastBody["grants"].([]any)
	if len(grants) != 2 {
		t.Fatalf("apply-body: %v", api.lastBody)
	}
	first, _ := grants[0].(map[string]any)
	if first["group"] != "deployers" || first["max_validity_seconds"] != float64(8*3600) {
		t.Errorf("erster grant: %v", first)
	}
	if !strings.Contains(stdout, "2 angelegt") || !strings.Contains(stdout, "1 gelöscht") {
		t.Errorf("zusammenfassung: %s", stdout)
	}

	var stdout2, stderr2 bytes.Buffer
	if code := Run(&stdout2, &stderr2, []string{"apply"}); code != 2 {
		t.Errorf("apply ohne datei: code %d, erwartet 2", code)
	}
}

func TestLoadGrantsFileFehler(t *testing.T) {
	if _, _, _, err := loadGrantsFile(filepath.Join(t.TempDir(), "fehlt.yaml")); err == nil {
		t.Error("fehlende datei: fehler erwartet")
	}
	path := filepath.Join(t.TempDir(), "kaputt.yaml")
	if err := os.WriteFile(path, []byte("grants: [max_validity: quatsch"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := loadGrantsFile(path); err == nil {
		t.Error("kaputtes yaml: fehler erwartet")
	}
}

func TestTokenAusUmgebung(t *testing.T) {
	api := &fakeAdminAPI{t: t}
	srv := httptest.NewServer(api.handler())
	t.Cleanup(srv.Close)
	config := writeConfig(t, srv.URL)
	t.Setenv(envIDToken, testToken)

	var stdout, stderr bytes.Buffer
	if code := Run(&stdout, &stderr, []string{"grant", "list", "--config", config}); code != 0 {
		t.Fatalf("code %d: %s", code, stderr.String())
	}
}

func TestParseHelpers(t *testing.T) {
	tags, err := parseTags("env=prod,role=web")
	if err != nil || tags["env"] != "prod" || tags["role"] != "web" {
		t.Errorf("parseTags: %v, %v", tags, err)
	}
	if _, err := parseTags("kaputt"); err == nil {
		t.Error("parseTags ohne '=': fehler erwartet")
	}
	if got := formatTags(nil); got != "*" {
		t.Errorf("formatTags(nil) = %q", got)
	}
	if got := splitList(" a, ,b "); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("splitList = %v", got)
	}
}

func TestAPIFehlerWirdGemeldet(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "keine admin-berechtigung", http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	config := writeConfig(t, srv.URL)

	var stdout, stderr bytes.Buffer
	code := Run(&stdout, &stderr, []string{"grant", "list", "--config", config, "--token", testToken})
	if code != 1 {
		t.Fatalf("code %d, erwartet 1", code)
	}
	if !strings.Contains(stderr.String(), "keine admin-berechtigung") {
		t.Errorf("stderr: %s", stderr.String())
	}
}
