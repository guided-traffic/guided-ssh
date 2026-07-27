package rulespec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeRules writes content into a temporary file and returns its path.
func writeRules(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadHostRules(t *testing.T) {
	path := writeRules(t, `grants:
  - group: deployers
    issuer: https://idp.example/realms/x
    tags:
      env: prod
    principals: [deploy]
    max_validity: 8h
  - group: admins
    principals: [root]
    sudo: true
    max_validity: 1h
`)
	specs, err := LoadHostRules(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) != 2 {
		t.Fatalf("specs: %v", specs)
	}
	first := specs[0]
	if first.Group != "deployers" || first.Issuer != "https://idp.example/realms/x" ||
		first.TagSelector["env"] != "prod" || first.Principals[0] != "deploy" ||
		first.Sudo || first.MaxValiditySeconds != 8*3600 {
		t.Errorf("first grant: %+v", first)
	}
	if !specs[1].Sudo || specs[1].MaxValiditySeconds != 3600 {
		t.Errorf("second grant: %+v", specs[1])
	}
}

// TestLoadHostRulesEmptyList: `grants: []` is the explicit "delete all host
// rules" state and must load as an empty (non-nil) spec list.
func TestLoadHostRulesEmptyList(t *testing.T) {
	specs, err := LoadHostRules(writeRules(t, "grants: []\n"))
	if err != nil {
		t.Fatal(err)
	}
	if specs == nil || len(specs) != 0 {
		t.Errorf("specs = %v, expected empty list", specs)
	}
}

func TestLoadHostRulesErrors(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantMsg string
	}{
		{"missing key", "# only a comment\n", "missing top-level grants key"},
		{"empty file", "", "missing top-level grants key"},
		{"wrong domain key", "ci_grants: []\n", "unexpected ci_grants key"},
		{"unknown key", "grants: []\ngrant:\n  - group: x\n", "field grant not found"},
		{"unknown entry key", "grants:\n  - group: x\n    sudoo: true\n", "field sudoo not found"},
		{"bad duration", "grants:\n  - group: x\n    max_validity: bogus\n", "invalid duration"},
		{"broken yaml", "grants: [max_validity: bogus", "rules file"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadHostRules(writeRules(t, tc.content))
			if err == nil {
				t.Fatal("error expected")
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("error = %q, expected to contain %q", err, tc.wantMsg)
			}
		})
	}
}

func TestLoadHostRulesMissingFile(t *testing.T) {
	if _, err := LoadHostRules(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Error("missing file: error expected")
	}
}

func TestLoadCIRules(t *testing.T) {
	path := writeRules(t, `ci_grants:
  - project: infra/ansible
    ref: main
    protected_only: false
    environment: prod
    tags:
      env: prod
    principals: [deploy]
    max_validity: 1h
  - project: infra/terraform
    principals: [deploy]
    max_validity: 30m
`)
	specs, err := LoadCIRules(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) != 2 {
		t.Fatalf("specs: %v", specs)
	}
	first := specs[0]
	if first.ProjectPath != "infra/ansible" || first.RefPattern != "main" ||
		first.ProtectedOnly || first.EnvironmentPattern != "prod" ||
		first.TagSelector["env"] != "prod" || first.MaxValiditySeconds != 3600 {
		t.Errorf("first ci grant: %+v", first)
	}
	// Omitted protected_only defaults to true, like the admin API.
	if !specs[1].ProtectedOnly || specs[1].MaxValiditySeconds != 1800 {
		t.Errorf("second ci grant: %+v", specs[1])
	}
}

func TestLoadCIRulesEmptyList(t *testing.T) {
	specs, err := LoadCIRules(writeRules(t, "ci_grants: []\n"))
	if err != nil {
		t.Fatal(err)
	}
	if specs == nil || len(specs) != 0 {
		t.Errorf("specs = %v, expected empty list", specs)
	}
}

func TestLoadCIRulesErrors(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantMsg string
	}{
		{"missing key", "# only a comment\n", "missing top-level ci_grants key"},
		{"wrong domain key", "grants: []\n", "unexpected grants key"},
		{"unknown entry key", "ci_grants:\n  - project: x\n    refs: main\n", "field refs not found"},
		{"bad duration", "ci_grants:\n  - project: x\n    max_validity: 8\n", "invalid duration"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadCIRules(writeRules(t, tc.content))
			if err == nil {
				t.Fatal("error expected")
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("error = %q, expected to contain %q", err, tc.wantMsg)
			}
		})
	}
}

// TestLoadCombinedCIMissing: the combined file of `gssh-admin apply` leaves
// the CI rules untouched when the ci_grants section is absent.
func TestLoadCombinedCIMissing(t *testing.T) {
	grants, ciGrants, ciPresent, err := LoadCombined(writeRules(t,
		"grants:\n  - group: deployers\n    principals: [deploy]\n    max_validity: 8h\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 1 || grants[0].Group != "deployers" {
		t.Errorf("grants: %+v", grants)
	}
	if ciPresent || ciGrants != nil {
		t.Errorf("ciPresent = %t, ciGrants = %v, expected untouched", ciPresent, ciGrants)
	}
}

// TestLoadCombinedCIEmpty: an explicitly empty ci_grants section deletes all
// CI rules — present, but with no entries.
func TestLoadCombinedCIEmpty(t *testing.T) {
	_, ciGrants, ciPresent, err := LoadCombined(writeRules(t, "grants: []\nci_grants: []\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !ciPresent || len(ciGrants) != 0 {
		t.Errorf("ciPresent = %t, ciGrants = %v", ciPresent, ciGrants)
	}
}

func TestLoadCombinedBothDomains(t *testing.T) {
	grants, ciGrants, ciPresent, err := LoadCombined(writeRules(t, `grants:
  - group: deployers
    principals: [deploy]
    max_validity: 8h
ci_grants:
  - project: infra/ansible
    principals: [deploy]
    max_validity: 1h
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 1 || !ciPresent || len(ciGrants) != 1 {
		t.Fatalf("grants: %+v, ciPresent: %t, ciGrants: %+v", grants, ciPresent, ciGrants)
	}
	if ciGrants[0].ProjectPath != "infra/ansible" || !ciGrants[0].ProtectedOnly {
		t.Errorf("ci grant: %+v", ciGrants[0])
	}
}

// TestLoadCombinedMissingGrants: the authoritative grants section must be
// present — a file without it must not be read as "delete everything".
func TestLoadCombinedMissingGrants(t *testing.T) {
	_, _, _, err := LoadCombined(writeRules(t,
		"ci_grants:\n  - project: x\n    principals: [deploy]\n    max_validity: 1h\n"))
	if err == nil || !strings.Contains(err.Error(), "missing top-level grants key") {
		t.Errorf("error = %v, expected missing grants key", err)
	}
}
