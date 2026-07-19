package admincli

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/guided-traffic/guided-ssh/internal/cli"
)

// grantsFile ist das Format der deklarativen Grant-Datei (GitOps):
//
//	grants:
//	  - group: deployers
//	    # issuer: https://idp.example/realms/x   (default: issuer des tokens)
//	    tags:
//	      env: prod
//	    principals: [deploy]
//	    sudo: false
//	    max_validity: 8h
//	ci_grants:
//	  - project: infra/ansible
//	    ref: main            # glob; leer = alle refs
//	    protected_only: true # default true
//	    environment: prod    # glob; leer = keine bedingung
//	    tags:
//	      env: prod
//	    principals: [deploy]
//	    max_validity: 1h
//
// Fehlt der Abschnitt ci_grants komplett, bleiben CI-Grants unangetastet;
// ein leerer Abschnitt (ci_grants: []) löscht alle.
type grantsFile struct {
	Grants   []grantEntry    `yaml:"grants"`
	CIGrants *[]ciGrantEntry `yaml:"ci_grants"`
}

// grantEntry ist eine Zugriffsregel in der YAML-Datei.
type grantEntry struct {
	Group       string            `yaml:"group"`
	Issuer      string            `yaml:"issuer,omitempty"`
	Tags        map[string]string `yaml:"tags,omitempty"`
	Principals  []string          `yaml:"principals"`
	Sudo        bool              `yaml:"sudo,omitempty"`
	MaxValidity cli.Duration      `yaml:"max_validity"`
}

// ciGrantEntry ist eine CI-Zugriffsregel in der YAML-Datei (Phase 7).
type ciGrantEntry struct {
	Project       string            `yaml:"project"`
	Ref           string            `yaml:"ref,omitempty"`
	ProtectedOnly *bool             `yaml:"protected_only,omitempty"`
	Environment   string            `yaml:"environment,omitempty"`
	Tags          map[string]string `yaml:"tags,omitempty"`
	Principals    []string          `yaml:"principals"`
	MaxValidity   cli.Duration      `yaml:"max_validity"`
}

// loadGrantsFile liest und mappt die deklarative Grant-Datei; die inhaltliche
// Validierung übernimmt der Server (Zeilenkontext kommt von dort als Index).
// ciGrants ist nil, wenn der Abschnitt ci_grants in der Datei fehlt.
func loadGrantsFile(path string) (grants []Grant, ciGrants []CIGrant, ciPresent bool, err error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, false, fmt.Errorf("grants-datei lesen: %w", err)
	}
	var file grantsFile
	if err := yaml.Unmarshal(raw, &file); err != nil {
		return nil, nil, false, fmt.Errorf("grants-datei %s: %w", path, err)
	}
	grants = make([]Grant, 0, len(file.Grants))
	for _, entry := range file.Grants {
		grants = append(grants, Grant{
			Group:              entry.Group,
			Issuer:             entry.Issuer,
			TagSelector:        entry.Tags,
			Principals:         entry.Principals,
			Sudo:               entry.Sudo,
			MaxValiditySeconds: int64(time.Duration(entry.MaxValidity) / time.Second),
		})
	}
	if file.CIGrants == nil {
		return grants, nil, false, nil
	}
	ciGrants = make([]CIGrant, 0, len(*file.CIGrants))
	for _, entry := range *file.CIGrants {
		ciGrants = append(ciGrants, CIGrant{
			Project:            entry.Project,
			RefPattern:         entry.Ref,
			ProtectedOnly:      entry.ProtectedOnly,
			EnvironmentPattern: entry.Environment,
			TagSelector:        entry.Tags,
			Principals:         entry.Principals,
			MaxValiditySeconds: int64(time.Duration(entry.MaxValidity) / time.Second),
		})
	}
	return grants, ciGrants, true, nil
}
