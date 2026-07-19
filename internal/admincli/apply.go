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
type grantsFile struct {
	Grants []grantEntry `yaml:"grants"`
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

// loadGrantsFile liest und mappt die deklarative Grant-Datei; die inhaltliche
// Validierung übernimmt der Server (Zeilenkontext kommt von dort als Index).
func loadGrantsFile(path string) ([]Grant, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("grants-datei lesen: %w", err)
	}
	var file grantsFile
	if err := yaml.Unmarshal(raw, &file); err != nil {
		return nil, fmt.Errorf("grants-datei %s: %w", path, err)
	}
	grants := make([]Grant, 0, len(file.Grants))
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
	return grants, nil
}
