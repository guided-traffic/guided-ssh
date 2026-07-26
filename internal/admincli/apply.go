package admincli

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/guided-traffic/guided-ssh/internal/cli"
)

// grantsFile is the format of the declarative grants file (GitOps):
//
//	grants:
//	  - group: deployers
//	    # issuer: https://idp.example/realms/x   (default: token's issuer)
//	    tags:
//	      env: prod
//	    principals: [deploy]
//	    sudo: false
//	    max_validity: 8h
//	ci_grants:
//	  - project: infra/ansible
//	    ref: main            # glob; empty = all refs
//	    protected_only: true # default true
//	    environment: prod    # glob; empty = no condition
//	    tags:
//	      env: prod
//	    principals: [deploy]
//	    max_validity: 1h
//
// If the ci_grants section is missing entirely, CI grants are left
// untouched; an empty section (ci_grants: []) deletes all of them.
type grantsFile struct {
	Grants   []grantEntry    `yaml:"grants"`
	CIGrants *[]ciGrantEntry `yaml:"ci_grants"`
}

// grantEntry is an access rule in the YAML file.
type grantEntry struct {
	Group       string            `yaml:"group"`
	Issuer      string            `yaml:"issuer,omitempty"`
	Tags        map[string]string `yaml:"tags,omitempty"`
	Principals  []string          `yaml:"principals"`
	Sudo        bool              `yaml:"sudo,omitempty"`
	MaxValidity cli.Duration      `yaml:"max_validity"`
}

// ciGrantEntry is a CI access rule in the YAML file (phase 7).
type ciGrantEntry struct {
	Project       string            `yaml:"project"`
	Ref           string            `yaml:"ref,omitempty"`
	ProtectedOnly *bool             `yaml:"protected_only,omitempty"`
	Environment   string            `yaml:"environment,omitempty"`
	Tags          map[string]string `yaml:"tags,omitempty"`
	Principals    []string          `yaml:"principals"`
	MaxValidity   cli.Duration      `yaml:"max_validity"`
}

// loadGrantsFile reads and maps the declarative grants file; content
// validation is handled by the server (line context comes from there as an
// index). ciGrants is nil if the ci_grants section is missing from the file.
func loadGrantsFile(path string) (grants []Grant, ciGrants []CIGrant, ciPresent bool, err error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, false, fmt.Errorf("read grants file: %w", err)
	}
	var file grantsFile
	if err := yaml.Unmarshal(raw, &file); err != nil {
		return nil, nil, false, fmt.Errorf("grants file %s: %w", path, err)
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
