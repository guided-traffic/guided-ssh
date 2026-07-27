// Package rulespec parses the declarative rule files (GitOps) that describe
// the target state of the access rules. It is shared by `gssh-admin apply`
// (combined file, both domains) and the server-side rules-file reconciler
// (one file per domain).
//
// Parsing is strict on purpose: the file is fully authoritative, so a typo
// must never be interpreted as "empty file → delete everything".
package rulespec

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/guided-traffic/guided-ssh/internal/cli"
	"github.com/guided-traffic/guided-ssh/internal/store"
)

// Environment variables of the rules provisioning (GITOPS_EXTERNAL_RULES D9).
// They live here because server, API gates and reconciler all name them in
// their error messages — one spelling for all three.
const (
	// EnvManualRules gates the interactive CRUD endpoints; only the exact
	// value "true" enables them.
	EnvManualRules = "GSSH_MANUAL_RULES"
	// EnvHostRulesFile / EnvCIRulesFile point at a declarative rules file
	// per domain; a file-owned domain rejects all API writes.
	EnvHostRulesFile = "GSSH_HOST_RULES_FILE"
	EnvCIRulesFile   = "GSSH_CI_RULES_FILE"
)

// GrantEntry is an access rule in the YAML file:
//
//	grants:
//	  - group: deployers
//	    # issuer: https://idp.example/realms/x   (default: token's issuer)
//	    tags:
//	      env: prod
//	    principals: [deploy]
//	    sudo: false
//	    max_validity: 8h
type GrantEntry struct {
	Group       string            `yaml:"group"`
	Issuer      string            `yaml:"issuer,omitempty"`
	Tags        map[string]string `yaml:"tags,omitempty"`
	Principals  []string          `yaml:"principals"`
	Sudo        bool              `yaml:"sudo,omitempty"`
	MaxValidity cli.Duration      `yaml:"max_validity"`
}

// Spec maps the entry onto the store's declarative apply input.
func (e GrantEntry) Spec() store.GrantSpec {
	return store.GrantSpec{
		Group:              e.Group,
		Issuer:             e.Issuer,
		TagSelector:        e.Tags,
		Principals:         e.Principals,
		Sudo:               e.Sudo,
		MaxValiditySeconds: int64(time.Duration(e.MaxValidity) / time.Second),
	}
}

// CIGrantEntry is a CI access rule in the YAML file:
//
//	ci_grants:
//	  - project: infra/ansible
//	    ref: main            # glob; empty = all refs
//	    protected_only: true # default true
//	    environment: prod    # glob; empty = no condition
//	    tags:
//	      env: prod
//	    principals: [deploy]
//	    max_validity: 1h
type CIGrantEntry struct {
	Project       string            `yaml:"project"`
	Ref           string            `yaml:"ref,omitempty"`
	ProtectedOnly *bool             `yaml:"protected_only,omitempty"`
	Environment   string            `yaml:"environment,omitempty"`
	Tags          map[string]string `yaml:"tags,omitempty"`
	Principals    []string          `yaml:"principals"`
	MaxValidity   cli.Duration      `yaml:"max_validity"`
}

// Spec maps the entry onto the store's declarative apply input; an omitted
// protected_only defaults to true, matching the admin API
// (internal/api/admin_ci.go).
func (e CIGrantEntry) Spec() store.CIGrantSpec {
	protectedOnly := true
	if e.ProtectedOnly != nil {
		protectedOnly = *e.ProtectedOnly
	}
	return store.CIGrantSpec{
		ProjectPath:        e.Project,
		RefPattern:         e.Ref,
		ProtectedOnly:      protectedOnly,
		EnvironmentPattern: e.Environment,
		TagSelector:        e.Tags,
		Principals:         e.Principals,
		MaxValiditySeconds: int64(time.Duration(e.MaxValidity) / time.Second),
	}
}

// rulesFile is the on-disk format. Both sections are pointers so that a
// missing key is distinguishable from an explicitly empty list — the latter
// deletes all rules of that domain.
type rulesFile struct {
	Grants   *[]GrantEntry   `yaml:"grants"`
	CIGrants *[]CIGrantEntry `yaml:"ci_grants"`
}

// decodeFile reads path and decodes it with KnownFields: unknown or
// misspelled keys are errors, not silently ignored. An empty file decodes
// into an empty rulesFile — the callers reject it via the required-key check.
func decodeFile(path string) (*rulesFile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rules file: %w", err)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)
	var file rulesFile
	if err := decoder.Decode(&file); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("rules file %s: %w", path, err)
	}
	return &file, nil
}

// errMissingGrants / errMissingCIGrants describe the required top-level key.
func errMissingGrants(path string) error {
	return fmt.Errorf("rules file %s: missing top-level grants key "+
		"(use `grants: []` to delete all host rules)", path)
}

func errMissingCIGrants(path string) error {
	return fmt.Errorf("rules file %s: missing top-level ci_grants key "+
		"(use `ci_grants: []` to delete all CI rules)", path)
}

// LoadHostRules reads a host-rules file: top-level `grants:` is required, a
// `ci_grants:` section is rejected — one domain per file.
func LoadHostRules(path string) ([]store.GrantSpec, error) {
	file, err := decodeFile(path)
	if err != nil {
		return nil, err
	}
	if file.CIGrants != nil {
		return nil, fmt.Errorf("host rules file %s: unexpected ci_grants key "+
			"(CI rules belong into the CI rules file)", path)
	}
	if file.Grants == nil {
		return nil, errMissingGrants(path)
	}
	return grantSpecs(*file.Grants), nil
}

// LoadCIRules reads a CI-rules file: top-level `ci_grants:` is required, a
// `grants:` section is rejected — one domain per file.
func LoadCIRules(path string) ([]store.CIGrantSpec, error) {
	file, err := decodeFile(path)
	if err != nil {
		return nil, err
	}
	if file.Grants != nil {
		return nil, fmt.Errorf("CI rules file %s: unexpected grants key "+
			"(host rules belong into the host rules file)", path)
	}
	if file.CIGrants == nil {
		return nil, errMissingCIGrants(path)
	}
	return ciGrantSpecs(*file.CIGrants), nil
}

// LoadCombined reads the combined file of `gssh-admin apply`: `grants:` is
// required, a missing `ci_grants:` section leaves the CI rules untouched
// (ciPresent=false), an empty one deletes all of them.
func LoadCombined(path string) (grants []store.GrantSpec, ciGrants []store.CIGrantSpec, ciPresent bool, err error) {
	file, err := decodeFile(path)
	if err != nil {
		return nil, nil, false, err
	}
	if file.Grants == nil {
		return nil, nil, false, errMissingGrants(path)
	}
	if file.CIGrants == nil {
		return grantSpecs(*file.Grants), nil, false, nil
	}
	return grantSpecs(*file.Grants), ciGrantSpecs(*file.CIGrants), true, nil
}

func grantSpecs(entries []GrantEntry) []store.GrantSpec {
	specs := make([]store.GrantSpec, 0, len(entries))
	for _, entry := range entries {
		specs = append(specs, entry.Spec())
	}
	return specs
}

func ciGrantSpecs(entries []CIGrantEntry) []store.CIGrantSpec {
	specs := make([]store.CIGrantSpec, 0, len(entries))
	for _, entry := range entries {
		specs = append(specs, entry.Spec())
	}
	return specs
}
