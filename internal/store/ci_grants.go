package store

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Audit events for CI grant changes (phase 7): like group grants, every
// mutation is attributable to an actor and is written transactionally.
const (
	EventCIGrantCreated = "ci_grant.created"
	EventCIGrantUpdated = "ci_grant.updated"
	EventCIGrantDeleted = "ci_grant.deleted"
)

// CIGrant is an access rule for GitLab CI pipelines (ADR-019):
// project/group × ref condition × tag selector → target principals.
type CIGrant struct {
	ID uuid.UUID `db:"id"`
	// ProjectPath is the GitLab project or namespace path; matches exactly
	// or as a namespace prefix ("infra" covers "infra/ansible").
	ProjectPath string `db:"project_path"`
	// RefPattern is a glob over the ref name ('*' matches anything,
	// including '/'); empty = all refs.
	RefPattern string `db:"ref_pattern"`
	// ProtectedOnly restricts the grant to protected refs (ref_protected).
	ProtectedOnly bool `db:"protected_only"`
	// EnvironmentPattern is a glob over the environment claim; empty =
	// no condition (also matches jobs without an environment).
	EnvironmentPattern string `db:"environment_pattern"`
	// TagSelector must be a subset of the host tags (empty = all hosts).
	TagSelector map[string]string `db:"tag_selector"`
	// Principals are the local target users on the hosts.
	Principals         []string  `db:"principals"`
	MaxValiditySeconds int64     `db:"max_validity_seconds"`
	CreatedAt          time.Time `db:"created_at"`
	UpdatedAt          time.Time `db:"updated_at"`
}

// MaxValidity is the maximum certificate validity as a Duration.
func (g *CIGrant) MaxValidity() time.Duration {
	return time.Duration(g.MaxValiditySeconds) * time.Second
}

// CIMatch holds the claims of a GitLab job token relevant to grant
// evaluation.
type CIMatch struct {
	ProjectPath  string
	Ref          string
	RefProtected bool
	Environment  string
}

// Matches checks whether the grant matches the job claims.
func (g *CIGrant) Matches(m CIMatch) bool {
	if !projectMatches(g.ProjectPath, m.ProjectPath) {
		return false
	}
	if g.ProtectedOnly && !m.RefProtected {
		return false
	}
	if g.RefPattern != "" && !wildcardMatch(g.RefPattern, m.Ref) {
		return false
	}
	if g.EnvironmentPattern != "" && !wildcardMatch(g.EnvironmentPattern, m.Environment) {
		return false
	}
	return true
}

// projectMatches: exact path or namespace prefix (bounded at '/').
func projectMatches(grantPath, projectPath string) bool {
	return grantPath == projectPath || strings.HasPrefix(projectPath, grantPath+"/")
}

// wildcardMatch matches value against a glob pattern in which '*' spans
// any characters (including '/'); other characters match literally.
func wildcardMatch(pattern, value string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == value
	}
	if !strings.HasPrefix(value, parts[0]) {
		return false
	}
	value = value[len(parts[0]):]
	for _, part := range parts[1 : len(parts)-1] {
		idx := strings.Index(value, part)
		if idx < 0 {
			return false
		}
		value = value[idx+len(part):]
	}
	return strings.HasSuffix(value, parts[len(parts)-1])
}

// ciGrantAuditEvent builds the audit event for a CI grant change.
func ciGrantAuditEvent(eventType, actor string, g *CIGrant) (*AuditEvent, error) {
	payload, err := json.Marshal(map[string]any{
		"ci_grant_id":          g.ID,
		"project_path":         g.ProjectPath,
		"ref_pattern":          g.RefPattern,
		"protected_only":       g.ProtectedOnly,
		"environment_pattern":  g.EnvironmentPattern,
		"tag_selector":         g.TagSelector,
		"principals":           g.Principals,
		"max_validity_seconds": g.MaxValiditySeconds,
	})
	if err != nil {
		return nil, err
	}
	return &AuditEvent{EventType: eventType, Actor: actor, Payload: payload}, nil
}

// createCIGrantTx creates a CI access rule within the transaction and
// writes the audit event.
func createCIGrantTx(ctx context.Context, tx pgx.Tx, actor string, g *CIGrant) error {
	if g.TagSelector == nil {
		g.TagSelector = map[string]string{}
	}
	created, err := queryOne[CIGrant](ctx, tx, `
		INSERT INTO ci_grants (project_path, ref_pattern, protected_only,
		                       environment_pattern, tag_selector, principals,
		                       max_validity_seconds)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING *`,
		g.ProjectPath, g.RefPattern, g.ProtectedOnly, g.EnvironmentPattern,
		g.TagSelector, g.Principals, g.MaxValiditySeconds)
	if err != nil {
		return err
	}
	*g = *created
	event, err := ciGrantAuditEvent(EventCIGrantCreated, actor, g)
	if err != nil {
		return err
	}
	return insertAuditEvent(ctx, tx, event)
}

// CreateCIGrant creates a CI access rule (fills in the ID and timestamp)
// and writes an audit event with the actor transactionally.
func (s *Store) CreateCIGrant(ctx context.Context, actor string, g *CIGrant) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		return createCIGrantTx(ctx, tx, actor, g)
	})
}

// GetCIGrant returns a CI access rule by ID.
func (s *Store) GetCIGrant(ctx context.Context, id uuid.UUID) (*CIGrant, error) {
	return queryOne[CIGrant](ctx, s.pool, `SELECT * FROM ci_grants WHERE id = $1`, id)
}

// ListCIGrants returns all CI access rules.
func (s *Store) ListCIGrants(ctx context.Context) ([]CIGrant, error) {
	return queryAll[CIGrant](ctx, s.pool, `
		SELECT * FROM ci_grants ORDER BY project_path, created_at, id`)
}

// MatchCIGrants returns all CI access rules that match the job claims
// (evaluated during certificate issuance). Candidates come from the
// database via a project/namespace match; the ref/environment conditions
// are checked in Go.
func (s *Store) MatchCIGrants(ctx context.Context, m CIMatch) ([]CIGrant, error) {
	candidates, err := queryAll[CIGrant](ctx, s.pool, `
		SELECT * FROM ci_grants
		WHERE project_path = $1 OR $1 LIKE project_path || '/%'
		ORDER BY created_at, id`, m.ProjectPath)
	if err != nil {
		return nil, err
	}
	matched := make([]CIGrant, 0, len(candidates))
	for _, g := range candidates {
		if g.Matches(m) {
			matched = append(matched, g)
		}
	}
	return matched, nil
}

// updateCIGrantTx updates a CI access rule within the transaction.
func updateCIGrantTx(ctx context.Context, tx pgx.Tx, actor string, g *CIGrant) error {
	if g.TagSelector == nil {
		g.TagSelector = map[string]string{}
	}
	updated, err := queryOne[CIGrant](ctx, tx, `
		UPDATE ci_grants
		SET ref_pattern = $2, protected_only = $3, environment_pattern = $4,
		    tag_selector = $5, principals = $6, max_validity_seconds = $7,
		    updated_at = now()
		WHERE id = $1
		RETURNING *`,
		g.ID, g.RefPattern, g.ProtectedOnly, g.EnvironmentPattern,
		g.TagSelector, g.Principals, g.MaxValiditySeconds)
	if err != nil {
		return err
	}
	*g = *updated
	event, err := ciGrantAuditEvent(EventCIGrantUpdated, actor, g)
	if err != nil {
		return err
	}
	return insertAuditEvent(ctx, tx, event)
}

// UpdateCIGrant updates the mutable fields of a CI access rule
// (project_path is identity and stays fixed) and writes an audit event
// with the actor transactionally.
func (s *Store) UpdateCIGrant(ctx context.Context, actor string, g *CIGrant) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		return updateCIGrantTx(ctx, tx, actor, g)
	})
}

// deleteCIGrantTx removes a CI access rule within the transaction.
func deleteCIGrantTx(ctx context.Context, tx pgx.Tx, actor string, id uuid.UUID) error {
	deleted, err := queryOne[CIGrant](ctx, tx,
		`DELETE FROM ci_grants WHERE id = $1 RETURNING *`, id)
	if err != nil {
		return err
	}
	event, err := ciGrantAuditEvent(EventCIGrantDeleted, actor, deleted)
	if err != nil {
		return err
	}
	return insertAuditEvent(ctx, tx, event)
}

// DeleteCIGrant removes a CI access rule and writes an audit event with
// the actor transactionally.
func (s *Store) DeleteCIGrant(ctx context.Context, actor string, id uuid.UUID) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		return deleteCIGrantTx(ctx, tx, actor, id)
	})
}

// CIGrantSpec is a declarative CI access rule (YAML import/apply).
type CIGrantSpec struct {
	ProjectPath        string
	RefPattern         string
	ProtectedOnly      bool
	EnvironmentPattern string
	TagSelector        map[string]string
	Principals         []string
	MaxValiditySeconds int64
}

// ciGrantKey identifies a CI grant for the declarative reconciliation via
// its full condition (project, ref/environment patterns, selector).
func ciGrantKey(projectPath, refPattern string, protectedOnly bool, envPattern string, selector map[string]string) (string, error) {
	if selector == nil {
		selector = map[string]string{}
	}
	canonical, err := json.Marshal(selector)
	if err != nil {
		return "", err
	}
	return strings.Join([]string{
		projectPath, refPattern, fmt.Sprintf("%t", protectedOnly), envPattern, string(canonical),
	}, "\x00"), nil
}

// validateCIGrantSpec checks the required fields of a declarative CI access
// rule; violations wrap ErrInvalidGrantSpec (client error).
func validateCIGrantSpec(index int, spec CIGrantSpec) error {
	fail := func(reason string) error {
		return fmt.Errorf("store: %w: ci-grant %d (project %q): %s",
			ErrInvalidGrantSpec, index+1, spec.ProjectPath, reason)
	}
	if spec.ProjectPath == "" {
		return fail("project is missing")
	}
	if len(spec.Principals) == 0 {
		return fail("principals are missing")
	}
	if spec.MaxValiditySeconds <= 0 {
		return fail("max_validity must be greater than 0")
	}
	return nil
}

// ApplyCIGrants reconciles the CI grant inventory with specs declaratively
// (GitOps): identity is the full condition (project, ref/environment
// patterns, tag selector) — new ones are created, differing ones updated,
// ones no longer declared are deleted. Everything runs in one transaction;
// every change produces an audit event with the actor.
func (s *Store) ApplyCIGrants(ctx context.Context, actor string, specs []CIGrantSpec) (*ApplyResult, error) {
	result := &ApplyResult{}
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		existing, err := queryAll[CIGrant](ctx, tx, `
			SELECT * FROM ci_grants ORDER BY created_at, id`)
		if err != nil {
			return err
		}
		byKey := map[string][]CIGrant{}
		for _, grant := range existing {
			key, err := ciGrantKey(grant.ProjectPath, grant.RefPattern,
				grant.ProtectedOnly, grant.EnvironmentPattern, grant.TagSelector)
			if err != nil {
				return err
			}
			byKey[key] = append(byKey[key], grant)
		}

		seen := map[string]bool{}
		for i, spec := range specs {
			if err := validateCIGrantSpec(i, spec); err != nil {
				return err
			}
			key, err := ciGrantKey(spec.ProjectPath, spec.RefPattern,
				spec.ProtectedOnly, spec.EnvironmentPattern, spec.TagSelector)
			if err != nil {
				return err
			}
			if seen[key] {
				return fmt.Errorf("store: %w: ci-grant %d (project %q): duplicate entry for the same condition",
					ErrInvalidGrantSpec, i+1, spec.ProjectPath)
			}
			seen[key] = true

			if err := applyCISpecTx(ctx, tx, actor, spec, byKey[key], result); err != nil {
				return err
			}
			delete(byKey, key)
		}

		for _, grants := range byKey {
			for _, grant := range grants {
				if err := deleteCIGrantTx(ctx, tx, actor, grant.ID); err != nil {
					return err
				}
				result.Deleted++
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// applyCISpecTx applies a single CI spec against the inventory: an existing
// grant is updated (duplicates deleted), a missing one is created.
func applyCISpecTx(ctx context.Context, tx pgx.Tx, actor string, spec CIGrantSpec, candidates []CIGrant, result *ApplyResult) error {
	if len(candidates) == 0 {
		grant := &CIGrant{
			ProjectPath:        spec.ProjectPath,
			RefPattern:         spec.RefPattern,
			ProtectedOnly:      spec.ProtectedOnly,
			EnvironmentPattern: spec.EnvironmentPattern,
			TagSelector:        spec.TagSelector,
			Principals:         spec.Principals,
			MaxValiditySeconds: spec.MaxValiditySeconds,
		}
		if err := createCIGrantTx(ctx, tx, actor, grant); err != nil {
			return err
		}
		result.Created++
		return nil
	}

	current := candidates[0]
	for _, dup := range candidates[1:] {
		if err := deleteCIGrantTx(ctx, tx, actor, dup.ID); err != nil {
			return err
		}
		result.Deleted++
	}
	if slices.Equal(current.Principals, spec.Principals) &&
		current.MaxValiditySeconds == spec.MaxValiditySeconds {
		result.Unchanged++
		return nil
	}
	current.Principals = spec.Principals
	current.MaxValiditySeconds = spec.MaxValiditySeconds
	if err := updateCIGrantTx(ctx, tx, actor, &current); err != nil {
		return err
	}
	result.Updated++
	return nil
}
