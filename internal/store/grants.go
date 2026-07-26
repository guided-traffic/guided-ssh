package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Audit events for grant changes (phase 6): every mutation is attributable
// to an actor and is written transactionally along with the change.
const (
	EventGrantCreated = "grant.created"
	EventGrantUpdated = "grant.updated"
	EventGrantDeleted = "grant.deleted"
)

// grantAuditEvent builds the audit event for a grant change.
func grantAuditEvent(eventType, actor string, g *AccessGrant) (*AuditEvent, error) {
	payload, err := json.Marshal(map[string]any{
		"grant_id":             g.ID,
		"group_id":             g.GroupID,
		"tag_selector":         g.TagSelector,
		"principals":           g.Principals,
		"sudo":                 g.Sudo,
		"max_validity_seconds": g.MaxValiditySeconds,
	})
	if err != nil {
		return nil, err
	}
	return &AuditEvent{EventType: eventType, Actor: actor, Payload: payload}, nil
}

// createGrantTx creates an access rule within the transaction and writes
// the audit event.
func createGrantTx(ctx context.Context, tx pgx.Tx, actor string, g *AccessGrant) error {
	if g.TagSelector == nil {
		g.TagSelector = map[string]string{}
	}
	created, err := queryOne[AccessGrant](ctx, tx, `
		INSERT INTO access_grants (group_id, tag_selector, principals, sudo, max_validity_seconds)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING *`,
		g.GroupID, g.TagSelector, g.Principals, g.Sudo, g.MaxValiditySeconds)
	if err != nil {
		return err
	}
	*g = *created
	event, err := grantAuditEvent(EventGrantCreated, actor, g)
	if err != nil {
		return err
	}
	return insertAuditEvent(ctx, tx, event)
}

// CreateGrant creates an access rule (fills in the ID and timestamp) and
// writes an audit event with the actor transactionally.
func (s *Store) CreateGrant(ctx context.Context, actor string, g *AccessGrant) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		return createGrantTx(ctx, tx, actor, g)
	})
}

// GetGrant returns an access rule by ID.
func (s *Store) GetGrant(ctx context.Context, id uuid.UUID) (*AccessGrant, error) {
	return queryOne[AccessGrant](ctx, s.pool, `SELECT * FROM access_grants WHERE id = $1`, id)
}

// GrantWithGroup is an access rule including group name and issuer
// (for the API/CLI, where groups are addressed by name rather than UUID).
type GrantWithGroup struct {
	AccessGrant
	GroupName   string `db:"group_name"`
	GroupIssuer string `db:"group_issuer"`
}

// GetGrantDetailed returns an access rule including group info.
func (s *Store) GetGrantDetailed(ctx context.Context, id uuid.UUID) (*GrantWithGroup, error) {
	return queryOne[GrantWithGroup](ctx, s.pool, `
		SELECT g.*, gr.name AS group_name, gr.issuer AS group_issuer
		FROM access_grants g
		JOIN groups gr ON gr.id = g.group_id
		WHERE g.id = $1`, id)
}

// ListGrantsDetailed returns all access rules including group info.
func (s *Store) ListGrantsDetailed(ctx context.Context) ([]GrantWithGroup, error) {
	return queryAll[GrantWithGroup](ctx, s.pool, `
		SELECT g.*, gr.name AS group_name, gr.issuer AS group_issuer
		FROM access_grants g
		JOIN groups gr ON gr.id = g.group_id
		ORDER BY gr.name, g.created_at, g.id`)
}

// ListGrants returns all access rules.
func (s *Store) ListGrants(ctx context.Context) ([]AccessGrant, error) {
	return queryAll[AccessGrant](ctx, s.pool, `SELECT * FROM access_grants ORDER BY created_at, id`)
}

// ListGrantsForGroups returns all access rules of the given groups.
func (s *Store) ListGrantsForGroups(ctx context.Context, groupIDs []uuid.UUID) ([]AccessGrant, error) {
	return queryAll[AccessGrant](ctx, s.pool, `
		SELECT * FROM access_grants
		WHERE group_id = ANY ($1::uuid[])
		ORDER BY created_at, id`, groupIDs)
}

// ListGrantsForUser returns all access rules that apply to this user via a
// group membership (evaluated during certificate issuance).
func (s *Store) ListGrantsForUser(ctx context.Context, userID uuid.UUID) ([]AccessGrant, error) {
	return queryAll[AccessGrant](ctx, s.pool, `
		SELECT g.* FROM access_grants g
		JOIN user_groups ug ON ug.group_id = g.group_id
		WHERE ug.user_id = $1
		ORDER BY g.created_at, g.id`, userID)
}

// UpdateGrant updates the mutable fields of an access rule and writes an
// audit event with the actor transactionally.
func (s *Store) UpdateGrant(ctx context.Context, actor string, g *AccessGrant) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		return updateGrantTx(ctx, tx, actor, g)
	})
}

// updateGrantTx updates an access rule within the transaction.
func updateGrantTx(ctx context.Context, tx pgx.Tx, actor string, g *AccessGrant) error {
	if g.TagSelector == nil {
		g.TagSelector = map[string]string{}
	}
	updated, err := queryOne[AccessGrant](ctx, tx, `
		UPDATE access_grants
		SET tag_selector = $2, principals = $3, sudo = $4, max_validity_seconds = $5, updated_at = now()
		WHERE id = $1
		RETURNING *`,
		g.ID, g.TagSelector, g.Principals, g.Sudo, g.MaxValiditySeconds)
	if err != nil {
		return err
	}
	*g = *updated
	event, err := grantAuditEvent(EventGrantUpdated, actor, g)
	if err != nil {
		return err
	}
	return insertAuditEvent(ctx, tx, event)
}

// DeleteGrant removes an access rule and writes an audit event with the
// actor transactionally.
func (s *Store) DeleteGrant(ctx context.Context, actor string, id uuid.UUID) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		return deleteGrantTx(ctx, tx, actor, id)
	})
}

// deleteGrantTx removes an access rule within the transaction.
func deleteGrantTx(ctx context.Context, tx pgx.Tx, actor string, id uuid.UUID) error {
	deleted, err := queryOne[AccessGrant](ctx, tx,
		`DELETE FROM access_grants WHERE id = $1 RETURNING *`, id)
	if err != nil {
		return err
	}
	event, err := grantAuditEvent(EventGrantDeleted, actor, deleted)
	if err != nil {
		return err
	}
	return insertAuditEvent(ctx, tx, event)
}

// ErrInvalidGrantSpec: a declarative access rule is incomplete or
// contradictory (client error, not a technical error).
var ErrInvalidGrantSpec = errors.New("invalid grant specification")

// GrantSpec is a declarative access rule (YAML import/apply): the group is
// referenced by name and created if needed.
type GrantSpec struct {
	// Group is the group name in the IdP.
	Group string
	// Issuer of the group; empty ⇒ the call's DefaultIssuer.
	Issuer string
	// TagSelector must be a subset of the host tags (empty = all hosts).
	TagSelector map[string]string
	// Principals are the local target users on the hosts.
	Principals []string
	// Sudo marks the grant for sudo authorization (enforced in phase 9).
	Sudo bool
	// MaxValiditySeconds is the maximum certificate validity.
	MaxValiditySeconds int64
}

// ApplyResult summarizes a declarative grant reconciliation.
type ApplyResult struct {
	Created   int `json:"created"`
	Updated   int `json:"updated"`
	Deleted   int `json:"deleted"`
	Unchanged int `json:"unchanged"`
}

// grantKey identifies a grant for the declarative reconciliation:
// issuer + group name + canonical tag selector (JSON sorts map keys).
func grantKey(issuer, group string, selector map[string]string) (string, error) {
	if selector == nil {
		selector = map[string]string{}
	}
	canonical, err := json.Marshal(selector)
	if err != nil {
		return "", err
	}
	return issuer + "\x00" + group + "\x00" + string(canonical), nil
}

// ApplyGrants reconciles the grant inventory with specs declaratively
// (GitOps): grants are identified by (issuer, group, tag selector) — new
// ones are created, differing ones updated, ones no longer declared are
// deleted. Unknown groups are created (the IdP sync links members once the
// group exists there). Everything runs in one transaction; every change
// produces an audit event with the actor.
func (s *Store) ApplyGrants(ctx context.Context, actor, defaultIssuer string, specs []GrantSpec) (*ApplyResult, error) {
	result := &ApplyResult{}
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		existing, err := queryAll[GrantWithGroup](ctx, tx, `
			SELECT g.*, gr.name AS group_name, gr.issuer AS group_issuer
			FROM access_grants g
			JOIN groups gr ON gr.id = g.group_id
			ORDER BY g.created_at, g.id`)
		if err != nil {
			return err
		}
		byKey, err := grantsByKey(existing)
		if err != nil {
			return err
		}

		seen := map[string]bool{}
		for i, spec := range specs {
			issuer := spec.Issuer
			if issuer == "" {
				issuer = defaultIssuer
			}
			if err := validateGrantSpec(i, issuer, spec); err != nil {
				return err
			}
			key, err := grantKey(issuer, spec.Group, spec.TagSelector)
			if err != nil {
				return err
			}
			if seen[key] {
				return fmt.Errorf("store: %w: grant %d (group %q): duplicate entry for group and tag selector",
					ErrInvalidGrantSpec, i+1, spec.Group)
			}
			seen[key] = true

			if err := applySpecTx(ctx, tx, actor, issuer, spec, byKey[key], result); err != nil {
				return err
			}
			delete(byKey, key)
		}

		for _, grants := range byKey {
			for _, grant := range grants {
				if err := deleteGrantTx(ctx, tx, actor, grant.ID); err != nil {
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

// grantsByKey groups the grant inventory by reconciliation key; multiple
// grants per key are duplicates — the oldest becomes the update candidate,
// the rest are deleted during reconciliation.
func grantsByKey(existing []GrantWithGroup) (map[string][]GrantWithGroup, error) {
	byKey := map[string][]GrantWithGroup{}
	for _, grant := range existing {
		key, err := grantKey(grant.GroupIssuer, grant.GroupName, grant.TagSelector)
		if err != nil {
			return nil, err
		}
		byKey[key] = append(byKey[key], grant)
	}
	return byKey, nil
}

// applySpecTx applies a single spec against the inventory: an existing
// grant is updated (duplicates deleted), a missing one is created along
// with its group.
func applySpecTx(ctx context.Context, tx pgx.Tx, actor, issuer string, spec GrantSpec, candidates []GrantWithGroup, result *ApplyResult) error {
	if len(candidates) == 0 {
		group, err := ensureGroupTx(ctx, tx, issuer, spec.Group)
		if err != nil {
			return err
		}
		grant := &AccessGrant{
			GroupID:            group.ID,
			TagSelector:        spec.TagSelector,
			Principals:         spec.Principals,
			Sudo:               spec.Sudo,
			MaxValiditySeconds: spec.MaxValiditySeconds,
		}
		if err := createGrantTx(ctx, tx, actor, grant); err != nil {
			return err
		}
		result.Created++
		return nil
	}

	current := candidates[0]
	for _, dup := range candidates[1:] {
		if err := deleteGrantTx(ctx, tx, actor, dup.ID); err != nil {
			return err
		}
		result.Deleted++
	}
	if slices.Equal(current.Principals, spec.Principals) &&
		current.Sudo == spec.Sudo &&
		current.MaxValiditySeconds == spec.MaxValiditySeconds {
		result.Unchanged++
		return nil
	}
	grant := current.AccessGrant
	grant.Principals = spec.Principals
	grant.Sudo = spec.Sudo
	grant.MaxValiditySeconds = spec.MaxValiditySeconds
	if err := updateGrantTx(ctx, tx, actor, &grant); err != nil {
		return err
	}
	result.Updated++
	return nil
}

// validateGrantSpec checks the required fields of a declarative access
// rule; violations wrap ErrInvalidGrantSpec (client error).
func validateGrantSpec(index int, issuer string, spec GrantSpec) error {
	fail := func(reason string) error {
		return fmt.Errorf("store: %w: grant %d (group %q): %s",
			ErrInvalidGrantSpec, index+1, spec.Group, reason)
	}
	if spec.Group == "" {
		return fail("group is missing")
	}
	if issuer == "" {
		return fail("issuer is missing (set neither on the grant nor as a default)")
	}
	if len(spec.Principals) == 0 {
		return fail("principals are missing")
	}
	if spec.MaxValiditySeconds <= 0 {
		return fail("max_validity must be greater than 0")
	}
	return nil
}

// ensureGroupTx resolves a group by issuer+name and creates it if needed.
func ensureGroupTx(ctx context.Context, tx pgx.Tx, issuer, name string) (*Group, error) {
	group, err := queryOne[Group](ctx, tx,
		`SELECT * FROM groups WHERE issuer = $1 AND name = $2`, issuer, name)
	if err == nil {
		return group, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	return queryOne[Group](ctx, tx,
		`INSERT INTO groups (issuer, name) VALUES ($1, $2) RETURNING *`, issuer, name)
}
