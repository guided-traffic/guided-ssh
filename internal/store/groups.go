package store

import (
	"context"

	"github.com/google/uuid"
)

// CreateGroup creates a group and fills in the ID and timestamp.
func (s *Store) CreateGroup(ctx context.Context, g *Group) error {
	created, err := queryOne[Group](ctx, s.pool, `
		INSERT INTO groups (issuer, name, external_id)
		VALUES ($1, $2, $3)
		RETURNING *`,
		g.Issuer, g.Name, g.ExternalID)
	if err != nil {
		return err
	}
	*g = *created
	return nil
}

// GetGroup returns a group by ID.
func (s *Store) GetGroup(ctx context.Context, id uuid.UUID) (*Group, error) {
	return queryOne[Group](ctx, s.pool, `SELECT * FROM groups WHERE id = $1`, id)
}

// GetGroupByName returns a group by IdP identity (issuer, name).
func (s *Store) GetGroupByName(ctx context.Context, issuer, name string) (*Group, error) {
	return queryOne[Group](ctx, s.pool,
		`SELECT * FROM groups WHERE issuer = $1 AND name = $2`, issuer, name)
}

// ListGroups returns all groups.
func (s *Store) ListGroups(ctx context.Context) ([]Group, error) {
	return queryAll[Group](ctx, s.pool, `SELECT * FROM groups ORDER BY name, id`)
}

// DeleteGroup removes a group (memberships and grants cascade).
func (s *Store) DeleteGroup(ctx context.Context, id uuid.UUID) error {
	return s.execAffectingOne(ctx, `DELETE FROM groups WHERE id = $1`, id)
}
