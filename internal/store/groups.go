package store

import (
	"context"

	"github.com/google/uuid"
)

// CreateGroup legt eine Gruppe an und füllt ID und Zeitstempel.
func (s *Store) CreateGroup(ctx context.Context, g *Group) error {
	created, err := queryOne[Group](ctx, s, `
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

// GetGroup liefert eine Gruppe per ID.
func (s *Store) GetGroup(ctx context.Context, id uuid.UUID) (*Group, error) {
	return queryOne[Group](ctx, s, `SELECT * FROM groups WHERE id = $1`, id)
}

// GetGroupByName liefert eine Gruppe per IdP-Identität (issuer, name).
func (s *Store) GetGroupByName(ctx context.Context, issuer, name string) (*Group, error) {
	return queryOne[Group](ctx, s,
		`SELECT * FROM groups WHERE issuer = $1 AND name = $2`, issuer, name)
}

// ListGroups liefert alle Gruppen.
func (s *Store) ListGroups(ctx context.Context) ([]Group, error) {
	return queryAll[Group](ctx, s, `SELECT * FROM groups ORDER BY name, id`)
}

// DeleteGroup entfernt eine Gruppe (Mitgliedschaften und Grants kaskadieren).
func (s *Store) DeleteGroup(ctx context.Context, id uuid.UUID) error {
	return s.execAffectingOne(ctx, `DELETE FROM groups WHERE id = $1`, id)
}
