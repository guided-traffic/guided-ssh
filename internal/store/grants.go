package store

import (
	"context"

	"github.com/google/uuid"
)

// CreateGrant legt eine Zugriffsregel an und füllt ID und Zeitstempel.
func (s *Store) CreateGrant(ctx context.Context, g *AccessGrant) error {
	created, err := queryOne[AccessGrant](ctx, s.pool, `
		INSERT INTO access_grants (group_id, tag_selector, principals, sudo, max_validity_seconds)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING *`,
		g.GroupID, g.TagSelector, g.Principals, g.Sudo, g.MaxValiditySeconds)
	if err != nil {
		return err
	}
	*g = *created
	return nil
}

// GetGrant liefert eine Zugriffsregel per ID.
func (s *Store) GetGrant(ctx context.Context, id uuid.UUID) (*AccessGrant, error) {
	return queryOne[AccessGrant](ctx, s.pool, `SELECT * FROM access_grants WHERE id = $1`, id)
}

// ListGrants liefert alle Zugriffsregeln.
func (s *Store) ListGrants(ctx context.Context) ([]AccessGrant, error) {
	return queryAll[AccessGrant](ctx, s.pool, `SELECT * FROM access_grants ORDER BY created_at, id`)
}

// ListGrantsForGroups liefert alle Zugriffsregeln der angegebenen Gruppen.
func (s *Store) ListGrantsForGroups(ctx context.Context, groupIDs []uuid.UUID) ([]AccessGrant, error) {
	return queryAll[AccessGrant](ctx, s.pool, `
		SELECT * FROM access_grants
		WHERE group_id = ANY ($1::uuid[])
		ORDER BY created_at, id`, groupIDs)
}

// UpdateGrant aktualisiert die veränderlichen Felder einer Zugriffsregel.
func (s *Store) UpdateGrant(ctx context.Context, g *AccessGrant) error {
	updated, err := queryOne[AccessGrant](ctx, s.pool, `
		UPDATE access_grants
		SET tag_selector = $2, principals = $3, sudo = $4, max_validity_seconds = $5, updated_at = now()
		WHERE id = $1
		RETURNING *`,
		g.ID, g.TagSelector, g.Principals, g.Sudo, g.MaxValiditySeconds)
	if err != nil {
		return err
	}
	*g = *updated
	return nil
}

// DeleteGrant entfernt eine Zugriffsregel.
func (s *Store) DeleteGrant(ctx context.Context, id uuid.UUID) error {
	return s.execAffectingOne(ctx, `DELETE FROM access_grants WHERE id = $1`, id)
}
