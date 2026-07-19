package store

import (
	"context"

	"github.com/google/uuid"
)

// CreateServiceAccount legt eine maschinelle Identität an und füllt ID und Zeitstempel.
func (s *Store) CreateServiceAccount(ctx context.Context, a *ServiceAccount) error {
	created, err := queryOne[ServiceAccount](ctx, s.pool, `
		INSERT INTO service_accounts (name, kind, issuer, claim_matcher, active)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING *`,
		a.Name, a.Kind, a.Issuer, a.ClaimMatcher, a.Active)
	if err != nil {
		return err
	}
	*a = *created
	return nil
}

// GetServiceAccount liefert eine maschinelle Identität per ID.
func (s *Store) GetServiceAccount(ctx context.Context, id uuid.UUID) (*ServiceAccount, error) {
	return queryOne[ServiceAccount](ctx, s.pool, `SELECT * FROM service_accounts WHERE id = $1`, id)
}

// GetServiceAccountByName liefert eine maschinelle Identität per Name.
func (s *Store) GetServiceAccountByName(ctx context.Context, name string) (*ServiceAccount, error) {
	return queryOne[ServiceAccount](ctx, s.pool, `SELECT * FROM service_accounts WHERE name = $1`, name)
}

// ListServiceAccounts liefert alle maschinellen Identitäten.
func (s *Store) ListServiceAccounts(ctx context.Context) ([]ServiceAccount, error) {
	return queryAll[ServiceAccount](ctx, s.pool, `SELECT * FROM service_accounts ORDER BY name`)
}

// UpdateServiceAccount aktualisiert die veränderlichen Felder einer maschinellen Identität.
func (s *Store) UpdateServiceAccount(ctx context.Context, a *ServiceAccount) error {
	updated, err := queryOne[ServiceAccount](ctx, s.pool, `
		UPDATE service_accounts
		SET kind = $2, issuer = $3, claim_matcher = $4, active = $5, updated_at = now()
		WHERE id = $1
		RETURNING *`,
		a.ID, a.Kind, a.Issuer, a.ClaimMatcher, a.Active)
	if err != nil {
		return err
	}
	*a = *updated
	return nil
}

// DeleteServiceAccount entfernt eine maschinelle Identität.
func (s *Store) DeleteServiceAccount(ctx context.Context, id uuid.UUID) error {
	return s.execAffectingOne(ctx, `DELETE FROM service_accounts WHERE id = $1`, id)
}
