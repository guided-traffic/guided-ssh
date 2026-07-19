package store

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// EventServiceAccountUpdated ist das Audit-Event einer Service-Account-Änderung
// über die Admin-API (Phase 8): der Not-Aus-Schalter ist nachvollziehbar.
const EventServiceAccountUpdated = "service_account.updated"

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

// KindGitLabCI kennzeichnet Service-Accounts, die pro GitLab-Projekt bei der
// ersten CI-Ausstellung angelegt werden (Phase 7).
const KindGitLabCI = "gitlab-ci"

// EnsureCIServiceAccount stellt den Service-Account eines GitLab-Projekts
// sicher (Name = project_path) und liefert ihn zurück. Ein bestehender
// Account behält seinen active-Status — active = false wirkt damit als
// Not-Aus pro Projekt.
func (s *Store) EnsureCIServiceAccount(ctx context.Context, issuer, projectPath string) (*ServiceAccount, error) {
	return queryOne[ServiceAccount](ctx, s.pool, `
		INSERT INTO service_accounts (name, kind, issuer, claim_matcher, active)
		VALUES ($1, $2, $3, $4, true)
		ON CONFLICT (name) DO UPDATE SET updated_at = now()
		RETURNING *`,
		projectPath, KindGitLabCI, issuer, map[string]string{"project_path": projectPath})
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

// SetServiceAccountActive setzt den active-Status (Not-Aus pro Projekt) und
// schreibt transaktional ein Audit-Event mit dem Actor.
func (s *Store) SetServiceAccountActive(ctx context.Context, actor string, id uuid.UUID, active bool) (*ServiceAccount, error) {
	var updated *ServiceAccount
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		u, err := queryOne[ServiceAccount](ctx, tx, `
			UPDATE service_accounts
			SET active = $2, updated_at = now()
			WHERE id = $1
			RETURNING *`, id, active)
		if err != nil {
			return err
		}
		updated = u
		payload, err := json.Marshal(map[string]any{
			"service_account_id": u.ID,
			"name":               u.Name,
			"kind":               u.Kind,
			"active":             u.Active,
		})
		if err != nil {
			return err
		}
		return insertAuditEvent(ctx, tx, &AuditEvent{
			EventType: EventServiceAccountUpdated, Actor: actor, Payload: payload,
		})
	})
	if err != nil {
		return nil, err
	}
	return updated, nil
}

// DeleteServiceAccount entfernt eine maschinelle Identität.
func (s *Store) DeleteServiceAccount(ctx context.Context, id uuid.UUID) error {
	return s.execAffectingOne(ctx, `DELETE FROM service_accounts WHERE id = $1`, id)
}
