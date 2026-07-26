package store

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// EventServiceAccountUpdated is the audit event of a service account change
// via the admin API (phase 8): the kill switch is traceable.
const EventServiceAccountUpdated = "service_account.updated"

// CreateServiceAccount creates a machine identity and fills in the ID and timestamp.
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

// KindGitLabCI marks service accounts that are created per GitLab project on
// the first CI issuance (phase 7).
const KindGitLabCI = "gitlab-ci"

// EnsureCIServiceAccount ensures the service account of a GitLab project
// exists (name = project_path) and returns it. An existing account keeps
// its active status — active = false thus acts as a per-project kill
// switch.
func (s *Store) EnsureCIServiceAccount(ctx context.Context, issuer, projectPath string) (*ServiceAccount, error) {
	return queryOne[ServiceAccount](ctx, s.pool, `
		INSERT INTO service_accounts (name, kind, issuer, claim_matcher, active)
		VALUES ($1, $2, $3, $4, true)
		ON CONFLICT (name) DO UPDATE SET updated_at = now()
		RETURNING *`,
		projectPath, KindGitLabCI, issuer, map[string]string{"project_path": projectPath})
}

// GetServiceAccount returns a machine identity by ID.
func (s *Store) GetServiceAccount(ctx context.Context, id uuid.UUID) (*ServiceAccount, error) {
	return queryOne[ServiceAccount](ctx, s.pool, `SELECT * FROM service_accounts WHERE id = $1`, id)
}

// GetServiceAccountByName returns a machine identity by name.
func (s *Store) GetServiceAccountByName(ctx context.Context, name string) (*ServiceAccount, error) {
	return queryOne[ServiceAccount](ctx, s.pool, `SELECT * FROM service_accounts WHERE name = $1`, name)
}

// ListServiceAccounts returns all machine identities.
func (s *Store) ListServiceAccounts(ctx context.Context) ([]ServiceAccount, error) {
	return queryAll[ServiceAccount](ctx, s.pool, `SELECT * FROM service_accounts ORDER BY name`)
}

// UpdateServiceAccount updates the mutable fields of a machine identity.
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

// SetServiceAccountActive sets the active status (per-project kill switch)
// and writes an audit event with the actor transactionally.
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

// DeleteServiceAccount removes a machine identity.
func (s *Store) DeleteServiceAccount(ctx context.Context, id uuid.UUID) error {
	return s.execAffectingOne(ctx, `DELETE FROM service_accounts WHERE id = $1`, id)
}
