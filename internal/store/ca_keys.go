package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// CreateCAKey creates a CA key and fills in the ID and timestamp.
// An empty state defaults to "active".
func (s *Store) CreateCAKey(ctx context.Context, k *CAKey) error {
	if k.State == "" {
		k.State = CAKeyStateActive
	}
	created, err := queryOne[CAKey](ctx, s.pool, `
		INSERT INTO ca_keys (purpose, algorithm, public_key, encrypted_private_key, state)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING *`,
		k.Purpose, k.Algorithm, k.PublicKey, k.EncryptedPrivateKey, k.State)
	if err != nil {
		return err
	}
	*k = *created
	return nil
}

// GetCAKey returns a CA key by ID.
func (s *Store) GetCAKey(ctx context.Context, id uuid.UUID) (*CAKey, error) {
	return queryOne[CAKey](ctx, s.pool, `SELECT * FROM ca_keys WHERE id = $1`, id)
}

// ListCAKeys returns all CA keys of a purpose, newest first.
func (s *Store) ListCAKeys(ctx context.Context, purpose string) ([]CAKey, error) {
	return queryAll[CAKey](ctx, s.pool, `
		SELECT * FROM ca_keys WHERE purpose = $1
		ORDER BY created_at DESC, id`, purpose)
}

// ListActiveCAKeys returns all non-retired CA keys of a purpose
// (active + retiring — both belong in the distributed CA bundle).
func (s *Store) ListActiveCAKeys(ctx context.Context, purpose string) ([]CAKey, error) {
	return queryAll[CAKey](ctx, s.pool, `
		SELECT * FROM ca_keys WHERE purpose = $1 AND state <> 'retired'
		ORDER BY created_at DESC, id`, purpose)
}

// UpdateCAKeyState sets the state of a CA key; when set to "retired",
// retired_at is stamped.
func (s *Store) UpdateCAKeyState(ctx context.Context, id uuid.UUID, state string) (*CAKey, error) {
	return queryOne[CAKey](ctx, s.pool, `
		UPDATE ca_keys
		SET state = $2,
		    retired_at = CASE WHEN $2 = 'retired' THEN now() ELSE retired_at END
		WHERE id = $1
		RETURNING *`, id, state)
}

// ErrCAKeyRetired is returned by AdoptCAKey when the mounted key matches a
// ca_keys row that was already retired. Adopting it would resurrect a key that
// an operator deliberately took out of service.
var ErrCAKeyRetired = errors.New("store: ca-key is retired")

// AdoptCAKey adopts an externally managed CA key (self-managed mode) and
// returns the ca_keys row for (purpose, publicKey), inserting it if absent.
// The second return value reports whether this call inserted the row, so the
// caller can audit the first adoption of a key exactly once.
//
// A newly inserted row has encrypted_private_key = NULL and state "active" and
// demotes every other "active" key of the same purpose to "retiring", so the
// previous public key stays in the CA bundle during a file-based rotation.
// An existing row is returned unchanged: a key in state "retiring" is *not*
// promoted back to "active", so re-mounting a superseded key does not silently
// reverse a rotation; a "retired" row yields ErrCAKeyRetired.
//
// Everything runs in one transaction; concurrent adopts of the same key by
// multiple replicas are serialized by the unique index on
// (purpose, public_key).
func (s *Store) AdoptCAKey(ctx context.Context, purpose, algorithm, publicKey string) (*CAKey, bool, error) {
	var (
		key     *CAKey
		created bool
	)
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		inserted, err := queryOne[CAKey](ctx, tx, `
			INSERT INTO ca_keys (purpose, algorithm, public_key, encrypted_private_key, state)
			VALUES ($1, $2, $3, NULL, $4)
			ON CONFLICT (purpose, public_key) DO NOTHING
			RETURNING *`, purpose, algorithm, publicKey, CAKeyStateActive)
		switch {
		case err == nil:
			key, created = inserted, true
		case errors.Is(err, ErrNotFound):
			// The row already exists (possibly just created by a concurrent
			// replica): re-select it and keep its state as it is.
			key, err = queryOne[CAKey](ctx, tx, `
				SELECT * FROM ca_keys WHERE purpose = $1 AND public_key = $2`, purpose, publicKey)
			if err != nil {
				return fmt.Errorf("re-select adopted ca-key: %w", err)
			}
			if key.State == CAKeyStateRetired {
				return fmt.Errorf("%w: purpose %q; provide the current key or un-retire this one", ErrCAKeyRetired, purpose)
			}
			return nil
		default:
			return fmt.Errorf("insert adopted ca-key: %w", err)
		}

		if _, err := tx.Exec(ctx, `
			UPDATE ca_keys SET state = $1
			WHERE purpose = $2 AND state = $3 AND id <> $4`,
			CAKeyStateRetiring, purpose, CAKeyStateActive, key.ID); err != nil {
			return fmt.Errorf("demote previous active ca-key: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	return key, created, nil
}
