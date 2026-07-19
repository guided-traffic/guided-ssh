package store

import (
	"context"

	"github.com/google/uuid"
)

// CreateCAKey legt einen CA-Key an und füllt ID und Zeitstempel.
// Leerer State wird zu "active".
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

// GetCAKey liefert einen CA-Key per ID.
func (s *Store) GetCAKey(ctx context.Context, id uuid.UUID) (*CAKey, error) {
	return queryOne[CAKey](ctx, s.pool, `SELECT * FROM ca_keys WHERE id = $1`, id)
}

// ListCAKeys liefert alle CA-Keys eines Zwecks, neueste zuerst.
func (s *Store) ListCAKeys(ctx context.Context, purpose string) ([]CAKey, error) {
	return queryAll[CAKey](ctx, s.pool, `
		SELECT * FROM ca_keys WHERE purpose = $1
		ORDER BY created_at DESC, id`, purpose)
}

// ListActiveCAKeys liefert alle nicht ausgemusterten CA-Keys eines Zwecks
// (active + retiring — beide gehören ins verteilte CA-Bundle).
func (s *Store) ListActiveCAKeys(ctx context.Context, purpose string) ([]CAKey, error) {
	return queryAll[CAKey](ctx, s.pool, `
		SELECT * FROM ca_keys WHERE purpose = $1 AND state <> 'retired'
		ORDER BY created_at DESC, id`, purpose)
}

// UpdateCAKeyState setzt den Zustand eines CA-Keys; bei "retired" wird
// retired_at gestempelt.
func (s *Store) UpdateCAKeyState(ctx context.Context, id uuid.UUID, state string) (*CAKey, error) {
	return queryOne[CAKey](ctx, s.pool, `
		UPDATE ca_keys
		SET state = $2,
		    retired_at = CASE WHEN $2 = 'retired' THEN now() ELSE retired_at END
		WHERE id = $1
		RETURNING *`, id, state)
}
