package store

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// CreateHost legt einen Host an und füllt ID und Zeitstempel.
func (s *Store) CreateHost(ctx context.Context, h *Host) error {
	created, err := queryOne[Host](ctx, s, `
		INSERT INTO hosts (name, public_key, enrolled_at, last_seen_at)
		VALUES ($1, $2, $3, $4)
		RETURNING *`,
		h.Name, h.PublicKey, h.EnrolledAt, h.LastSeenAt)
	if err != nil {
		return err
	}
	*h = *created
	return nil
}

// GetHost liefert einen Host per ID.
func (s *Store) GetHost(ctx context.Context, id uuid.UUID) (*Host, error) {
	return queryOne[Host](ctx, s, `SELECT * FROM hosts WHERE id = $1`, id)
}

// GetHostByName liefert einen Host per Name.
func (s *Store) GetHostByName(ctx context.Context, name string) (*Host, error) {
	return queryOne[Host](ctx, s, `SELECT * FROM hosts WHERE name = $1`, name)
}

// ListHosts liefert alle Hosts.
func (s *Store) ListHosts(ctx context.Context) ([]Host, error) {
	return queryAll[Host](ctx, s, `SELECT * FROM hosts ORDER BY name`)
}

// UpdateHost aktualisiert die veränderlichen Felder eines Hosts.
func (s *Store) UpdateHost(ctx context.Context, h *Host) error {
	updated, err := queryOne[Host](ctx, s, `
		UPDATE hosts
		SET public_key = $2, enrolled_at = $3, last_seen_at = $4, updated_at = now()
		WHERE id = $1
		RETURNING *`,
		h.ID, h.PublicKey, h.EnrolledAt, h.LastSeenAt)
	if err != nil {
		return err
	}
	*h = *updated
	return nil
}

// DeleteHost entfernt einen Host (Tags kaskadieren).
func (s *Store) DeleteHost(ctx context.Context, id uuid.UUID) error {
	return s.execAffectingOne(ctx, `DELETE FROM hosts WHERE id = $1`, id)
}

// SetHostTags ersetzt die Tags eines Hosts atomar.
func (s *Store) SetHostTags(ctx context.Context, hostID uuid.UUID, tags map[string]string) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM host_tags WHERE host_id = $1`, hostID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO host_tags (host_id, key, value)
			SELECT $1, e.key, e.value FROM jsonb_each_text($2) AS e`, hostID, tags)
		return err
	})
}

// GetHostTags liefert die Tags eines Hosts.
func (s *Store) GetHostTags(ctx context.Context, hostID uuid.UUID) (map[string]string, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT key, value FROM host_tags WHERE host_id = $1`, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	tags := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		tags[k] = v
	}
	return tags, rows.Err()
}
