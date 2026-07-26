package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// CreateHost creates a host and fills in the ID and timestamp.
func (s *Store) CreateHost(ctx context.Context, h *Host) error {
	created, err := queryOne[Host](ctx, s.pool, `
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

// GetHost returns a host by ID.
func (s *Store) GetHost(ctx context.Context, id uuid.UUID) (*Host, error) {
	return queryOne[Host](ctx, s.pool, `SELECT * FROM hosts WHERE id = $1`, id)
}

// GetHostByName returns a host by name.
func (s *Store) GetHostByName(ctx context.Context, name string) (*Host, error) {
	return queryOne[Host](ctx, s.pool, `SELECT * FROM hosts WHERE name = $1`, name)
}

// ListHosts returns all hosts.
func (s *Store) ListHosts(ctx context.Context) ([]Host, error) {
	return queryAll[Host](ctx, s.pool, `SELECT * FROM hosts ORDER BY name`)
}

// UpdateHost updates the mutable fields of a host.
func (s *Store) UpdateHost(ctx context.Context, h *Host) error {
	updated, err := queryOne[Host](ctx, s.pool, `
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

// DeleteHost removes a host (tags cascade).
func (s *Store) DeleteHost(ctx context.Context, id uuid.UUID) error {
	return s.execAffectingOne(ctx, `DELETE FROM hosts WHERE id = $1`, id)
}

// SetHostTags atomically replaces the tags of a host.
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

// HostDetailed is a host including tags and the expiry of the most
// recently issued host certificate (for the web UI, phase 8).
type HostDetailed struct {
	Host
	Tags            map[string]string `db:"tags"`
	CertValidBefore *time.Time        `db:"cert_valid_before"`
}

// ListHostsDetailed returns all hosts including tags and the latest
// valid_before of their host certificates (NULL if none has been issued yet).
func (s *Store) ListHostsDetailed(ctx context.Context) ([]HostDetailed, error) {
	return queryAll[HostDetailed](ctx, s.pool, `
		SELECT h.*,
			COALESCE((SELECT jsonb_object_agg(t.key, t.value)
				FROM host_tags t WHERE t.host_id = h.id), '{}'::jsonb) AS tags,
			(SELECT max(c.valid_before)
				FROM certificates c
				WHERE c.host_id = h.id AND c.cert_type = 'host') AS cert_valid_before
		FROM hosts h
		ORDER BY h.name`)
}

// GetHostTags returns the tags of a host.
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
