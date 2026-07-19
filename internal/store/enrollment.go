package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// EnrollmentToken ist ein einmaliges Token für das Host-Enrollment; in der
// Datenbank liegt nur der SHA-256-Hash.
type EnrollmentToken struct {
	ID        uuid.UUID         `db:"id"`
	TokenHash []byte            `db:"token_hash"`
	HostName  *string           `db:"host_name"`
	Tags      map[string]string `db:"tags"`
	ExpiresAt time.Time         `db:"expires_at"`
	UsedAt    *time.Time        `db:"used_at"`
	UsedBy    *uuid.UUID        `db:"used_by"`
	CreatedAt time.Time         `db:"created_at"`
}

// ErrTokenHostMismatch: das Token ist an einen anderen Hostnamen gebunden.
var ErrTokenHostMismatch = errors.New("store: enrollment-token ist an anderen hostnamen gebunden")

// EventHostEnrolled ist das Audit-Event eines erfolgreichen Enrollments.
const EventHostEnrolled = "host.enrolled"

// CreateEnrollmentToken legt ein Enrollment-Token an (Hash, nie Klartext).
func (s *Store) CreateEnrollmentToken(ctx context.Context, t *EnrollmentToken) error {
	if t.Tags == nil {
		t.Tags = map[string]string{}
	}
	created, err := queryOne[EnrollmentToken](ctx, s.pool, `
		INSERT INTO enrollment_tokens (token_hash, host_name, tags, expires_at)
		VALUES ($1, $2, $3, $4)
		RETURNING *`,
		t.TokenHash, t.HostName, t.Tags, t.ExpiresAt)
	if err != nil {
		return err
	}
	*t = *created
	return nil
}

// EnrollHostParams sind die Eingaben eines Enrollments.
type EnrollHostParams struct {
	// TokenHash ist der SHA-256 des vorgelegten Tokens.
	TokenHash []byte
	// Name ist der Hostname, unter dem sich der Host registriert.
	Name string
	// PublicKey ist der SSH-Host-Public-Key (authorized_keys-Format).
	PublicKey string
	// Tags aus dem Enroll-Request; Token-Tags haben Vorrang bei Kollision.
	Tags map[string]string
}

// EnrollHost führt das Enrollment transaktional aus: Token einmalig
// verbrauchen (Single-Use, Ablauf geprüft), Host anlegen bzw. beim
// Re-Enrollment aktualisieren, Tags setzen (Token-Tags über Request-Tags)
// und ein Audit-Event schreiben. Ungültiges/verbrauchtes/abgelaufenes Token
// ⇒ ErrNotFound; Hostname-Bindung verletzt ⇒ ErrTokenHostMismatch.
func (s *Store) EnrollHost(ctx context.Context, p EnrollHostParams) (*Host, error) {
	var host *Host
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		token, err := queryOne[EnrollmentToken](ctx, tx, `
			UPDATE enrollment_tokens
			SET used_at = now()
			WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()
			RETURNING *`, p.TokenHash)
		if err != nil {
			return err
		}
		if token.HostName != nil && *token.HostName != p.Name {
			return ErrTokenHostMismatch
		}

		host, err = queryOne[Host](ctx, tx, `
			INSERT INTO hosts (name, public_key, enrolled_at, last_seen_at)
			VALUES ($1, $2, now(), now())
			ON CONFLICT (name) DO UPDATE
			SET public_key = EXCLUDED.public_key, enrolled_at = now(),
			    last_seen_at = now(), updated_at = now()
			RETURNING *`, p.Name, p.PublicKey)
		if err != nil {
			return fmt.Errorf("host anlegen: %w", err)
		}

		tags := map[string]string{}
		for k, v := range p.Tags {
			tags[k] = v
		}
		for k, v := range token.Tags {
			tags[k] = v
		}
		if _, err := tx.Exec(ctx, `DELETE FROM host_tags WHERE host_id = $1`, host.ID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO host_tags (host_id, key, value)
			SELECT $1, e.key, e.value FROM jsonb_each_text($2) AS e`, host.ID, tags); err != nil {
			return fmt.Errorf("tags setzen: %w", err)
		}

		if _, err := tx.Exec(ctx,
			`UPDATE enrollment_tokens SET used_by = $2 WHERE id = $1`, token.ID, host.ID); err != nil {
			return err
		}

		payload, err := json.Marshal(map[string]any{
			"host_id": host.ID, "name": host.Name, "tags": tags, "token_id": token.ID,
		})
		if err != nil {
			return err
		}
		return insertAuditEvent(ctx, tx, &AuditEvent{
			EventType: EventHostEnrolled,
			Actor:     "host:" + p.Name,
			Payload:   payload,
		})
	})
	if err != nil {
		return nil, err
	}
	return host, nil
}

// TouchHostLastSeen stempelt last_seen_at (Agent-Kontakt).
func (s *Store) TouchHostLastSeen(ctx context.Context, id uuid.UUID) error {
	return s.execAffectingOne(ctx,
		`UPDATE hosts SET last_seen_at = now() WHERE id = $1`, id)
}

// ListAuthorizedPrincipals liefert für einen Host und einen lokalen Benutzer
// die Zertifikats-Principals (Username + E-Mail aktiver Benutzer), die sich
// als dieser lokale Benutzer anmelden dürfen: alle Mitglieder von Gruppen,
// deren Grant den lokalen Benutzer als Ziel-Principal enthält und deren
// Tag-Selektor auf die Host-Tags passt (Selektor ⊆ Host-Tags; leer = alle).
func (s *Store) ListAuthorizedPrincipals(ctx context.Context, hostID uuid.UUID, localUser string) ([]string, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT u.username, u.email
		FROM access_grants g
		JOIN user_groups ug ON ug.group_id = g.group_id
		JOIN users u ON u.id = ug.user_id AND u.active
		WHERE $2 = ANY (g.principals)
		  AND g.tag_selector <@ (
		      SELECT COALESCE(jsonb_object_agg(key, value), '{}'::jsonb)
		      FROM host_tags WHERE host_id = $1)
		ORDER BY u.username, u.email`, hostID, localUser)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var principals []string
	seen := map[string]bool{}
	for rows.Next() {
		var username, email string
		if err := rows.Scan(&username, &email); err != nil {
			return nil, err
		}
		for _, p := range []string{username, email} {
			if p != "" && !seen[p] {
				seen[p] = true
				principals = append(principals, p)
			}
		}
	}
	return principals, rows.Err()
}
