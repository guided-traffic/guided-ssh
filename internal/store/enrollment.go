package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// EnrollmentToken is a single-use token for host enrollment; the database
// only holds its SHA-256 hash.
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

// ErrTokenHostMismatch: the token is bound to a different hostname.
var ErrTokenHostMismatch = errors.New("store: enrollment token is bound to a different hostname")

// EventHostEnrolled is the audit event of a successful enrollment.
const EventHostEnrolled = "host.enrolled"

// EventEnrollTokenCreated is the audit event of a minted enrollment token.
// The payload never contains the plaintext and never the hash.
const EventEnrollTokenCreated = "host.enroll_token.created" //#nosec G101 -- event name, not a credential

// enrollTokenPrefix marks enrollment tokens in plaintext (makes secret
// scanners and misdiagnosis of mixed-up tokens easier).
const enrollTokenPrefix = "gssh-et-" //#nosec G101 -- prefix, not a credential

// NewEnrollmentToken generates the plaintext of an enrollment token and the
// associated record (hash only). Network-free — the CLI and admin API mint
// tokens identically this way. The caller persists the record via
// CreateEnrollmentToken and displays the plaintext exactly once; it is
// never stored anywhere.
func NewEnrollmentToken(hostname string, tags map[string]string, ttl time.Duration) (string, *EnrollmentToken, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", nil, fmt.Errorf("store: generate enrollment token: %w", err)
	}
	plaintext := enrollTokenPrefix + base64.RawURLEncoding.EncodeToString(buf)
	hash := sha256.Sum256([]byte(plaintext))
	rec := &EnrollmentToken{
		TokenHash: hash[:],
		Tags:      tags,
		ExpiresAt: time.Now().Add(ttl),
	}
	if hostname != "" {
		rec.HostName = &hostname
	}
	return plaintext, rec, nil
}

// CreateEnrollmentToken creates an enrollment token (hash, never plaintext).
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

// EnrollHostParams are the inputs of an enrollment.
type EnrollHostParams struct {
	// TokenHash is the SHA-256 of the presented token.
	TokenHash []byte
	// Name is the hostname under which the host registers.
	Name string
	// PublicKey is the SSH host public key (authorized_keys format).
	PublicKey string
	// Tags from the enroll request; token tags take precedence on collision.
	Tags map[string]string
}

// EnrollHost runs the enrollment transactionally: consumes the token once
// (single-use, expiry checked), creates the host or updates it on
// re-enrollment, sets tags (token tags override request tags), and writes
// an audit event. An invalid/used/expired token ⇒ ErrNotFound; a violated
// hostname binding ⇒ ErrTokenHostMismatch.
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
			return fmt.Errorf("create host: %w", err)
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
			return fmt.Errorf("set tags: %w", err)
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

// TouchHostLastSeen stamps last_seen_at (agent contact).
func (s *Store) TouchHostLastSeen(ctx context.Context, id uuid.UUID) error {
	return s.execAffectingOne(ctx,
		`UPDATE hosts SET last_seen_at = now() WHERE id = $1`, id)
}

// ListAuthorizedPrincipals returns, for a host and a local user, the
// certificate principals allowed to log in as that local user: username +
// email of active members of groups whose grant contains the local user as
// a target principal and whose tag selector matches the host tags
// (selector ⊆ host tags; empty = all) — plus ci:<project_path> of every
// matching CI grant (ADR-019).
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
	add := func(p string) {
		if p != "" && !seen[p] {
			seen[p] = true
			principals = append(principals, p)
		}
	}
	for rows.Next() {
		var username, email string
		if err := rows.Scan(&username, &email); err != nil {
			return nil, err
		}
		add(username)
		add(email)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	ciRows, err := s.pool.Query(ctx, `
		SELECT DISTINCT 'ci:' || g.project_path
		FROM ci_grants g
		WHERE $2 = ANY (g.principals)
		  AND g.tag_selector <@ (
		      SELECT COALESCE(jsonb_object_agg(key, value), '{}'::jsonb)
		      FROM host_tags WHERE host_id = $1)
		ORDER BY 1`, hostID, localUser)
	if err != nil {
		return nil, err
	}
	defer ciRows.Close()
	for ciRows.Next() {
		var principal string
		if err := ciRows.Scan(&principal); err != nil {
			return nil, err
		}
		add(principal)
	}
	return principals, ciRows.Err()
}
