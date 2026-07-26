package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Audit events for host sessions (phase 9): session start/end and sudo are
// reported by the host agent and written transactionally with the session state.
const (
	EventSessionOpened = "session.opened"
	EventSessionClosed = "session.closed"
	EventSudo          = "session.sudo"
)

// SessionEvent is a session/sudo event reported by the host agent.
// OccurredAt is the host-side time of the event (may be delivered late);
// CertSerial is nil if the agent could not correlate a serial.
type SessionEvent struct {
	HostID     uuid.UUID
	HostName   string
	LocalUser  string
	RemoteUser string
	RemoteAddr string
	TTY        string
	CertSerial *int64
	KeyID      string
	Command    string
	OccurredAt time.Time
}

// actor returns the audit actor: the reporting host.
func (e SessionEvent) actor() string { return "host:" + e.HostName }

// nullableTime returns nil for the zero value (⇒ SQL COALESCE falls back to now()).
func nullableTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// OpenHostSession creates an active session and writes a session.opened
// audit event. If CertSerial is set and maps to a certificate, user_id is
// correlated from it (unknown serial ⇒ NULL, tolerant).
func (s *Store) OpenHostSession(ctx context.Context, e SessionEvent) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var userID *uuid.UUID
		if e.CertSerial != nil {
			cert, err := queryOne[Certificate](ctx, tx,
				`SELECT * FROM certificates WHERE serial = $1`, *e.CertSerial)
			switch {
			case err == nil:
				userID = cert.UserID
			case errors.Is(err, ErrNotFound):
				// tolerant: local account without a guided-ssh certificate or similar.
			default:
				return err
			}
		}
		session, err := queryOne[HostSession](ctx, tx, `
			INSERT INTO host_sessions
				(host_id, local_user, remote_user, remote_addr, tty, cert_serial, key_id, user_id, started_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, COALESCE($9, now()))
			RETURNING *`,
			e.HostID, e.LocalUser, e.RemoteUser, e.RemoteAddr, e.TTY,
			e.CertSerial, e.KeyID, userID, nullableTime(e.OccurredAt))
		if err != nil {
			return err
		}
		payload, err := json.Marshal(map[string]any{
			"session_id":  session.ID,
			"host_id":     e.HostID,
			"local_user":  e.LocalUser,
			"remote_addr": e.RemoteAddr,
			"tty":         e.TTY,
			"cert_serial": e.CertSerial,
			"key_id":      e.KeyID,
			"user_id":     userID,
		})
		if err != nil {
			return err
		}
		return insertAuditEvent(ctx, tx, &AuditEvent{
			EventType: EventSessionOpened, Actor: e.actor(),
			Payload: payload, OccurredAt: e.OccurredAt,
		})
	})
}

// CloseHostSession closes the most recent matching open session (host +
// local user + tty) and writes a session.closed audit event. If no open
// session is found (e.g. its start was missed before auditing was
// enabled), only the audit event is written — loss-tolerant.
func (s *Store) CloseHostSession(ctx context.Context, e SessionEvent) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		closed, err := queryOne[HostSession](ctx, tx, `
			UPDATE host_sessions SET ended_at = COALESCE($4, now())
			WHERE id = (
				SELECT id FROM host_sessions
				WHERE host_id = $1 AND local_user = $2 AND tty = $3 AND ended_at IS NULL
				ORDER BY started_at DESC LIMIT 1)
			RETURNING *`,
			e.HostID, e.LocalUser, e.TTY, nullableTime(e.OccurredAt))
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}

		fields := map[string]any{
			"host_id":    e.HostID,
			"local_user": e.LocalUser,
			"tty":        e.TTY,
			"matched":    err == nil,
		}
		if err == nil {
			fields["session_id"] = closed.ID
			fields["cert_serial"] = closed.CertSerial
			fields["user_id"] = closed.UserID
			if closed.EndedAt != nil {
				fields["duration_seconds"] = int64(closed.EndedAt.Sub(closed.StartedAt).Seconds())
			}
		}
		payload, marshalErr := json.Marshal(fields)
		if marshalErr != nil {
			return marshalErr
		}
		return insertAuditEvent(ctx, tx, &AuditEvent{
			EventType: EventSessionClosed, Actor: e.actor(),
			Payload: payload, OccurredAt: e.OccurredAt,
		})
	})
}

// RecordSudoEvent writes a session.sudo audit event (target user, invoking
// user, command). The command is best-effort (see the pam-session helper);
// no session state is maintained.
func (s *Store) RecordSudoEvent(ctx context.Context, e SessionEvent) error {
	payload, err := json.Marshal(map[string]any{
		"host_id":       e.HostID,
		"target_user":   e.LocalUser,
		"invoking_user": e.RemoteUser,
		"command":       e.Command,
		"tty":           e.TTY,
	})
	if err != nil {
		return err
	}
	return s.AppendAuditEvent(ctx, &AuditEvent{
		EventType: EventSudo, Actor: e.actor(),
		Payload: payload, OccurredAt: e.OccurredAt,
	})
}

// ListActiveSessions returns the active sessions (ended_at IS NULL), newest
// first — the basis for later dashboards.
func (s *Store) ListActiveSessions(ctx context.Context, limit int) ([]HostSession, error) {
	return queryAll[HostSession](ctx, s.pool, `
		SELECT * FROM host_sessions
		WHERE ended_at IS NULL
		ORDER BY started_at DESC
		LIMIT NULLIF($1, 0)`, limit)
}
