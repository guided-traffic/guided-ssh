package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Audit-Events für Host-Sessions (Phase 9): Session-Start/-Ende und sudo werden
// vom Host-Agent gemeldet und transaktional mit dem Session-Zustand geschrieben.
const (
	EventSessionOpened = "session.opened"
	EventSessionClosed = "session.closed"
	EventSudo          = "session.sudo"
)

// SessionEvent ist ein vom Host-Agent gemeldetes Session-/sudo-Ereignis.
// OccurredAt ist die Host-Zeit des Ereignisses (verzögert eingeliefert möglich);
// CertSerial ist nil, wenn der Agent keinen Serial korrelieren konnte.
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

// actor liefert den Audit-Actor: der meldende Host.
func (e SessionEvent) actor() string { return "host:" + e.HostName }

// nullableTime gibt nil für den Zero-Value zurück (⇒ SQL COALESCE auf now()).
func nullableTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// OpenHostSession legt eine aktive Session an und schreibt ein session.opened-
// Audit-Event. Ist ein CertSerial gesetzt und einem Zertifikat zuordenbar, wird
// user_id daraus korreliert (unbekannter Serial ⇒ NULL, tolerant).
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
				// tolerant: lokales Konto ohne guided-ssh-Zertifikat o. Ä.
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

// CloseHostSession schließt die jüngste passende offene Session (host + lokaler
// Benutzer + tty) und schreibt ein session.closed-Audit-Event. Findet sich keine
// offene Session (z. B. Start vor Aktivierung des Audits verpasst), wird nur das
// Audit-Event geschrieben — verlust-tolerant.
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

// RecordSudoEvent schreibt ein session.sudo-Audit-Event (Ziel-Benutzer,
// aufrufender Benutzer, Kommando). Das Kommando ist best-effort (siehe
// pam-session-Helper); es wird kein Session-Zustand geführt.
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

// ListActiveSessions liefert die aktiven Sessions (ended_at IS NULL), neueste
// zuerst — Grundlage der späteren Dashboards.
func (s *Store) ListActiveSessions(ctx context.Context, limit int) ([]HostSession, error) {
	return queryAll[HostSession](ctx, s.pool, `
		SELECT * FROM host_sessions
		WHERE ended_at IS NULL
		ORDER BY started_at DESC
		LIMIT NULLIF($1, 0)`, limit)
}
