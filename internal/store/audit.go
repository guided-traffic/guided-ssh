package store

import (
	"context"
	"time"
)

// AuditFilter schränkt ListAuditEvents ein; Zero-Values bedeuten "kein Filter".
type AuditFilter struct {
	EventType string
	Actor     string
	Since     time.Time
	Until     time.Time
	Limit     int
}

// insertAuditEvent schreibt ein Audit-Event (append-only) über den gegebenen
// querier (Pool oder Transaktion). Nil-Payload wird zu {}.
func insertAuditEvent(ctx context.Context, q querier, e *AuditEvent) error {
	created, err := queryOne[AuditEvent](ctx, q, `
		INSERT INTO audit_events (event_type, actor, payload)
		VALUES ($1, $2, COALESCE($3, '{}'::jsonb))
		RETURNING *`,
		e.EventType, e.Actor, e.Payload)
	if err != nil {
		return err
	}
	*e = *created
	return nil
}

// AppendAuditEvent schreibt ein Audit-Event (append-only) und füllt ID und
// Zeitstempel.
func (s *Store) AppendAuditEvent(ctx context.Context, e *AuditEvent) error {
	return insertAuditEvent(ctx, s.pool, e)
}

// ListAuditEvents liefert Audit-Events, neueste zuerst.
func (s *Store) ListAuditEvents(ctx context.Context, f AuditFilter) ([]AuditEvent, error) {
	var since, until *time.Time
	if !f.Since.IsZero() {
		since = &f.Since
	}
	if !f.Until.IsZero() {
		until = &f.Until
	}
	return queryAll[AuditEvent](ctx, s.pool, `
		SELECT * FROM audit_events
		WHERE ($1 = '' OR event_type = $1)
		  AND ($2 = '' OR actor = $2)
		  AND ($3::timestamptz IS NULL OR occurred_at >= $3)
		  AND ($4::timestamptz IS NULL OR occurred_at <= $4)
		ORDER BY occurred_at DESC, id DESC
		LIMIT NULLIF($5, 0)`,
		f.EventType, f.Actor, since, until, f.Limit)
}
