package store

import (
	"context"
	"time"
)

// AuditFilter schränkt ListAuditEvents ein; Zero-Values bedeuten "kein Filter".
type AuditFilter struct {
	EventType string
	Actor     string
	// Search matcht als Teilstring (case-insensitiv) gegen Actor und
	// Payload — deckt Filter nach Host oder Pipeline ab, die nur im
	// Payload stehen.
	Search string
	Since  time.Time
	Until  time.Time
	Limit  int
	Offset int
}

// auditFilterWhere ist die WHERE-Klausel der Audit-Queries; die Argumente
// $1–$5 liefern auditFilterArgs.
const auditFilterWhere = `
	($1 = '' OR event_type = $1)
	AND ($2 = '' OR actor = $2)
	AND ($3::timestamptz IS NULL OR occurred_at >= $3)
	AND ($4::timestamptz IS NULL OR occurred_at <= $4)
	AND ($5 = '' OR actor ILIKE '%' || $5 || '%' OR payload::text ILIKE '%' || $5 || '%')`

// auditFilterArgs baut die Argumente zu auditFilterWhere.
func auditFilterArgs(f AuditFilter) []any {
	var since, until *time.Time
	if !f.Since.IsZero() {
		since = &f.Since
	}
	if !f.Until.IsZero() {
		until = &f.Until
	}
	return []any{f.EventType, f.Actor, since, until, f.Search}
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
	args := append(auditFilterArgs(f), f.Limit, f.Offset)
	return queryAll[AuditEvent](ctx, s.pool, `
		SELECT * FROM audit_events
		WHERE `+auditFilterWhere+`
		ORDER BY occurred_at DESC, id DESC
		LIMIT NULLIF($6, 0) OFFSET $7`, args...)
}

// CountAuditEvents zählt die Events zum Filter (für Pagination in der UI).
func (s *Store) CountAuditEvents(ctx context.Context, f AuditFilter) (int64, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT count(*) FROM audit_events WHERE `+auditFilterWhere,
		auditFilterArgs(f)...)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	var count int64
	if rows.Next() {
		if err := rows.Scan(&count); err != nil {
			return 0, err
		}
	}
	return count, rows.Err()
}

// ListAuditEventsAfter liefert bis zu limit Events mit ID > afterID in
// aufsteigender Reihenfolge — Basis für das Audit-Streaming (SIEM/Webhook),
// das committete Events fortlaufend abholt.
func (s *Store) ListAuditEventsAfter(ctx context.Context, afterID int64, limit int) ([]AuditEvent, error) {
	return queryAll[AuditEvent](ctx, s.pool, `
		SELECT * FROM audit_events
		WHERE id > $1
		ORDER BY id ASC
		LIMIT $2`, afterID, limit)
}

// MaxAuditEventID liefert die höchste vorhandene Event-ID (0 bei leerer
// Tabelle); Startpunkt des Audit-Streamings.
func (s *Store) MaxAuditEventID(ctx context.Context) (int64, error) {
	rows, err := s.pool.Query(ctx, `SELECT COALESCE(max(id), 0) FROM audit_events`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	var maxID int64
	if rows.Next() {
		if err := rows.Scan(&maxID); err != nil {
			return 0, err
		}
	}
	return maxID, rows.Err()
}
