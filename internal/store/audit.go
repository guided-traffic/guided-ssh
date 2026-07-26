package store

import (
	"context"
	"time"
)

// AuditFilter restricts ListAuditEvents; zero values mean "no filter".
type AuditFilter struct {
	EventType string
	Actor     string
	// Search matches as a substring (case-insensitive) against Actor and
	// Payload — covers filtering by host or pipeline, which only appear in
	// the payload.
	Search string
	Since  time.Time
	Until  time.Time
	Limit  int
	Offset int
}

// auditFilterWhere is the WHERE clause of the audit queries; arguments
// $1-$5 are supplied by auditFilterArgs.
const auditFilterWhere = `
	($1 = '' OR event_type = $1)
	AND ($2 = '' OR actor = $2)
	AND ($3::timestamptz IS NULL OR occurred_at >= $3)
	AND ($4::timestamptz IS NULL OR occurred_at <= $4)
	AND ($5 = '' OR actor ILIKE '%' || $5 || '%' OR payload::text ILIKE '%' || $5 || '%')`

// auditFilterArgs builds the arguments for auditFilterWhere.
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

// insertAuditEvent writes an audit event (append-only) through the given
// querier (pool or transaction). A nil payload becomes {}. A set
// OccurredAt is kept as-is (e.g. session events that occurred on the host
// and were delivered late); a zero value defaults to now().
func insertAuditEvent(ctx context.Context, q querier, e *AuditEvent) error {
	var occurredAt *time.Time
	if !e.OccurredAt.IsZero() {
		occurredAt = &e.OccurredAt
	}
	created, err := queryOne[AuditEvent](ctx, q, `
		INSERT INTO audit_events (event_type, actor, payload, occurred_at)
		VALUES ($1, $2, COALESCE($3, '{}'::jsonb), COALESCE($4, now()))
		RETURNING *`,
		e.EventType, e.Actor, e.Payload, occurredAt)
	if err != nil {
		return err
	}
	*e = *created
	return nil
}

// AppendAuditEvent writes an audit event (append-only) and fills in the ID
// and timestamp.
func (s *Store) AppendAuditEvent(ctx context.Context, e *AuditEvent) error {
	return insertAuditEvent(ctx, s.pool, e)
}

// ListAuditEvents returns audit events, newest first.
func (s *Store) ListAuditEvents(ctx context.Context, f AuditFilter) ([]AuditEvent, error) {
	args := append(auditFilterArgs(f), f.Limit, f.Offset)
	return queryAll[AuditEvent](ctx, s.pool, `
		SELECT * FROM audit_events
		WHERE `+auditFilterWhere+`
		ORDER BY occurred_at DESC, id DESC
		LIMIT NULLIF($6, 0) OFFSET $7`, args...)
}

// CountAuditEvents counts the events matching the filter (for pagination in the UI).
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

// ListAuditEventsAfter returns up to limit events with ID > afterID in
// ascending order — the basis for audit streaming (SIEM/webhook), which
// continuously polls for committed events.
func (s *Store) ListAuditEventsAfter(ctx context.Context, afterID int64, limit int) ([]AuditEvent, error) {
	return queryAll[AuditEvent](ctx, s.pool, `
		SELECT * FROM audit_events
		WHERE id > $1
		ORDER BY id ASC
		LIMIT $2`, afterID, limit)
}

// MaxAuditEventID returns the highest existing event ID (0 for an empty
// table); the starting point for audit streaming.
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
