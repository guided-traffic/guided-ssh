// Package auditstream continuously streams committed audit events as
// structured JSON logs (stdout, SIEM integration) and optionally to a
// webhook (Phase 8). The streamer polls the audit table starting from the
// highest event ID seen at startup — so only committed events are emitted
// and a restart never replays history. The audit table remains the source
// of truth; streaming is best-effort (a failed webhook delivery is logged
// but not retried).
package auditstream

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/guided-traffic/guided-ssh/internal/store"
)

// Store is the set of store methods the streamer needs
// (*store.Store satisfies it; tests use a fake).
type Store interface {
	MaxAuditEventID(ctx context.Context) (int64, error)
	ListAuditEventsAfter(ctx context.Context, afterID int64, limit int) ([]store.AuditEvent, error)
}

// Config configures the streamer.
type Config struct {
	// Logger receives streamer errors and — when LogEvents is set — every
	// event as a structured log entry (msg "audit-event").
	Logger *slog.Logger
	// LogEvents enables streaming events to the log (SIEM via stdout).
	LogEvents bool
	// WebhookURL receives each batch as a JSON array via POST; empty disables it.
	WebhookURL string
	// Interval is the poll interval (default 10s).
	Interval time.Duration
	// HTTPClient for the webhook (default: 10s timeout).
	HTTPClient *http.Client
}

// batchSize limits the events per query; full batches are polled again
// immediately until the backlog is caught up.
const batchSize = 500

// Streamer polls audit events and emits them to the log and webhook.
type Streamer struct {
	store  Store
	cfg    Config
	lastID int64
}

// New builds a Streamer; defaults are applied here.
func New(st Store, cfg Config) *Streamer {
	if cfg.Interval <= 0 {
		cfg.Interval = 10 * time.Second
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &Streamer{store: st, cfg: cfg}
}

// eventJSON is the webhook representation of an audit event.
type eventJSON struct {
	ID         int64           `json:"id"`
	OccurredAt time.Time       `json:"occurred_at"`
	EventType  string          `json:"event_type"`
	Actor      string          `json:"actor"`
	Payload    json.RawMessage `json:"payload"`
}

// Run polls until the context ends; blocks (call it as a goroutine).
func (s *Streamer) Run(ctx context.Context) {
	maxID, err := s.store.MaxAuditEventID(ctx)
	if err != nil {
		if s.cfg.Logger != nil {
			s.cfg.Logger.Error("audit-stream: failed to determine start point", "error", err)
		}
		return
	}
	s.lastID = maxID

	ticker := time.NewTicker(s.cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.drain(ctx)
		}
	}
}

// drain fetches all new events in batches and emits them.
func (s *Streamer) drain(ctx context.Context) {
	for {
		events, err := s.store.ListAuditEventsAfter(ctx, s.lastID, batchSize)
		if err != nil {
			if s.cfg.Logger != nil {
				s.cfg.Logger.Error("audit-stream: failed to load events", "error", err)
			}
			return
		}
		if len(events) == 0 {
			return
		}
		s.emit(ctx, events)
		s.lastID = events[len(events)-1].ID
		if len(events) < batchSize {
			return
		}
	}
}

// emit writes the events as structured logs and to the webhook.
func (s *Streamer) emit(ctx context.Context, events []store.AuditEvent) {
	if s.cfg.LogEvents && s.cfg.Logger != nil {
		for i := range events {
			e := &events[i]
			s.cfg.Logger.Info("audit-event",
				"audit_id", e.ID,
				"occurred_at", e.OccurredAt,
				"event_type", e.EventType,
				"actor", e.Actor,
				"payload", e.Payload,
			)
		}
	}
	if s.cfg.WebhookURL == "" {
		return
	}
	if err := s.postWebhook(ctx, events); err != nil && s.cfg.Logger != nil {
		s.cfg.Logger.Warn("audit-stream: webhook failed", "error", err, "events", len(events))
	}
}

// postWebhook sends the batch as a JSON array to the configured URL.
func (s *Streamer) postWebhook(ctx context.Context, events []store.AuditEvent) error {
	out := make([]eventJSON, 0, len(events))
	for i := range events {
		e := &events[i]
		out = append(out, eventJSON{
			ID: e.ID, OccurredAt: e.OccurredAt, EventType: e.EventType,
			Actor: e.Actor, Payload: e.Payload,
		})
	}
	body, err := json.Marshal(out)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.cfg.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook status %d", resp.StatusCode)
	}
	return nil
}
