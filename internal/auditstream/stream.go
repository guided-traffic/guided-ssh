// Package auditstream streamt committete Audit-Events fortlaufend als
// strukturierte JSON-Logs (stdout, SIEM-Anbindung) und optional an einen
// Webhook (Phase 8). Der Streamer pollt die Audit-Tabelle ab dem beim Start
// höchsten Event — so werden nur committete Events emittiert und ein Neustart
// wiederholt keine Historie. Die Audit-Tabelle bleibt Source of Truth; das
// Streaming ist best-effort (ein fehlgeschlagener Webhook-Versand wird
// geloggt, aber nicht wiederholt).
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

// Store sind die vom Streamer benötigten Store-Methoden
// (*store.Store erfüllt sie; Tests nutzen einen Fake).
type Store interface {
	MaxAuditEventID(ctx context.Context) (int64, error)
	ListAuditEventsAfter(ctx context.Context, afterID int64, limit int) ([]store.AuditEvent, error)
}

// Config konfiguriert den Streamer.
type Config struct {
	// Logger erhält Streamer-Fehler und — bei LogEvents — jedes Event als
	// strukturierten Log-Eintrag (msg "audit-event").
	Logger *slog.Logger
	// LogEvents aktiviert das Event-Streaming ins Log (SIEM via stdout).
	LogEvents bool
	// WebhookURL erhält jede Batch als JSON-Array per POST; leer = deaktiviert.
	WebhookURL string
	// Interval ist das Poll-Intervall (Default 10 s).
	Interval time.Duration
	// HTTPClient für den Webhook (Default: Timeout 10 s).
	HTTPClient *http.Client
}

// batchSize begrenzt die Events pro Abfrage; volle Batches werden sofort
// weitergepollt, bis der Rückstand aufgeholt ist.
const batchSize = 500

// Streamer pollt Audit-Events und emittiert sie an Log und Webhook.
type Streamer struct {
	store  Store
	cfg    Config
	lastID int64
}

// New baut einen Streamer; Defaults werden hier gesetzt.
func New(st Store, cfg Config) *Streamer {
	if cfg.Interval <= 0 {
		cfg.Interval = 10 * time.Second
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &Streamer{store: st, cfg: cfg}
}

// eventJSON ist die Webhook-Repräsentation eines Audit-Events.
type eventJSON struct {
	ID         int64           `json:"id"`
	OccurredAt time.Time       `json:"occurred_at"`
	EventType  string          `json:"event_type"`
	Actor      string          `json:"actor"`
	Payload    json.RawMessage `json:"payload"`
}

// Run pollt bis der Kontext endet; blockiert (Aufruf als Goroutine).
func (s *Streamer) Run(ctx context.Context) {
	maxID, err := s.store.MaxAuditEventID(ctx)
	if err != nil {
		if s.cfg.Logger != nil {
			s.cfg.Logger.Error("audit-stream: startpunkt bestimmen fehlgeschlagen", "error", err)
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

// drain holt alle neuen Events in Batches ab und emittiert sie.
func (s *Streamer) drain(ctx context.Context) {
	for {
		events, err := s.store.ListAuditEventsAfter(ctx, s.lastID, batchSize)
		if err != nil {
			if s.cfg.Logger != nil {
				s.cfg.Logger.Error("audit-stream: events laden fehlgeschlagen", "error", err)
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

// emit schreibt die Events als strukturierte Logs und an den Webhook.
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
		s.cfg.Logger.Warn("audit-stream: webhook fehlgeschlagen", "error", err, "events", len(events))
	}
}

// postWebhook sendet die Batch als JSON-Array an die konfigurierte URL.
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
		return fmt.Errorf("webhook-status %d", resp.StatusCode)
	}
	return nil
}
