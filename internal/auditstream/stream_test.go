package auditstream_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/guided-traffic/guided-ssh/internal/auditstream"
	"github.com/guided-traffic/guided-ssh/internal/store"
)

// fakeStreamStore ist ein threadsicherer In-Memory-Store für den Streamer;
// started wird geschlossen, sobald der Streamer seinen Startpunkt bestimmt
// hat (Synchronisation der Tests: ab dann zählen Events als "neu").
type fakeStreamStore struct {
	mu      sync.Mutex
	events  []store.AuditEvent
	started chan struct{}
	once    sync.Once
}

func newFakeStreamStore() *fakeStreamStore {
	return &fakeStreamStore{started: make(chan struct{})}
}

func (f *fakeStreamStore) MaxAuditEventID(context.Context) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var maxID int64
	for _, e := range f.events {
		maxID = max(maxID, e.ID)
	}
	f.once.Do(func() { close(f.started) })
	return maxID, nil
}

func (f *fakeStreamStore) ListAuditEventsAfter(_ context.Context, afterID int64, limit int) ([]store.AuditEvent, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []store.AuditEvent
	for _, e := range f.events {
		if e.ID > afterID && len(out) < limit {
			out = append(out, e)
		}
	}
	return out, nil
}

func (f *fakeStreamStore) add(e store.AuditEvent) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, e)
}

// syncBuffer ist ein threadsicherer Log-Puffer (Streamer läuft als Goroutine).
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestStreamerEmittiertNurNeueEvents(t *testing.T) {
	st := newFakeStreamStore()
	// Historie vor dem Start — darf nicht erneut emittiert werden.
	st.add(store.AuditEvent{ID: 1, EventType: "grant.created", Actor: "user:alt@idp", Payload: []byte(`{}`)})
	st.add(store.AuditEvent{ID: 2, EventType: "ca.cert_issued", Actor: "user:alt@idp", Payload: []byte(`{}`)})

	var webhookMu sync.Mutex
	var received []map[string]any
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var batch []map[string]any
		if err := json.Unmarshal(body, &batch); err != nil {
			t.Errorf("webhook-body ungültig: %v", err)
		}
		webhookMu.Lock()
		received = append(received, batch...)
		webhookMu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer webhook.Close()

	logs := &syncBuffer{}
	streamer := auditstream.New(st, auditstream.Config{
		Logger:     slog.New(slog.NewJSONHandler(logs, nil)),
		LogEvents:  true,
		WebhookURL: webhook.URL,
		Interval:   5 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { streamer.Run(ctx); close(done) }()

	// Neue Events erst, nachdem der Streamer seinen Startpunkt kennt.
	<-st.started
	st.add(store.AuditEvent{ID: 3, EventType: "grant.updated", Actor: "user:admin@idp", Payload: []byte(`{"grant_id":"g1"}`)})
	st.add(store.AuditEvent{ID: 4, EventType: "service_account.updated", Actor: "user:admin@idp", Payload: []byte(`{"active":false}`)})

	deadline := time.Now().Add(2 * time.Second)
	for {
		webhookMu.Lock()
		count := len(received)
		webhookMu.Unlock()
		if count >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("webhook hat nur %d events erhalten", count)
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done

	webhookMu.Lock()
	defer webhookMu.Unlock()
	if len(received) != 2 {
		t.Fatalf("%d webhook-events, erwartet 2 (keine historie)", len(received))
	}
	if received[0]["id"].(float64) != 3 || received[1]["id"].(float64) != 4 {
		t.Errorf("webhook-events falsch: %v", received)
	}

	logged := logs.String()
	if !bytes.Contains([]byte(logged), []byte(`"event_type":"grant.updated"`)) ||
		!bytes.Contains([]byte(logged), []byte(`"event_type":"service_account.updated"`)) {
		t.Errorf("strukturierte logs unvollständig: %s", logged)
	}
	if bytes.Contains([]byte(logged), []byte("user:alt@idp")) {
		t.Errorf("historie wurde erneut geloggt: %s", logged)
	}
}

func TestStreamerOhneWebhookNurLogs(t *testing.T) {
	st := newFakeStreamStore()
	logs := &syncBuffer{}
	streamer := auditstream.New(st, auditstream.Config{
		Logger:    slog.New(slog.NewJSONHandler(logs, nil)),
		LogEvents: true,
		Interval:  5 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { streamer.Run(ctx); close(done) }()

	<-st.started
	st.add(store.AuditEvent{ID: 1, EventType: "host.enrolled", Actor: "host:web-1", Payload: []byte(`{}`)})

	deadline := time.Now().Add(2 * time.Second)
	for !bytes.Contains([]byte(logs.String()), []byte("host.enrolled")) {
		if time.Now().After(deadline) {
			t.Fatalf("event nicht geloggt: %s", logs.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
}
