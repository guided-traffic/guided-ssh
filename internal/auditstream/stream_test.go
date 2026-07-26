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

// fakeStreamStore is a thread-safe in-memory store for the streamer;
// started is closed once the streamer has determined its start point (test
// synchronization: from then on, events count as "new").
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

// syncBuffer is a thread-safe log buffer (the streamer runs as a goroutine).
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

func TestStreamerEmitsOnlyNewEvents(t *testing.T) {
	st := newFakeStreamStore()
	// History before start — must not be emitted again.
	st.add(store.AuditEvent{ID: 1, EventType: "grant.created", Actor: "user:alt@idp", Payload: []byte(`{}`)})
	st.add(store.AuditEvent{ID: 2, EventType: "ca.cert_issued", Actor: "user:alt@idp", Payload: []byte(`{}`)})

	var webhookMu sync.Mutex
	var received []map[string]any
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var batch []map[string]any
		if err := json.Unmarshal(body, &batch); err != nil {
			t.Errorf("invalid webhook body: %v", err)
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

	// New events only after the streamer knows its start point.
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
			t.Fatalf("webhook received only %d events", count)
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done

	webhookMu.Lock()
	defer webhookMu.Unlock()
	if len(received) != 2 {
		t.Fatalf("%d webhook events, expected 2 (no history)", len(received))
	}
	if received[0]["id"].(float64) != 3 || received[1]["id"].(float64) != 4 {
		t.Errorf("wrong webhook events: %v", received)
	}

	logged := logs.String()
	if !bytes.Contains([]byte(logged), []byte(`"event_type":"grant.updated"`)) ||
		!bytes.Contains([]byte(logged), []byte(`"event_type":"service_account.updated"`)) {
		t.Errorf("incomplete structured logs: %s", logged)
	}
	if bytes.Contains([]byte(logged), []byte("user:alt@idp")) {
		t.Errorf("history was logged again: %s", logged)
	}
}

func TestStreamerWithoutWebhookOnlyLogs(t *testing.T) {
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
			t.Fatalf("event not logged: %s", logs.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
}
