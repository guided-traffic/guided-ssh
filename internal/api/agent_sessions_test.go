package api_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/guided-traffic/guided-ssh/internal/api"
	"github.com/guided-traffic/guided-ssh/internal/ca"
	"github.com/guided-traffic/guided-ssh/internal/store"
)

// fakeSessionStore zählt die dispatchten Store-Aufrufe.
type fakeSessionStore struct {
	opened []store.SessionEvent
	closed []store.SessionEvent
	sudo   []store.SessionEvent
}

func (f *fakeSessionStore) OpenHostSession(_ context.Context, e store.SessionEvent) error {
	f.opened = append(f.opened, e)
	return nil
}

func (f *fakeSessionStore) CloseHostSession(_ context.Context, e store.SessionEvent) error {
	f.closed = append(f.closed, e)
	return nil
}

func (f *fakeSessionStore) RecordSudoEvent(_ context.Context, e store.SessionEvent) error {
	f.sudo = append(f.sudo, e)
	return nil
}

func newSessionsHandler(t *testing.T, hosts *fakeHostStore, sessions api.SessionStore) http.Handler {
	t.Helper()
	fs := &fakeStore{}
	masterKey := make([]byte, ca.MasterKeySize)
	certAuthority, err := ca.New(fs, masterKey, ca.NewPolicyEngine(ca.DefaultPolicies()))
	if err != nil {
		t.Fatalf("ca.New: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return api.NewAgent(api.AgentDeps{CA: certAuthority, Hosts: hosts, Sessions: sessions, Logger: logger})
}

func TestAgentSessionsDispatch(t *testing.T) {
	hosts := newFakeHostStore()
	host := enrolledHost(hosts)
	sessions := &fakeSessionStore{}
	handler := newSessionsHandler(t, hosts, sessions)

	body, _ := json.Marshal(map[string]any{"events": []map[string]any{
		{"phase": "open", "service": "sshd", "local_user": "deploy", "serial": 42, "remote_addr": "10.0.0.9"},
		{"phase": "close", "service": "sshd", "local_user": "deploy"},
		{"phase": "open", "service": "sudo", "local_user": "root", "remote_user": "deploy", "command": "/usr/bin/id"},
		{"phase": "close", "service": "sudo", "local_user": "root"}, // wird verworfen
	}})
	req := agentRequest(http.MethodPost, "/v1/agent/sessions", string(body), host.ID.String())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if len(sessions.opened) != 1 || sessions.opened[0].LocalUser != "deploy" {
		t.Fatalf("opened = %+v", sessions.opened)
	}
	if sessions.opened[0].CertSerial == nil || *sessions.opened[0].CertSerial != 42 {
		t.Errorf("serial nicht übernommen: %+v", sessions.opened[0].CertSerial)
	}
	if sessions.opened[0].HostName != host.Name {
		t.Errorf("hostname = %q", sessions.opened[0].HostName)
	}
	if len(sessions.closed) != 1 {
		t.Errorf("closed = %+v", sessions.closed)
	}
	if len(sessions.sudo) != 1 || sessions.sudo[0].Command != "/usr/bin/id" {
		t.Errorf("sudo = %+v", sessions.sudo)
	}
}

func TestAgentSessionsOhneClientCert(t *testing.T) {
	hosts := newFakeHostStore()
	handler := newSessionsHandler(t, hosts, &fakeSessionStore{})
	req := agentRequest(http.MethodPost, "/v1/agent/sessions", `{"events":[]}`, "")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d (401 erwartet)", rec.Code)
	}
}
