package agentd

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// startSocketServer serves the daemon socket handler on the configured unix
// socket (like Daemon.Run, but without the renew/bundle loops).
func startSocketServer(t *testing.T, d *Daemon) {
	t.Helper()
	listener, err := net.Listen("unix", d.cfg.SocketPath)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: d.socketHandler(), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
}

// TestRunPAMSessionRoundtrip covers the complete pam_exec path: PAM env →
// RunPAMSession → token-protected daemon socket → spool.
func TestRunPAMSessionRoundtrip(t *testing.T) {
	d := newTestDaemon(t, &fakeAPI{})
	enableAudit(d)
	if err := writeConfig(d.paths, d.cfg); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(d.paths.SocketTokenFile(), []byte(d.token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	startSocketServer(t, d)

	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	env := envFrom(map[string]string{
		"PAM_TYPE":    "open_session",
		"PAM_SERVICE": "sshd",
		"PAM_USER":    "deploy",
		"PAM_RHOST":   "192.0.2.1",
		"PAM_TTY":     "ssh",
	})
	if err := RunPAMSession(context.Background(), d.paths.StateDir, env, func() time.Time { return now }); err != nil {
		t.Fatalf("RunPAMSession: %v", err)
	}

	raw, err := os.ReadFile(d.paths.SpoolFile())
	if err != nil {
		t.Fatalf("reading spool: %v", err)
	}
	for _, want := range []string{"deploy", "sshd", "192.0.2.1", "open"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("spool missing %q: %s", want, raw)
		}
	}
}

// Without a socket token (session audit off), the hook is a no-op.
func TestRunPAMSessionWithoutAudit(t *testing.T) {
	stateDir := t.TempDir()
	env := envFrom(map[string]string{"PAM_TYPE": "open_session", "PAM_SERVICE": "sshd", "PAM_USER": "deploy"})
	if err := RunPAMSession(context.Background(), stateDir, env, time.Now); err != nil {
		t.Fatalf("without audit: %v", err)
	}
}

// An incomplete PAM environment (no PAM_USER) sends nothing — even with a token.
func TestRunPAMSessionIncompleteEnv(t *testing.T) {
	d := newTestDaemon(t, &fakeAPI{})
	enableAudit(d)
	if err := os.WriteFile(d.paths.SocketTokenFile(), []byte(d.token), 0o600); err != nil {
		t.Fatal(err)
	}
	env := envFrom(map[string]string{"PAM_TYPE": "open_session", "PAM_SERVICE": "sshd"})
	if err := RunPAMSession(context.Background(), d.paths.StateDir, env, time.Now); err != nil {
		t.Fatalf("incomplete env: %v", err)
	}
}

// runPAMSessionCmd (CLI) always exits 0 — fail-open, pam_exec must never
// block login/sudo, even without enrollment.
func TestCLIPAMSessionFailOpen(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := Run(&stdout, &stderr, []string{"pam-session", "-state-dir", t.TempDir()}); got != 0 {
		t.Fatalf("pam-session = %d, want 0 (fail-open)", got)
	}
}
