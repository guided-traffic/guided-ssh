package agentd

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// enableAudit versetzt einen Test-Daemon in den Session-Audit-Modus.
func enableAudit(d *Daemon) {
	d.cfg.SessionAudit = true
	d.token = "test-token"
}

func envFrom(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestPamEvent(t *testing.T) {
	fixed := time.Unix(1_700_000_000, 0)
	now := func() time.Time { return fixed }

	sshd, ok := pamEvent(envFrom(map[string]string{
		"PAM_TYPE": "open_session", "PAM_SERVICE": "sshd",
		"PAM_USER": "deploy", "PAM_RHOST": "10.0.0.9", "PAM_TTY": "ssh",
	}), now)
	if !ok || sshd.Phase != "open" || sshd.Service != "sshd" || sshd.LocalUser != "deploy" ||
		sshd.RemoteAddr != "10.0.0.9" || !sshd.OccurredAt.Equal(fixed) {
		t.Fatalf("sshd-open falsch: %+v (ok=%v)", sshd, ok)
	}

	sudo, ok := pamEvent(envFrom(map[string]string{
		"PAM_TYPE": "close_session", "PAM_SERVICE": "sudo",
		"PAM_USER": "root", "SUDO_USER": "deploy", "SUDO_COMMAND": "/usr/bin/id",
	}), now)
	if !ok || sudo.Phase != "close" || sudo.LocalUser != "root" ||
		sudo.RemoteUser != "deploy" || sudo.Command != "/usr/bin/id" {
		t.Fatalf("sudo falsch: %+v (ok=%v)", sudo, ok)
	}

	// Pflichtfelder fehlen bzw. unbekannter Typ ⇒ nicht gesendet.
	if _, ok := pamEvent(envFrom(map[string]string{"PAM_SERVICE": "sshd", "PAM_USER": "x"}), now); ok {
		t.Error("fehlendes PAM_TYPE muss ok=false liefern")
	}
	if _, ok := pamEvent(envFrom(map[string]string{"PAM_TYPE": "auth", "PAM_SERVICE": "sshd", "PAM_USER": "x"}), now); ok {
		t.Error("PAM_TYPE=auth muss ok=false liefern")
	}
}

func TestDaemonSessionCorrelationAndSpool(t *testing.T) {
	api := &fakeAPI{}
	d := newTestDaemon(t, api)
	enableAudit(d)

	// 1. Login meldet Serial 42 für deploy.
	postJSON(t, d.handleAuth, "/auth", d.token, authRecord{User: "deploy", Serial: 42, KeyID: "u@host"})

	// 2. sshd-Session-Open ohne Serial ⇒ Daemon reichert 42 an und spoolt.
	postJSON(t, d.handleSessionEvent, "/session-event", d.token, sessionEventWire{
		Phase: "open", Service: "sshd", LocalUser: "deploy", OccurredAt: time.Now(),
	})

	// 3. Flush an den Server.
	d.flushSpool(context.Background())
	sent := api.sentSessions()
	if len(sent) != 1 {
		t.Fatalf("flush: %d events (1 erwartet)", len(sent))
	}
	if sent[0].Serial != 42 || sent[0].KeyID != "u@host" {
		t.Errorf("korrelation fehlt: serial=%d keyid=%q", sent[0].Serial, sent[0].KeyID)
	}
	// Spool ist geleert.
	if raw, _ := os.ReadFile(d.paths.SpoolFile()); len(strings.TrimSpace(string(raw))) != 0 {
		t.Errorf("spool nicht geleert: %q", raw)
	}
}

func TestDaemonSessionTokenRequired(t *testing.T) {
	d := newTestDaemon(t, &fakeAPI{})
	enableAudit(d)

	rec := httptest.NewRecorder()
	body, _ := json.Marshal(authRecord{User: "deploy", Serial: 1})
	req := httptest.NewRequest(http.MethodPost, "/auth", strings.NewReader(string(body)))
	// Kein Token-Header.
	d.handleAuth(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("ohne token: status = %d (403 erwartet)", rec.Code)
	}
}

func TestFlushRequeueOnError(t *testing.T) {
	api := &fakeAPI{sessionsErr: context.DeadlineExceeded}
	d := newTestDaemon(t, api)
	enableAudit(d)

	if err := d.spoolAppend(sessionEventWire{Phase: "open", Service: "sshd", LocalUser: "deploy"}); err != nil {
		t.Fatal(err)
	}
	d.flushSpool(context.Background())

	if api.sessionCalls.Load() != 1 {
		t.Errorf("SendSessions-calls = %d", api.sessionCalls.Load())
	}
	// Bei Fehler bleiben die Events im Spool (verlust-tolerant).
	raw, _ := os.ReadFile(d.paths.SpoolFile())
	if !strings.Contains(string(raw), "deploy") {
		t.Errorf("spool muss nach fehler erhalten bleiben: %q", raw)
	}
}

// postJSON ruft einen Daemon-Handler mit Token-Header auf und verlangt 2xx.
func postJSON(t *testing.T, handler http.HandlerFunc, path, token string, body any) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(raw)))
	req.Header.Set(socketTokenHeader, token)
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code/100 != 2 {
		t.Fatalf("%s: status = %d, body = %s", path, rec.Code, rec.Body.String())
	}
}

func TestWriteSSHDFilesSessionAudit(t *testing.T) {
	opts, pamDir := sshdTestOpts(t, true)
	writePreexistingPAM(t, pamDir)

	resp := &enrollResponse{HostCertificate: "ssh-ed25519-cert", UserCABundle: "ssh-ed25519 CA\n"}
	if err := writeSSHDFiles(opts, resp); err != nil {
		t.Fatalf("writeSSHDFiles: %v", err)
	}

	snippet := readFile(t, SnippetPath(opts.SSHDir))
	if !strings.Contains(snippet, "-serial %s -keyid %i") {
		t.Errorf("snippet ohne serial-tokens:\n%s", snippet)
	}
	if !strings.Contains(snippet, "LogLevel VERBOSE") {
		t.Errorf("snippet ohne LogLevel VERBOSE:\n%s", snippet)
	}
	for _, svc := range []string{"sshd", "sudo"} {
		pam := readFile(t, filepath.Join(pamDir, svc))
		if strings.Count(pam, pamManagedMarker) != 1 {
			t.Errorf("%s: marker-anzahl != 1:\n%s", svc, pam)
		}
		if !strings.Contains(pam, "pam_exec.so quiet") {
			t.Errorf("%s: pam_exec-zeile fehlt:\n%s", svc, pam)
		}
	}

	// Idempotenz: zweiter Lauf hängt nichts an.
	if err := writeSSHDFiles(opts, resp); err != nil {
		t.Fatalf("zweiter writeSSHDFiles: %v", err)
	}
	if got := strings.Count(readFile(t, filepath.Join(pamDir, "sshd")), pamManagedMarker); got != 1 {
		t.Errorf("nicht idempotent: marker-anzahl = %d", got)
	}
}

func TestWriteSSHDFilesDefaultNoAudit(t *testing.T) {
	opts, pamDir := sshdTestOpts(t, false)
	writePreexistingPAM(t, pamDir)

	resp := &enrollResponse{HostCertificate: "cert", UserCABundle: "ca\n"}
	if err := writeSSHDFiles(opts, resp); err != nil {
		t.Fatalf("writeSSHDFiles: %v", err)
	}
	snippet := readFile(t, SnippetPath(opts.SSHDir))
	if strings.Contains(snippet, "-serial") || strings.Contains(snippet, "LogLevel") {
		t.Errorf("default-snippet darf keine audit-tokens enthalten:\n%s", snippet)
	}
	if pam := readFile(t, filepath.Join(pamDir, "sshd")); strings.Contains(pam, pamManagedMarker) {
		t.Errorf("default darf pam nicht anfassen:\n%s", pam)
	}
}

func TestWriteSocketTokenIdempotent(t *testing.T) {
	paths := Paths{StateDir: t.TempDir()}
	if err := writeSocketToken(paths); err != nil {
		t.Fatal(err)
	}
	first := readFile(t, paths.SocketTokenFile())
	if len(strings.TrimSpace(first)) != 64 { // 32 bytes hex
		t.Errorf("token-länge = %d", len(strings.TrimSpace(first)))
	}
	if err := writeSocketToken(paths); err != nil {
		t.Fatal(err)
	}
	if second := readFile(t, paths.SocketTokenFile()); second != first {
		t.Error("token darf beim re-enrollment nicht rotieren")
	}
}

func sshdTestOpts(t *testing.T, sessionAudit bool) (EnrollOptions, string) {
	t.Helper()
	sshDir := t.TempDir()
	pamDir := t.TempDir()
	return EnrollOptions{
		SSHDir:       sshDir,
		SSHKeyPath:   filepath.Join(sshDir, "ssh_host_ed25519_key.pub"),
		StateDir:     t.TempDir(),
		PAMDir:       pamDir,
		SessionAudit: sessionAudit,
	}, pamDir
}

func writePreexistingPAM(t *testing.T, pamDir string) {
	t.Helper()
	for _, svc := range []string{"sshd", "sudo"} {
		if err := os.WriteFile(filepath.Join(pamDir, svc), []byte("# stock\nsession required pam_unix.so\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(raw)
}
