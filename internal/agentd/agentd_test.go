package agentd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// hostCertValidity ist die Laufzeit der Test-Host-Zertifikate (wie Policy: 30 d).
const hostCertValidity = 30 * 24 * time.Hour

// testSignedHostCert baut ein signiertes Host-Zertifikat, dessen Laufzeit
// bereits um elapsed fortgeschritten ist.
func testSignedHostCert(t *testing.T, elapsed time.Duration) string {
	validFor := hostCertValidity
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatal(err)
	}
	validAfter := time.Now().Add(-elapsed)
	cert := &ssh.Certificate{
		Key:             sshPub,
		CertType:        ssh.HostCert,
		KeyId:           "host:test",
		ValidPrincipals: []string{"test"},
		ValidAfter:      uint64(validAfter.Unix()),               //nolint:gosec // Unix-Zeit nach 1970
		ValidBefore:     uint64(validAfter.Add(validFor).Unix()), //nolint:gosec // dito
	}
	if err := cert.SignCert(rand.Reader, signer); err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert)))
}

// fakeAPI implementiert agentAPI in-memory.
type fakeAPI struct {
	principals    map[string][]string
	principalsErr error
	renewCert     string
	renewErr      error
	bundle        string
	bundleCalls   atomic.Int32
	renewCalls    atomic.Int32

	sessionsMu   sync.Mutex
	sessions     []sessionEventWire
	sessionsErr  error
	sessionCalls atomic.Int32
}

func (f *fakeAPI) Renew(context.Context, string) (string, error) {
	f.renewCalls.Add(1)
	return f.renewCert, f.renewErr
}

func (f *fakeAPI) Principals(_ context.Context, user string) ([]string, error) {
	if f.principalsErr != nil {
		return nil, f.principalsErr
	}
	return f.principals[user], nil
}

func (f *fakeAPI) Bundle(context.Context) (string, error) {
	f.bundleCalls.Add(1)
	return f.bundle, nil
}

func (f *fakeAPI) SendSessions(_ context.Context, events []sessionEventWire) error {
	f.sessionCalls.Add(1)
	if f.sessionsErr != nil {
		return f.sessionsErr
	}
	f.sessionsMu.Lock()
	defer f.sessionsMu.Unlock()
	f.sessions = append(f.sessions, events...)
	return nil
}

func (f *fakeAPI) sentSessions() []sessionEventWire {
	f.sessionsMu.Lock()
	defer f.sessionsMu.Unlock()
	return append([]sessionEventWire(nil), f.sessions...)
}

// newTestDaemon baut einen Daemon mit Fake-API und Temp-Verzeichnissen.
func newTestDaemon(t *testing.T, api agentAPI) *Daemon {
	t.Helper()
	stateDir := t.TempDir()
	sshDir := t.TempDir()
	sock, err := os.MkdirTemp("", "gsshd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sock) })
	cfg := &Config{
		AgentURL:   "https://irrelevant.example",
		HostID:     "00000000-0000-0000-0000-000000000000",
		HostName:   "test.example.com",
		SSHKeyPath: filepath.Join(sshDir, "ssh_host_ed25519_key.pub"),
		SSHDir:     sshDir,
		SocketPath: filepath.Join(sock, "a.sock"),
	}
	cfg.applyDefaults(Paths{StateDir: stateDir})
	return &Daemon{
		cfg: cfg, paths: Paths{StateDir: stateDir}, api: api,
		logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		cache:      map[string]cacheEntry{},
		recentAuth: map[string][]authRec{},
	}
}

func TestConfigRoundtrip(t *testing.T) {
	stateDir := t.TempDir()
	paths := Paths{StateDir: stateDir}
	cfg := &Config{
		AgentURL: "https://gssh:8443", HostID: "id-1", HostName: "h",
		SSHKeyPath: "/etc/ssh/ssh_host_ed25519_key.pub",
		CacheTTL:   Duration(2 * time.Minute),
	}
	cfg.applyDefaults(paths)
	if err := writeConfig(paths, cfg); err != nil {
		t.Fatalf("writeConfig: %v", err)
	}
	loaded, err := LoadConfig(stateDir)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if loaded.AgentURL != cfg.AgentURL || time.Duration(loaded.CacheTTL) != 2*time.Minute {
		t.Errorf("roundtrip: %+v", loaded)
	}
	if time.Duration(loaded.BundleInterval) != defaultBundleInterval {
		t.Errorf("default fehlt: %v", loaded.BundleInterval)
	}
}

func TestLoadConfigFehlt(t *testing.T) {
	if _, err := LoadConfig(t.TempDir()); err == nil {
		t.Fatal("fehler erwartet")
	}
}

func TestLoadConfigUnvollstaendig(t *testing.T) {
	stateDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(stateDir, "config.yaml"), []byte("host_id: x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(stateDir); err == nil || !strings.Contains(err.Error(), "unvollständig") {
		t.Fatalf("unvollständig-fehler erwartet, bekam %v", err)
	}
}

func TestHostCertPath(t *testing.T) {
	got := HostCertPath("/etc/ssh/ssh_host_ed25519_key.pub")
	if got != "/etc/ssh/ssh_host_ed25519_key-cert.pub" {
		t.Errorf("HostCertPath = %q", got)
	}
}

func TestNeedsRenewal(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pub")

	// Keine Datei ⇒ erneuern.
	if !needsRenewal(certPath, time.Now()) {
		t.Error("fehlende datei muss erneuerung auslösen")
	}
	// Müll ⇒ erneuern.
	_ = os.WriteFile(certPath, []byte("müll"), 0o600)
	if !needsRenewal(certPath, time.Now()) {
		t.Error("unparsebares zertifikat muss erneuerung auslösen")
	}
	// Frisch (10 % verstrichen) ⇒ nicht erneuern.
	_ = os.WriteFile(certPath, []byte(testSignedHostCert(t, 3*24*time.Hour)), 0o600)
	if needsRenewal(certPath, time.Now()) {
		t.Error("frisches zertifikat darf nicht erneuert werden")
	}
	// 80 % verstrichen ⇒ erneuern.
	_ = os.WriteFile(certPath, []byte(testSignedHostCert(t, 24*24*time.Hour)), 0o600)
	if !needsRenewal(certPath, time.Now()) {
		t.Error("2/3 laufzeit überschritten muss erneuerung auslösen")
	}
}

func TestRenewIfNeeded(t *testing.T) {
	api := &fakeAPI{renewCert: testSignedHostCert(t, 0)}
	d := newTestDaemon(t, api)
	// Host-Key anlegen (Renew schickt ihn an die API).
	_ = os.WriteFile(d.cfg.SSHKeyPath, []byte("ssh-ed25519 AAAA host"), 0o600)

	d.renewIfNeeded(context.Background())
	if api.renewCalls.Load() != 1 {
		t.Fatalf("renewCalls = %d", api.renewCalls.Load())
	}
	raw, err := os.ReadFile(HostCertPath(d.cfg.SSHKeyPath))
	if err != nil || !strings.HasPrefix(string(raw), "ssh-ed25519-cert") {
		t.Fatalf("zertifikat nicht geschrieben: %v %q", err, raw)
	}
	// Zweiter Lauf: Zertifikat frisch ⇒ kein weiterer Call.
	d.renewIfNeeded(context.Background())
	if api.renewCalls.Load() != 1 {
		t.Errorf("frisches zertifikat erneut erneuert (calls=%d)", api.renewCalls.Load())
	}
}

func TestRefreshBundle(t *testing.T) {
	api := &fakeAPI{bundle: "ssh-ed25519 AAAA ca\n"}
	d := newTestDaemon(t, api)

	d.refreshBundle(context.Background())
	raw, err := os.ReadFile(UserCAPath(d.cfg.SSHDir))
	if err != nil || string(raw) != api.bundle {
		t.Fatalf("bundle: %v %q", err, raw)
	}
	// Unverändert ⇒ kein Rewrite nötig (nur API-Call zählt hoch).
	d.refreshBundle(context.Background())
	if api.bundleCalls.Load() != 2 {
		t.Errorf("bundleCalls = %d", api.bundleCalls.Load())
	}
}

func TestPrincipalsCacheUndFailClosed(t *testing.T) {
	api := &fakeAPI{principals: map[string][]string{"deploy": {"alice", "alice@example.com"}}}
	d := newTestDaemon(t, api)
	ctx := context.Background()

	// Erster Abruf: von der API, wird gecacht + persistiert.
	got, err := d.principals(ctx, "deploy")
	if err != nil || len(got) != 2 {
		t.Fatalf("principals: %v %v", got, err)
	}
	if _, err := os.Stat(d.paths.CacheFile()); err != nil {
		t.Errorf("cache nicht persistiert: %v", err)
	}

	// API fällt aus: frischer Cache (innerhalb TTL) trägt weiter.
	api.principalsErr = errors.New("api down")
	got, err = d.principals(ctx, "deploy")
	if err != nil || len(got) != 2 {
		t.Fatalf("cache-fallback: %v %v", got, err)
	}

	// Cache abgelaufen ⇒ fail-closed.
	d.mu.Lock()
	entry := d.cache["deploy"]
	entry.FetchedAt = time.Now().Add(-time.Duration(d.cfg.CacheTTL) - time.Minute)
	d.cache["deploy"] = entry
	d.mu.Unlock()
	if _, err := d.principals(ctx, "deploy"); err == nil {
		t.Fatal("fail-closed erwartet (cache abgelaufen, api down)")
	}

	// Unbekannter user ohne Cache ⇒ fail-closed.
	if _, err := d.principals(ctx, "root"); err == nil {
		t.Fatal("fail-closed erwartet (kein cache)")
	}
}

func TestDaemonSocketUndHelper(t *testing.T) {
	api := &fakeAPI{
		principals: map[string][]string{"deploy": {"alice"}},
		bundle:     "ssh-ed25519 AAAA ca\n",
		renewCert:  testSignedHostCert(t, 0),
	}
	d := newTestDaemon(t, api)
	_ = os.WriteFile(d.cfg.SSHKeyPath, []byte("ssh-ed25519 AAAA host"), 0o600)
	// Config auf Platte, damit der Helper sie laden kann.
	if err := writeConfig(d.paths, d.cfg); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()

	// Warten bis Socket antwortet.
	waitForSocket(t, d.cfg.SocketPath)

	var stdout bytes.Buffer
	if err := PrintPrincipals(ctx, d.paths.StateDir, "deploy", 0, "", &stdout); err != nil {
		t.Fatalf("PrintPrincipals: %v", err)
	}
	if strings.TrimSpace(stdout.String()) != "alice" {
		t.Errorf("stdout = %q", stdout.String())
	}

	// Fail-closed über den Helper: unbekannter User, API down.
	api.principalsErr = errors.New("api down")
	var out2 bytes.Buffer
	if err := PrintPrincipals(ctx, d.paths.StateDir, "root", 0, "", &out2); err == nil {
		t.Fatal("fail-closed erwartet")
	}
	if out2.Len() != 0 {
		t.Errorf("fail-closed darf nichts ausgeben: %q", out2.String())
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("daemon: %v", err)
	}
}

func TestPrintPrincipalsOhneDaemon(t *testing.T) {
	stateDir := t.TempDir()
	cfg := &Config{
		AgentURL: "https://x", HostID: "id", HostName: "h",
		SSHKeyPath: "/etc/ssh/k.pub",
		SocketPath: filepath.Join(stateDir, "fehlt.sock"),
	}
	cfg.applyDefaults(Paths{StateDir: stateDir})
	if err := writeConfig(Paths{StateDir: stateDir}, cfg); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	if err := PrintPrincipals(context.Background(), stateDir, "deploy", 0, "", &stdout); err == nil {
		t.Fatal("fehler erwartet (daemon läuft nicht)")
	}
}

func TestPrintPrincipalsOhneUser(t *testing.T) {
	if err := PrintPrincipals(context.Background(), t.TempDir(), "", 0, "", io.Discard); err == nil {
		t.Fatal("fehler erwartet (user fehlt)")
	}
}

// waitForSocket pollt bis der Daemon-Socket antwortet.
func waitForSocket(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("daemon-socket kam nicht hoch")
}

func TestRunCLI(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := Run(&stdout, &stderr, nil); got != 2 {
		t.Errorf("ohne args = %d", got)
	}
	if got := Run(&stdout, &stderr, []string{"gibtsnicht"}); got != 2 {
		t.Errorf("unbekannt = %d", got)
	}
	stdout.Reset()
	if got := Run(&stdout, &stderr, []string{"version"}); got != 0 || !strings.Contains(stdout.String(), "guided-ssh") {
		t.Errorf("version = %d %q", got, stdout.String())
	}
	stdout.Reset()
	if got := Run(&stdout, &stderr, []string{"help"}); got != 0 || !strings.Contains(stdout.String(), "kommandos") {
		t.Errorf("help = %d", got)
	}
	if got := Run(&stdout, &stderr, []string{"enroll", "--gibtsnicht"}); got != 2 {
		t.Errorf("enroll flag-fehler = %d", got)
	}
	if got := Run(&stdout, &stderr, []string{"enroll"}); got != 1 {
		t.Errorf("enroll ohne pflicht-flags = %d", got)
	}
	if got := Run(&stdout, &stderr, []string{"run", "-state-dir", t.TempDir()}); got != 1 {
		t.Errorf("run ohne enrollment = %d", got)
	}
	if got := Run(&stdout, &stderr, []string{"principals", "-state-dir", t.TempDir(), "-user", "x"}); got != 1 {
		t.Errorf("principals ohne enrollment = %d", got)
	}
	if got := Run(&stdout, &stderr, []string{"enroll", "-tags", "kaputt", "-server", "x", "-agent-url", "y", "-token", "z"}); got != 2 {
		t.Errorf("kaputte tags = %d", got)
	}
}

// TestEnrollGegenFakeServer: kompletter Enroll-Ablauf gegen einen HTTP-Fake —
// prüft geschriebene Dateien und Snippet-Inhalt.
func TestEnrollGegenFakeServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/enroll" {
			http.NotFound(w, r)
			return
		}
		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "body", http.StatusBadRequest)
			return
		}
		if req["token"] != "tok-1" {
			http.Error(w, "token", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"host_id":          "11111111-2222-3333-4444-555555555555",
			"host_certificate": testSignedHostCert(t, 0),
			"user_ca_bundle":   "ssh-ed25519 AAAA user-ca\n",
			"mtls_certificate": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
			"mtls_ca":          "-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----\n",
		})
	}))
	t.Cleanup(server.Close)

	stateDir := t.TempDir()
	sshDir := t.TempDir()
	keyPath := filepath.Join(sshDir, "ssh_host_ed25519_key.pub")
	if err := os.WriteFile(keyPath, []byte("ssh-ed25519 AAAA host\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout bytes.Buffer
	err := Enroll(context.Background(), EnrollOptions{
		ServerURL: server.URL, AgentURL: "https://gssh:8443", Token: "tok-1",
		Hostname: "web1.example.com", StateDir: stateDir, SSHDir: sshDir, SSHKeyPath: keyPath,
		Tags: map[string]string{"env": "prod"},
	}, &stdout)
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	// State-Dateien.
	for _, f := range []string{"config.yaml", "agent.key", "agent.crt", "server-ca.pem"} {
		if _, err := os.Stat(filepath.Join(stateDir, f)); err != nil {
			t.Errorf("%s fehlt: %v", f, err)
		}
	}
	cfg, err := LoadConfig(stateDir)
	if err != nil || cfg.HostID != "11111111-2222-3333-4444-555555555555" {
		t.Errorf("config: %+v %v", cfg, err)
	}

	// sshd-Dateien.
	if _, err := os.Stat(HostCertPath(keyPath)); err != nil {
		t.Errorf("host-zertifikat fehlt: %v", err)
	}
	snippet, err := os.ReadFile(SnippetPath(sshDir))
	if err != nil {
		t.Fatalf("snippet: %v", err)
	}
	for _, want := range []string{"TrustedUserCAKeys", "HostCertificate", "AuthorizedPrincipalsCommand", "principals -state-dir " + stateDir} {
		if !strings.Contains(string(snippet), want) {
			t.Errorf("snippet ohne %q:\n%s", want, snippet)
		}
	}

	// Falsches Token ⇒ Fehler.
	err = Enroll(context.Background(), EnrollOptions{
		ServerURL: server.URL, AgentURL: "https://gssh:8443", Token: "falsch",
		Hostname: "x", StateDir: t.TempDir(), SSHDir: sshDir, SSHKeyPath: keyPath,
	}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("403 erwartet, bekam %v", err)
	}
}

func TestEnrollOhneHostKey(t *testing.T) {
	err := Enroll(context.Background(), EnrollOptions{
		ServerURL: "http://127.0.0.1:1", AgentURL: "https://x", Token: "t",
		Hostname: "h", StateDir: t.TempDir(), SSHDir: t.TempDir(),
		SSHKeyPath: filepath.Join(t.TempDir(), "fehlt.pub"),
	}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "ssh-host-key") {
		t.Fatalf("host-key-fehler erwartet, bekam %v", err)
	}
}
