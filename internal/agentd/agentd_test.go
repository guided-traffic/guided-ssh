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

// hostCertValidity is the validity period of test host certificates (like
// the policy: 30 d).
const hostCertValidity = 30 * 24 * time.Hour

// testSignedHostCert builds a signed host certificate whose validity has
// already advanced by elapsed.
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
		ValidAfter:      uint64(validAfter.Unix()),               //nolint:gosec // unix time after 1970
		ValidBefore:     uint64(validAfter.Add(validFor).Unix()), //nolint:gosec // same
	}
	if err := cert.SignCert(rand.Reader, signer); err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert)))
}

// fakeAPI implements agentAPI in-memory.
type fakeAPI struct {
	principals    map[string][]string
	principalsErr error
	renewCert     string
	renewErr      error
	bundle        string
	bundleCalls   atomic.Int32
	renewCalls    atomic.Int32
	mtlsCalls     atomic.Int32
	mtlsErr       error
	beatCalls     atomic.Int32
	beatErr       error

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

func (f *fakeAPI) Heartbeat(context.Context) error {
	f.beatCalls.Add(1)
	return f.beatErr
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

// newTestDaemon builds a Daemon with a fake API and temp directories.
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
		t.Errorf("default missing: %v", loaded.BundleInterval)
	}
}

func TestLoadConfigMissing(t *testing.T) {
	if _, err := LoadConfig(t.TempDir()); err == nil {
		t.Fatal("expected error")
	}
}

func TestLoadConfigIncomplete(t *testing.T) {
	stateDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(stateDir, "config.yaml"), []byte("host_id: x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(stateDir); err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("expected incomplete error, got %v", err)
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

	// No file ⇒ renew.
	if !needsRenewal(certPath, time.Now()) {
		t.Error("missing file must trigger renewal")
	}
	// Garbage ⇒ renew.
	_ = os.WriteFile(certPath, []byte("garbage"), 0o600)
	if !needsRenewal(certPath, time.Now()) {
		t.Error("unparsable certificate must trigger renewal")
	}
	// Fresh (10% elapsed) ⇒ do not renew.
	_ = os.WriteFile(certPath, []byte(testSignedHostCert(t, 3*24*time.Hour)), 0o600)
	if needsRenewal(certPath, time.Now()) {
		t.Error("fresh certificate must not be renewed")
	}
	// 80% elapsed ⇒ renew.
	_ = os.WriteFile(certPath, []byte(testSignedHostCert(t, 24*24*time.Hour)), 0o600)
	if !needsRenewal(certPath, time.Now()) {
		t.Error("2/3 of validity exceeded must trigger renewal")
	}
}

func TestRenewIfNeeded(t *testing.T) {
	api := &fakeAPI{renewCert: testSignedHostCert(t, 0)}
	d := newTestDaemon(t, api)
	// Create the host key (Renew sends it to the API).
	_ = os.WriteFile(d.cfg.SSHKeyPath, []byte("ssh-ed25519 AAAA host"), 0o600)

	d.renewIfNeeded(context.Background())
	if api.renewCalls.Load() != 1 {
		t.Fatalf("renewCalls = %d", api.renewCalls.Load())
	}
	raw, err := os.ReadFile(HostCertPath(d.cfg.SSHKeyPath))
	if err != nil || !strings.HasPrefix(string(raw), "ssh-ed25519-cert") {
		t.Fatalf("certificate not written: %v %q", err, raw)
	}
	// Second run: certificate fresh ⇒ no further call.
	d.renewIfNeeded(context.Background())
	if api.renewCalls.Load() != 1 {
		t.Errorf("fresh certificate renewed again (calls=%d)", api.renewCalls.Load())
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
	// Unchanged ⇒ no rewrite needed (only the API call counts up).
	d.refreshBundle(context.Background())
	if api.bundleCalls.Load() != 2 {
		t.Errorf("bundleCalls = %d", api.bundleCalls.Load())
	}
}

func TestPrincipalsCacheAndFailClosed(t *testing.T) {
	api := &fakeAPI{principals: map[string][]string{"deploy": {"alice", "alice@example.com"}}}
	d := newTestDaemon(t, api)
	ctx := context.Background()

	// First fetch: from the API, gets cached + persisted.
	got, err := d.principals(ctx, "deploy")
	if err != nil || len(got) != 2 {
		t.Fatalf("principals: %v %v", got, err)
	}
	if _, err := os.Stat(d.paths.CacheFile()); err != nil {
		t.Errorf("cache not persisted: %v", err)
	}

	// API goes down: fresh cache (within TTL) keeps serving.
	api.principalsErr = errors.New("api down")
	got, err = d.principals(ctx, "deploy")
	if err != nil || len(got) != 2 {
		t.Fatalf("cache fallback: %v %v", got, err)
	}

	// Cache expired ⇒ fail-closed.
	d.mu.Lock()
	entry := d.cache["deploy"]
	entry.FetchedAt = time.Now().Add(-time.Duration(d.cfg.CacheTTL) - time.Minute)
	d.cache["deploy"] = entry
	d.mu.Unlock()
	if _, err := d.principals(ctx, "deploy"); err == nil {
		t.Fatal("expected fail-closed (cache expired, api down)")
	}

	// Unknown user without a cache ⇒ fail-closed.
	if _, err := d.principals(ctx, "root"); err == nil {
		t.Fatal("expected fail-closed (no cache)")
	}
}

func TestDaemonSocketAndHelper(t *testing.T) {
	api := &fakeAPI{
		principals: map[string][]string{"deploy": {"alice"}},
		bundle:     "ssh-ed25519 AAAA ca\n",
		renewCert:  testSignedHostCert(t, 0),
	}
	d := newTestDaemon(t, api)
	_ = os.WriteFile(d.cfg.SSHKeyPath, []byte("ssh-ed25519 AAAA host"), 0o600)
	// Config on disk so the helper can load it.
	if err := writeConfig(d.paths, d.cfg); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()

	// Wait until the socket responds.
	waitForSocket(t, d.cfg.SocketPath)

	var stdout bytes.Buffer
	if err := PrintPrincipals(ctx, d.paths.StateDir, "deploy", 0, "", &stdout); err != nil {
		t.Fatalf("PrintPrincipals: %v", err)
	}
	if strings.TrimSpace(stdout.String()) != "alice" {
		t.Errorf("stdout = %q", stdout.String())
	}

	// Fail-closed via the helper: unknown user, API down.
	api.principalsErr = errors.New("api down")
	var out2 bytes.Buffer
	if err := PrintPrincipals(ctx, d.paths.StateDir, "root", 0, "", &out2); err == nil {
		t.Fatal("expected fail-closed")
	}
	if out2.Len() != 0 {
		t.Errorf("fail-closed must not output anything: %q", out2.String())
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("daemon: %v", err)
	}
}

// TestDaemonHeartbeat: an idle agent must still be visible — the other loops
// only reach the API once an hour (bundle) or at 2/3 of a certificate's
// lifetime. A failing heartbeat is pure observability and must not touch the
// authorization path.
func TestDaemonHeartbeat(t *testing.T) {
	api := &fakeAPI{
		principals: map[string][]string{"deploy": {"alice"}},
		bundle:     "ssh-ed25519 AAAA ca\n",
		renewCert:  testSignedHostCert(t, 0),
		beatErr:    errors.New("server unreachable"),
	}
	d := newTestDaemon(t, api)
	d.cfg.HeartbeatInterval = Duration(20 * time.Millisecond)
	_ = os.WriteFile(d.cfg.SSHKeyPath, []byte("ssh-ed25519 AAAA host"), 0o600)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()
	waitForSocket(t, d.cfg.SocketPath)

	// At startup, then every interval.
	deadline := time.Now().Add(2 * time.Second)
	for api.beatCalls.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := api.beatCalls.Load(); got < 2 {
		t.Errorf("heartbeats = %d, expected one at startup and at least one on the ticker", got)
	}
	if got, err := d.principals(ctx, "deploy"); err != nil || len(got) != 1 {
		t.Errorf("failing heartbeat disturbed the principals path: %v %v", got, err)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("daemon: %v", err)
	}
}

func TestPrintPrincipalsWithoutDaemon(t *testing.T) {
	stateDir := t.TempDir()
	cfg := &Config{
		AgentURL: "https://x", HostID: "id", HostName: "h",
		SSHKeyPath: "/etc/ssh/k.pub",
		SocketPath: filepath.Join(stateDir, "missing.sock"),
	}
	cfg.applyDefaults(Paths{StateDir: stateDir})
	if err := writeConfig(Paths{StateDir: stateDir}, cfg); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	if err := PrintPrincipals(context.Background(), stateDir, "deploy", 0, "", &stdout); err == nil {
		t.Fatal("expected error (daemon not running)")
	}
}

func TestPrintPrincipalsWithoutUser(t *testing.T) {
	if err := PrintPrincipals(context.Background(), t.TempDir(), "", 0, "", io.Discard); err == nil {
		t.Fatal("expected error (missing user)")
	}
}

// waitForSocket polls until the daemon socket responds.
func waitForSocket(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("daemon socket did not come up")
}

func TestRunCLI(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := Run(&stdout, &stderr, nil); got != 2 {
		t.Errorf("no args = %d", got)
	}
	if got := Run(&stdout, &stderr, []string{"doesnotexist"}); got != 2 {
		t.Errorf("unknown = %d", got)
	}
	stdout.Reset()
	if got := Run(&stdout, &stderr, []string{"version"}); got != 0 || !strings.Contains(stdout.String(), "guided-ssh") {
		t.Errorf("version = %d %q", got, stdout.String())
	}
	stdout.Reset()
	if got := Run(&stdout, &stderr, []string{"help"}); got != 0 || !strings.Contains(stdout.String(), "commands") {
		t.Errorf("help = %d", got)
	}
	if got := Run(&stdout, &stderr, []string{"enroll", "--doesnotexist"}); got != 2 {
		t.Errorf("enroll flag error = %d", got)
	}
	if got := Run(&stdout, &stderr, []string{"enroll"}); got != 1 {
		t.Errorf("enroll without required flags = %d", got)
	}
	if got := Run(&stdout, &stderr, []string{"run", "-state-dir", t.TempDir()}); got != 1 {
		t.Errorf("run without enrollment = %d", got)
	}
	if got := Run(&stdout, &stderr, []string{"principals", "-state-dir", t.TempDir(), "-user", "x"}); got != 1 {
		t.Errorf("principals without enrollment = %d", got)
	}
	if got := Run(&stdout, &stderr, []string{"enroll", "-tags", "broken", "-server", "x", "-agent-url", "y", "-token", "z"}); got != 2 {
		t.Errorf("broken tags = %d", got)
	}
}

// fakeEnrollServer answers POST /v1/enroll like the real server (token
// "tok-1"; anything else ⇒ 403).
func fakeEnrollServer(t *testing.T) *httptest.Server {
	t.Helper()
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
	return server
}

// TestEnrollAgainstFakeServer: complete enroll flow against an HTTP fake —
// checks the written files, the snippet content, and that enrollment
// activates the configuration instead of only writing it.
func TestEnrollAgainstFakeServer(t *testing.T) {
	server := fakeEnrollServer(t)

	stateDir := t.TempDir()
	sshDir := testSSHDir(t)
	keyPath := filepath.Join(sshDir, "ssh_host_ed25519_key.pub")
	if err := os.WriteFile(keyPath, []byte("ssh-ed25519 AAAA host\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	reloadMarker := filepath.Join(t.TempDir(), "reloaded")

	var stdout bytes.Buffer
	err := Enroll(context.Background(), EnrollOptions{
		ServerURL: server.URL, AgentURL: "https://gssh:8443", Token: "tok-1",
		Hostname: "web1.example.com", StateDir: stateDir, SSHDir: sshDir, SSHKeyPath: keyPath,
		Tags:          map[string]string{"env": "prod"},
		ReloadCommand: "touch " + reloadMarker,
		sshdBinary:    stubSSHD(t, "1", 0), // nothing listening ⇒ probe inconclusive
	}, &stdout)
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	// The reload really ran, and it is persisted for the renewal path — an
	// empty reload_command leaves sshd on the old certificate after renewal.
	if _, err := os.Stat(reloadMarker); err != nil {
		t.Errorf("enrollment did not reload sshd: %v", err)
	}

	// State files.
	for _, f := range []string{"config.yaml", "agent.key", "agent.crt", "server-ca.pem"} {
		if _, err := os.Stat(filepath.Join(stateDir, f)); err != nil {
			t.Errorf("%s missing: %v", f, err)
		}
	}
	cfg, err := LoadConfig(stateDir)
	if err != nil || cfg.HostID != "11111111-2222-3333-4444-555555555555" {
		t.Errorf("config: %+v %v", cfg, err)
	}
	if cfg.ReloadCommand == "" {
		t.Error("reload_command not persisted — renewals would leave sshd on the old certificate")
	}

	// sshd files.
	if _, err := os.Stat(HostCertPath(keyPath)); err != nil {
		t.Errorf("host certificate missing: %v", err)
	}
	snippet, err := os.ReadFile(SnippetPath(sshDir))
	if err != nil {
		t.Fatalf("snippet: %v", err)
	}
	for _, want := range []string{"TrustedUserCAKeys", "HostCertificate", "AuthorizedPrincipalsCommand", "principals -state-dir " + stateDir} {
		if !strings.Contains(string(snippet), want) {
			t.Errorf("snippet missing %q:\n%s", want, snippet)
		}
	}

	// Wrong token ⇒ error.
	err = Enroll(context.Background(), EnrollOptions{
		ServerURL: server.URL, AgentURL: "https://gssh:8443", Token: "wrong",
		Hostname: "x", StateDir: t.TempDir(), SSHDir: sshDir, SSHKeyPath: keyPath,
	}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("expected 403, got %v", err)
	}
}

// TestEnrollWithoutInclude: without the Include the snippet would never be
// read — enrollment must fail before the token is spent.
func TestEnrollWithoutInclude(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	t.Cleanup(server.Close)

	sshDir := t.TempDir()
	if err := os.WriteFile(SSHDConfigPath(sshDir), []byte("PasswordAuthentication no\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := Enroll(context.Background(), EnrollOptions{
		ServerURL: server.URL, AgentURL: "https://gssh:8443", Token: "tok-1",
		Hostname: "web1.example.com", StateDir: t.TempDir(), SSHDir: sshDir,
		SSHKeyPath: filepath.Join(sshDir, "ssh_host_ed25519_key.pub"),
	}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "Include") {
		t.Fatalf("expected Include error, got %v", err)
	}
	if requests.Load() != 0 {
		t.Errorf("the token was spent despite the failure (%d requests)", requests.Load())
	}
}

// TestEnrollKeepsPreviousReloadCommand: re-enrolling on a host whose init
// system is no longer detectable must not silently drop the reload command —
// renewals would stop reaching sshd one certificate lifetime later.
func TestEnrollKeepsPreviousReloadCommand(t *testing.T) {
	server := fakeEnrollServer(t)
	sshDir := testSSHDir(t)
	stateDir := t.TempDir()
	keyPath := filepath.Join(sshDir, "ssh_host_ed25519_key.pub")
	if err := os.WriteFile(keyPath, []byte("ssh-ed25519 AAAA host\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// State of an earlier enrollment.
	paths := Paths{StateDir: stateDir}
	previous := &Config{
		AgentURL: "https://gssh:8443", HostID: "old", HostName: "web1.example.com",
		SSHKeyPath: keyPath, ReloadCommand: "true",
	}
	previous.applyDefaults(paths)
	if err := writeConfig(paths, previous); err != nil {
		t.Fatal(err)
	}

	// No service manager on PATH ⇒ nothing detected; sh stays reachable so
	// the carried-over command can still run.
	binDir := t.TempDir()
	if err := os.Symlink("/bin/sh", filepath.Join(binDir, "sh")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir)
	err := Enroll(context.Background(), EnrollOptions{
		ServerURL: server.URL, AgentURL: "https://gssh:8443", Token: "tok-1",
		Hostname: "web1.example.com", StateDir: stateDir, SSHDir: sshDir, SSHKeyPath: keyPath,
		sshdBinary: stubSSHD(t, "1", 0),
	}, io.Discard)
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	cfg, err := LoadConfig(stateDir)
	if err != nil || cfg.ReloadCommand != "true" {
		t.Fatalf("reload_command = %q (%v), want the carried-over value", cfg.ReloadCommand, err)
	}
}

// TestEnrollRollsBackInvalidConfig: a snippet sshd rejects would take the
// daemon down on its next restart — it must not survive the failure.
func TestEnrollRollsBackInvalidConfig(t *testing.T) {
	server := fakeEnrollServer(t)
	sshDir := testSSHDir(t)
	keyPath := filepath.Join(sshDir, "ssh_host_ed25519_key.pub")
	if err := os.WriteFile(keyPath, []byte("ssh-ed25519 AAAA host\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := Enroll(context.Background(), EnrollOptions{
		ServerURL: server.URL, AgentURL: "https://gssh:8443", Token: "tok-1",
		Hostname: "web1.example.com", StateDir: t.TempDir(), SSHDir: sshDir, SSHKeyPath: keyPath,
		NoReload:   true,
		sshdBinary: stubSSHD(t, "1", 1), // sshd -t rejects the configuration
	}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("expected rollback error, got %v", err)
	}
	if _, statErr := os.Stat(SnippetPath(sshDir)); !os.IsNotExist(statErr) {
		t.Errorf("snippet survived an invalid configuration: %v", statErr)
	}
}

func TestEnrollWithoutHostKey(t *testing.T) {
	err := Enroll(context.Background(), EnrollOptions{
		ServerURL: "http://127.0.0.1:1", AgentURL: "https://x", Token: "t",
		Hostname: "h", StateDir: t.TempDir(), SSHDir: testSSHDir(t),
		SSHKeyPath: filepath.Join(t.TempDir(), "missing.pub"),
	}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "ssh-host-key") {
		t.Fatalf("expected host-key error, got %v", err)
	}
}
