package agentd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// minFresh: principals cached more recently than this are answered without
// an API roundtrip (sshd can ask multiple times per login).
const minFresh = 10 * time.Second

// apiTimeout bounds principals lookups on the auth path (sshd is waiting).
const apiTimeout = 5 * time.Second

// cacheEntry is a principals cache entry.
type cacheEntry struct {
	Principals []string  `json:"principals"`
	FetchedAt  time.Time `json:"fetched_at"`
}

// Daemon is the running host agent: certificate renewal, bundle maintenance,
// and principals cache with a unix socket for the sshd helper.
type Daemon struct {
	cfg    *Config
	paths  Paths
	api    agentAPI
	logger *slog.Logger

	mu         sync.Mutex
	cache      map[string]cacheEntry
	recentAuth map[string][]authRec // guarded by mu; serial→session correlation (phase 9)

	// token protects the writable socket endpoints; empty ⇒ session audit off.
	token   string
	spoolMu sync.Mutex // serializes access to the spool file
}

// NewDaemon loads the configuration and mTLS material from the state directory.
func NewDaemon(stateDir string, logger *slog.Logger) (*Daemon, error) {
	cfg, err := LoadConfig(stateDir)
	if err != nil {
		return nil, err
	}
	paths := Paths{StateDir: stateDir}
	client, err := newAPIClient(cfg, paths)
	if err != nil {
		return nil, err
	}
	d := &Daemon{
		cfg: cfg, paths: paths, api: client, logger: logger,
		cache:      map[string]cacheEntry{},
		recentAuth: map[string][]authRec{},
	}
	if cfg.SessionAudit {
		d.token = readSocketToken(stateDir)
	}
	return d, nil
}

// sessionAuditEnabled is true when session audit is active and the token is loaded.
func (d *Daemon) sessionAuditEnabled() bool {
	return d.cfg.SessionAudit && d.token != ""
}

// Run starts the socket server and maintenance loops; blocks until ctx ends.
func (d *Daemon) Run(ctx context.Context) error {
	d.loadCache()

	listener, err := d.listen()
	if err != nil {
		return err
	}
	server := &http.Server{Handler: d.socketHandler(), ReadHeaderTimeout: 5 * time.Second}
	errCh := make(chan error, 1)
	go func() { errCh <- server.Serve(listener) }()
	d.logger.Info("gssh-agentd started", "socket", d.cfg.SocketPath, "host", d.cfg.HostName)

	// Initial maintenance, then periodic. The heartbeat goes out right away
	// so a restarted agent is visible without waiting a full interval.
	d.refreshBundle(ctx)
	d.renewIfNeeded(ctx)
	d.rotateMTLSIfNeeded(ctx)
	d.heartbeat(ctx)
	renewTicker := time.NewTicker(time.Duration(d.cfg.RenewInterval))
	bundleTicker := time.NewTicker(time.Duration(d.cfg.BundleInterval))
	heartbeatTicker := time.NewTicker(time.Duration(d.cfg.HeartbeatInterval))
	defer renewTicker.Stop()
	defer bundleTicker.Stop()
	defer heartbeatTicker.Stop()

	// Session flush only with audit enabled; otherwise a dead channel.
	var flushC <-chan time.Time
	if d.sessionAuditEnabled() {
		flushTicker := time.NewTicker(sessionFlushInterval)
		defer flushTicker.Stop()
		flushC = flushTicker.C
		d.flushSpool(ctx) // work off any backlog from a previous run immediately
	}

	for {
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			return server.Shutdown(shutdownCtx)
		case err := <-errCh:
			return err
		case <-renewTicker.C:
			d.renewIfNeeded(ctx)
			d.rotateMTLSIfNeeded(ctx)
		case <-bundleTicker.C:
			d.refreshBundle(ctx)
		case <-heartbeatTicker.C:
			d.heartbeat(ctx)
		case <-flushC:
			d.flushSpool(ctx)
		}
	}
}

// listen opens the unix socket (an old socket file is replaced; 0666 so
// AuthorizedPrincipalsCommandUser can connect — the socket only serves
// public principals lists).
func (d *Daemon) listen() (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(d.cfg.SocketPath), 0o755); err != nil { //nolint:gosec // socket directory must be traversable for sshd
		return nil, err
	}
	_ = os.Remove(d.cfg.SocketPath)
	listener, err := net.Listen("unix", d.cfg.SocketPath)
	if err != nil {
		return nil, fmt.Errorf("opening socket %s: %w", d.cfg.SocketPath, err)
	}
	if err := os.Chmod(d.cfg.SocketPath, 0o666); err != nil { //nolint:gosec // read-only principals lookup only
		_ = listener.Close()
		return nil, err
	}
	return listener, nil
}

// socketHandler serves the principals helper: cache-first with TTL,
// fail-closed when neither the API nor the cache can help.
func (d *Daemon) socketHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /principals", func(w http.ResponseWriter, r *http.Request) {
		user := r.URL.Query().Get("user")
		if user == "" {
			http.Error(w, "missing query parameter user", http.StatusBadRequest)
			return
		}
		principals, err := d.principals(r.Context(), user)
		if err != nil {
			// Fail-closed: no response ⇒ the helper denies the login.
			d.logger.Warn("principals unavailable (fail-closed)", "user", user, "error", err)
			http.Error(w, "principals unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string][]string{"principals": principals})
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	if d.sessionAuditEnabled() {
		mux.HandleFunc("POST /auth", d.handleAuth)
		mux.HandleFunc("POST /session-event", d.handleSessionEvent)
	}
	return mux
}

// principals returns the principals of a local user: fresh cache directly,
// otherwise the API with a short timeout, and on API error the cache until
// CacheTTL.
func (d *Daemon) principals(ctx context.Context, user string) ([]string, error) {
	d.mu.Lock()
	entry, cached := d.cache[user]
	d.mu.Unlock()
	if cached && time.Since(entry.FetchedAt) < minFresh {
		return entry.Principals, nil
	}

	apiCtx, cancel := context.WithTimeout(ctx, apiTimeout)
	defer cancel()
	principals, err := d.api.Principals(apiCtx, user)
	if err == nil {
		d.mu.Lock()
		d.cache[user] = cacheEntry{Principals: principals, FetchedAt: time.Now()}
		d.mu.Unlock()
		d.persistCache()
		return principals, nil
	}
	if cached && time.Since(entry.FetchedAt) < time.Duration(d.cfg.CacheTTL) {
		d.logger.Warn("api unreachable — serving principals from cache", "user", user, "age", time.Since(entry.FetchedAt))
		return entry.Principals, nil
	}
	return nil, fmt.Errorf("api unreachable and cache expired: %w", err)
}

// renewIfNeeded renews the host certificate once 2/3 of its validity has
// elapsed (or none exists).
func (d *Daemon) renewIfNeeded(ctx context.Context) {
	certPath := HostCertPath(d.cfg.SSHKeyPath)
	if !needsRenewal(certPath, time.Now()) {
		return
	}
	publicKey, err := os.ReadFile(d.cfg.SSHKeyPath)
	if err != nil {
		d.logger.Error("reading host key failed", "path", d.cfg.SSHKeyPath, "error", err)
		return
	}
	certLine, err := d.api.Renew(ctx, strings.TrimSpace(string(publicKey)))
	if err != nil {
		d.logger.Error("renewing certificate failed", "error", err)
		return
	}
	if err := os.WriteFile(certPath, []byte(certLine+"\n"), 0o644); err != nil { //nolint:gosec // public certificate
		d.logger.Error("writing certificate failed", "path", certPath, "error", err)
		return
	}
	d.logger.Info("host certificate renewed", "path", certPath)
	d.runReloadCommand()
}

// needsRenewal: no certificate, unparsable, or 2/3 of validity elapsed.
func needsRenewal(certPath string, now time.Time) bool {
	raw, err := os.ReadFile(certPath)
	if err != nil {
		return true
	}
	parsed, _, _, _, err := ssh.ParseAuthorizedKey(raw)
	if err != nil {
		return true
	}
	cert, ok := parsed.(*ssh.Certificate)
	if !ok {
		return true
	}
	validAfter := certTime(cert.ValidAfter)
	validBefore := certTime(cert.ValidBefore)
	renewAt := validAfter.Add(validBefore.Sub(validAfter) * 2 / 3)
	return now.After(renewAt)
}

// rotateMTLSIfNeeded rotates the mTLS client certificate once 2/3 of its
// validity has elapsed (phase 10): submit a fresh key pair + CSR over the
// still-valid mTLS channel, replace the files, switch the client over.
// Errors are non-critical — the old certificate stays valid until the next
// check (RenewInterval).
func (d *Daemon) rotateMTLSIfNeeded(ctx context.Context) {
	if !mtlsNeedsRotation(d.paths.AgentCertFile(), time.Now()) {
		return
	}
	priv, csrPEM, err := newMTLSKeyAndCSR()
	if err != nil {
		d.logger.Error("mtls rotation: generating key failed", "error", err)
		return
	}
	certPEM, err := d.api.RenewMTLS(ctx, string(csrPEM))
	if err != nil {
		d.logger.Error("mtls rotation: renewal failed", "error", err)
		return
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		d.logger.Error("mtls rotation: serializing key failed", "error", err)
		return
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	pair, err := tls.X509KeyPair([]byte(certPEM), keyPEM)
	if err != nil {
		d.logger.Error("mtls rotation: server returned an unusable certificate", "error", err)
		return
	}
	// Write the key before the certificate (each atomic via rename); the
	// tiny window of an inconsistent pair is healed by the next rotation run.
	if err := writeFileAtomic(d.paths.AgentKeyFile(), keyPEM, 0o600); err != nil {
		d.logger.Error("mtls rotation: writing key failed", "error", err)
		return
	}
	if err := writeFileAtomic(d.paths.AgentCertFile(), []byte(certPEM), 0o644); err != nil {
		d.logger.Error("mtls rotation: writing certificate failed", "error", err)
		return
	}
	if setter, ok := d.api.(interface{ setClientCert(tls.Certificate) }); ok {
		setter.setClientCert(pair)
	}
	d.logger.Info("mtls client certificate rotated", "path", d.paths.AgentCertFile())
}

// mtlsNeedsRotation: 2/3 of validity elapsed — or the file is unreadable, in
// which case a rotation repairs the state via the still-loaded certificate.
func mtlsNeedsRotation(certPath string, now time.Time) bool {
	raw, err := os.ReadFile(certPath)
	if err != nil {
		return true
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return true
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return true
	}
	rotateAt := cert.NotBefore.Add(cert.NotAfter.Sub(cert.NotBefore) * 2 / 3)
	return now.After(rotateAt)
}

// writeFileAtomic writes via a temp file + rename in the same directory.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// refreshBundle keeps the TrustedUserCAKeys file up to date (writes only on
// change; sshd re-reads the file on every authentication).
func (d *Daemon) refreshBundle(ctx context.Context) {
	bundle, err := d.api.Bundle(ctx)
	if err != nil {
		d.logger.Warn("fetching ca bundle failed", "error", err)
		return
	}
	path := UserCAPath(d.cfg.SSHDir)
	current, _ := os.ReadFile(path)
	if string(current) == bundle {
		return
	}
	if err := os.WriteFile(path, []byte(bundle), 0o644); err != nil { //nolint:gosec // public ca keys
		d.logger.Error("writing ca bundle failed", "path", path, "error", err)
		return
	}
	d.logger.Info("user ca bundle updated", "path", path)
}

// heartbeat reports liveness to the server. Failures are logged and
// otherwise ignored: liveness is observability, it must never influence the
// authorization path (principals stay served from cache/API as before).
func (d *Daemon) heartbeat(ctx context.Context) {
	beatCtx, cancel := context.WithTimeout(ctx, apiTimeout)
	defer cancel()
	if err := d.api.Heartbeat(beatCtx); err != nil {
		d.logger.Warn("heartbeat failed", "error", err)
	}
}

// runReloadCommand executes the configured reload command (sshd reads
// HostCertificate only at startup).
func (d *Daemon) runReloadCommand() {
	if d.cfg.ReloadCommand == "" {
		return
	}
	cmd := exec.Command("sh", "-c", d.cfg.ReloadCommand) //nolint:gosec // deliberately configurable (root-owned config, 0600)
	if out, err := cmd.CombinedOutput(); err != nil {
		d.logger.Error("reload command failed", "cmd", d.cfg.ReloadCommand, "error", err, "output", string(out))
	}
}

// certTime converts SSH certificate times (uint64) to time.Time (see
// internal/cli — duplicated here rather than shared, both users are small).
func certTime(sec uint64) time.Time {
	const maxCertUnix = 1 << 40
	if sec > maxCertUnix {
		sec = maxCertUnix
	}
	return time.Unix(int64(sec), 0) //nolint:gosec // bounded by maxCertUnix
}

// loadCache loads the persisted principals cache (fail-closed buffer across restarts).
func (d *Daemon) loadCache() {
	raw, err := os.ReadFile(d.paths.CacheFile())
	if err != nil {
		return
	}
	var cache map[string]cacheEntry
	if err := json.Unmarshal(raw, &cache); err != nil {
		d.logger.Warn("principals cache unreadable — ignored", "error", err)
		return
	}
	d.mu.Lock()
	d.cache = cache
	d.mu.Unlock()
}

// persistCache writes the cache to disk (best effort).
func (d *Daemon) persistCache() {
	d.mu.Lock()
	raw, err := json.Marshal(d.cache)
	d.mu.Unlock()
	if err != nil {
		return
	}
	if err := os.WriteFile(d.paths.CacheFile(), raw, 0o600); err != nil {
		d.logger.Warn("writing principals cache failed", "error", err)
	}
}
