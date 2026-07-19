package agentd

import (
	"context"
	"encoding/json"
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

// minFresh: jünger gecachte Principals werden ohne API-Roundtrip beantwortet
// (sshd kann pro Login mehrfach fragen).
const minFresh = 10 * time.Second

// apiTimeout begrenzt Principals-Abfragen im Auth-Pfad (sshd wartet).
const apiTimeout = 5 * time.Second

// cacheEntry ist ein Principals-Cache-Eintrag.
type cacheEntry struct {
	Principals []string  `json:"principals"`
	FetchedAt  time.Time `json:"fetched_at"`
}

// Daemon ist der laufende Host-Agent: Zertifikatserneuerung, Bundle-Pflege
// und Principals-Cache mit Unix-Socket für den sshd-Helper.
type Daemon struct {
	cfg    *Config
	paths  Paths
	api    agentAPI
	logger *slog.Logger

	mu    sync.Mutex
	cache map[string]cacheEntry
}

// NewDaemon lädt Konfiguration und mTLS-Material aus dem State-Verzeichnis.
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
	return &Daemon{cfg: cfg, paths: paths, api: client, logger: logger, cache: map[string]cacheEntry{}}, nil
}

// Run startet Socket-Server und Pflege-Schleifen; blockiert bis ctx endet.
func (d *Daemon) Run(ctx context.Context) error {
	d.loadCache()

	listener, err := d.listen()
	if err != nil {
		return err
	}
	server := &http.Server{Handler: d.socketHandler(), ReadHeaderTimeout: 5 * time.Second}
	errCh := make(chan error, 1)
	go func() { errCh <- server.Serve(listener) }()
	d.logger.Info("gssh-agentd gestartet", "socket", d.cfg.SocketPath, "host", d.cfg.HostName)

	// Initiale Pflege, danach periodisch.
	d.refreshBundle(ctx)
	d.renewIfNeeded(ctx)
	renewTicker := time.NewTicker(time.Duration(d.cfg.RenewInterval))
	bundleTicker := time.NewTicker(time.Duration(d.cfg.BundleInterval))
	defer renewTicker.Stop()
	defer bundleTicker.Stop()

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
		case <-bundleTicker.C:
			d.refreshBundle(ctx)
		}
	}
}

// listen öffnet den Unix-Socket (alte Socket-Datei wird ersetzt; 0666, damit
// der AuthorizedPrincipalsCommandUser verbinden kann — der Socket liefert nur
// öffentliche Principals-Listen).
func (d *Daemon) listen() (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(d.cfg.SocketPath), 0o755); err != nil { //nolint:gosec // Socket-Verzeichnis muss für sshd traversierbar sein
		return nil, err
	}
	_ = os.Remove(d.cfg.SocketPath)
	listener, err := net.Listen("unix", d.cfg.SocketPath)
	if err != nil {
		return nil, fmt.Errorf("socket %s öffnen: %w", d.cfg.SocketPath, err)
	}
	if err := os.Chmod(d.cfg.SocketPath, 0o666); err != nil { //nolint:gosec // nur lesende Principals-Auskunft
		_ = listener.Close()
		return nil, err
	}
	return listener, nil
}

// socketHandler bedient den Principals-Helper: Cache-first mit TTL,
// fail-closed wenn API und Cache nicht helfen.
func (d *Daemon) socketHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /principals", func(w http.ResponseWriter, r *http.Request) {
		user := r.URL.Query().Get("user")
		if user == "" {
			http.Error(w, "query-parameter user fehlt", http.StatusBadRequest)
			return
		}
		principals, err := d.principals(r.Context(), user)
		if err != nil {
			// Fail-closed: keine Antwort ⇒ der Helper verweigert den Login.
			d.logger.Warn("principals nicht verfügbar (fail-closed)", "user", user, "error", err)
			http.Error(w, "principals nicht verfügbar", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string][]string{"principals": principals})
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	return mux
}

// principals liefert die Principals eines lokalen Benutzers: frischer Cache
// direkt, sonst API mit kurzem Timeout, bei API-Fehler Cache bis CacheTTL.
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
		d.logger.Warn("api nicht erreichbar — principals aus cache", "user", user, "age", time.Since(entry.FetchedAt))
		return entry.Principals, nil
	}
	return nil, fmt.Errorf("api nicht erreichbar und cache abgelaufen: %w", err)
}

// renewIfNeeded erneuert das Host-Zertifikat, sobald 2/3 der Laufzeit
// verstrichen sind (oder keines existiert).
func (d *Daemon) renewIfNeeded(ctx context.Context) {
	certPath := HostCertPath(d.cfg.SSHKeyPath)
	if !needsRenewal(certPath, time.Now()) {
		return
	}
	publicKey, err := os.ReadFile(d.cfg.SSHKeyPath)
	if err != nil {
		d.logger.Error("host-key lesen fehlgeschlagen", "path", d.cfg.SSHKeyPath, "error", err)
		return
	}
	certLine, err := d.api.Renew(ctx, strings.TrimSpace(string(publicKey)))
	if err != nil {
		d.logger.Error("zertifikat erneuern fehlgeschlagen", "error", err)
		return
	}
	if err := os.WriteFile(certPath, []byte(certLine+"\n"), 0o644); err != nil { //nolint:gosec // öffentliches Zertifikat
		d.logger.Error("zertifikat schreiben fehlgeschlagen", "path", certPath, "error", err)
		return
	}
	d.logger.Info("host-zertifikat erneuert", "path", certPath)
	d.runReloadCommand()
}

// needsRenewal: kein Zertifikat, nicht parsebar oder 2/3 der Laufzeit vorbei.
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

// refreshBundle hält die TrustedUserCAKeys-Datei aktuell (nur bei Änderung
// schreiben; sshd liest die Datei bei jeder Authentifizierung neu).
func (d *Daemon) refreshBundle(ctx context.Context) {
	bundle, err := d.api.Bundle(ctx)
	if err != nil {
		d.logger.Warn("ca-bundle abrufen fehlgeschlagen", "error", err)
		return
	}
	path := UserCAPath(d.cfg.SSHDir)
	current, _ := os.ReadFile(path)
	if string(current) == bundle {
		return
	}
	if err := os.WriteFile(path, []byte(bundle), 0o644); err != nil { //nolint:gosec // öffentliche CA-Keys
		d.logger.Error("ca-bundle schreiben fehlgeschlagen", "path", path, "error", err)
		return
	}
	d.logger.Info("user-ca-bundle aktualisiert", "path", path)
}

// runReloadCommand führt das konfigurierte Reload-Kommando aus (sshd liest
// HostCertificate nur beim Start).
func (d *Daemon) runReloadCommand() {
	if d.cfg.ReloadCommand == "" {
		return
	}
	cmd := exec.Command("sh", "-c", d.cfg.ReloadCommand) //nolint:gosec // bewusst konfigurierbar (root-eigene config, 0600)
	if out, err := cmd.CombinedOutput(); err != nil {
		d.logger.Error("reload-kommando fehlgeschlagen", "cmd", d.cfg.ReloadCommand, "error", err, "output", string(out))
	}
}

// certTime wandelt SSH-Zertifikatszeiten (uint64) in time.Time (siehe
// internal/cli — hier dupliziert statt geteilt, beide Nutzer sind klein).
func certTime(sec uint64) time.Time {
	const maxCertUnix = 1 << 40
	if sec > maxCertUnix {
		sec = maxCertUnix
	}
	return time.Unix(int64(sec), 0) //nolint:gosec // durch maxCertUnix begrenzt
}

// loadCache lädt den persistierten Principals-Cache (Fail-closed-Puffer über
// Neustarts hinweg).
func (d *Daemon) loadCache() {
	raw, err := os.ReadFile(d.paths.CacheFile())
	if err != nil {
		return
	}
	var cache map[string]cacheEntry
	if err := json.Unmarshal(raw, &cache); err != nil {
		d.logger.Warn("principals-cache unlesbar — ignoriert", "error", err)
		return
	}
	d.mu.Lock()
	d.cache = cache
	d.mu.Unlock()
}

// persistCache schreibt den Cache auf Platte (Best Effort).
func (d *Daemon) persistCache() {
	d.mu.Lock()
	raw, err := json.Marshal(d.cache)
	d.mu.Unlock()
	if err != nil {
		return
	}
	if err := os.WriteFile(d.paths.CacheFile(), raw, 0o600); err != nil {
		d.logger.Warn("principals-cache schreiben fehlgeschlagen", "error", err)
	}
}
