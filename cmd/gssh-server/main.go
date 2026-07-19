// gssh-server ist der API-Server von guided-ssh (CA, OIDC-Endpunkte, Host-API, UI).
// Phase 2: CA-Bootstrap (Migrationen, CA-Keys) und CA-Bundle-Endpoint;
// Phase 3: OIDC-Token-Validierung, POST /v1/sign/user, Gruppen-Sync.
package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/guided-traffic/guided-ssh/internal/api"
	"github.com/guided-traffic/guided-ssh/internal/auth"
	"github.com/guided-traffic/guided-ssh/internal/ca"
	"github.com/guided-traffic/guided-ssh/internal/store"
	"github.com/guided-traffic/guided-ssh/internal/version"
)

// Umgebungsvariablen des Servers (Werte kommen im Kubernetes-Deployment
// aus Secrets, siehe Plan Phase 11).
const (
	envDSN       = "GSSH_DB_DSN"
	envMasterKey = "GSSH_CA_MASTER_KEY" // Base64, 32 Bytes (AES-256)

	// OIDC (Phase 3); ohne Issuer bleibt der Sign-Endpoint deaktiviert (503).
	envOIDCIssuer   = "GSSH_OIDC_ISSUER"    // Issuer-URL des IdP
	envOIDCClientID = "GSSH_OIDC_CLIENT_ID" // erwartete Audience der ID-Tokens

	// Gruppen-Sync via Keycloak-Admin-API (optional; ohne Client-ID deaktiviert).
	envKCBaseURL      = "GSSH_KC_BASE_URL"      // Keycloak-Basis-URL
	envKCRealm        = "GSSH_KC_REALM"         // Realm
	envKCClientID     = "GSSH_KC_CLIENT_ID"     // Service-Account-Client
	envKCClientSecret = "GSSH_KC_CLIENT_SECRET" //nolint:gosec // Name der Env-Variable, kein Secret
	envSyncInterval   = "GSSH_KC_SYNC_INTERVAL" // Go-Duration, Default 5m
)

// defaultSyncInterval ist das Standard-Intervall des Gruppen-Syncs.
const defaultSyncInterval = 5 * time.Minute

func main() {
	os.Exit(run(os.Stdout, os.Stderr, os.Args[1:]))
}

// run enthält die eigentliche Logik, damit sie testbar bleibt; main ist nur ein
// dünner Wrapper um Exit-Code-Handling.
func run(stdout, stderr io.Writer, args []string) int {
	fs := flag.NewFlagSet("gssh-server", flag.ContinueOnError)
	fs.SetOutput(stderr)
	showVersion := fs.Bool("version", false, "Version ausgeben und beenden")
	listen := fs.String("listen", "", "Listen-Adresse der HTTP-API (z. B. :8080); leer = nicht starten")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *showVersion {
		fmt.Fprintln(stdout, version.String())
		return 0
	}

	if *listen == "" {
		fmt.Fprintln(stderr, "gssh-server: -listen fehlt (z. B. -listen :8080)")
		return 2
	}

	logger := slog.New(slog.NewJSONHandler(stdout, nil))
	if err := serve(logger, *listen); err != nil {
		logger.Error("serverstart fehlgeschlagen", "error", err)
		return 1
	}
	return 0
}

// serve startet die HTTP-API (und ggf. den Gruppen-Sync) und blockiert bis
// SIGINT/SIGTERM.
func serve(logger *slog.Logger, listen string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	certAuthority, st, err := setup(ctx)
	if err != nil {
		return err
	}
	defer st.Close()

	verifier, err := setupOIDC(ctx, logger)
	if err != nil {
		return err
	}
	startGroupSync(ctx, st, logger)

	server := &http.Server{
		Addr:              listen,
		Handler:           api.New(api.Deps{CA: certAuthority, Store: st, Verifier: verifier, Logger: logger}),
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() { errCh <- server.ListenAndServe() }()
	logger.Info("gssh-server gestartet", "listen", listen, "version", version.String())

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	}
}

// setupOIDC baut den Token-Verifier, falls OIDC konfiguriert ist; ohne
// Issuer bleibt der Sign-Endpoint deaktiviert.
func setupOIDC(ctx context.Context, logger *slog.Logger) (api.TokenVerifier, error) {
	issuer := os.Getenv(envOIDCIssuer)
	if issuer == "" {
		logger.Warn("oidc nicht konfiguriert — /v1/sign/user deaktiviert", "env", envOIDCIssuer)
		return nil, nil //nolint:nilnil // nil-Interface schaltet den Endpoint gezielt ab
	}
	verifier, err := auth.NewVerifier(ctx, auth.VerifierConfig{
		IssuerURL: issuer,
		ClientID:  os.Getenv(envOIDCClientID),
	})
	if err != nil {
		return nil, err
	}
	logger.Info("oidc konfiguriert", "issuer", issuer)
	return verifier, nil
}

// startGroupSync startet den periodischen Gruppen-Sync via
// Keycloak-Admin-API, falls konfiguriert.
func startGroupSync(ctx context.Context, st *store.Store, logger *slog.Logger) {
	clientID := os.Getenv(envKCClientID)
	if clientID == "" {
		logger.Warn("gruppen-sync nicht konfiguriert — offboarding wirkt nur über token-ablauf", "env", envKCClientID)
		return
	}
	interval := defaultSyncInterval
	if raw := os.Getenv(envSyncInterval); raw != "" {
		if parsed, err := time.ParseDuration(raw); err == nil && parsed > 0 {
			interval = parsed
		} else {
			logger.Warn("ungültiges sync-intervall, nutze default", "value", raw, "default", interval)
		}
	}
	source := auth.NewKeycloakSource(ctx, auth.KeycloakConfig{
		BaseURL:      os.Getenv(envKCBaseURL),
		Realm:        os.Getenv(envKCRealm),
		ClientID:     clientID,
		ClientSecret: os.Getenv(envKCClientSecret),
	})
	syncer := auth.NewSyncer(st, source, logger)
	go syncer.Run(ctx, interval)
	logger.Info("gruppen-sync gestartet", "issuer", source.Issuer(), "interval", interval)
}

// setup liest die Einstellungen aus der Umgebung, migriert die Datenbank und
// bootstrapt die CA (inkl. CA-Keys, falls noch keine existieren).
func setup(ctx context.Context) (*ca.CA, *store.Store, error) {
	dsn := os.Getenv(envDSN)
	if dsn == "" {
		return nil, nil, fmt.Errorf("%s nicht gesetzt", envDSN)
	}
	masterKey, err := base64.StdEncoding.DecodeString(os.Getenv(envMasterKey))
	if err != nil {
		return nil, nil, fmt.Errorf("%s dekodieren: %w", envMasterKey, err)
	}

	if err := store.Migrate(ctx, dsn); err != nil {
		return nil, nil, fmt.Errorf("migrationen: %w", err)
	}
	st, err := store.New(ctx, dsn)
	if err != nil {
		return nil, nil, err
	}
	certAuthority, err := ca.New(st, masterKey, ca.NewPolicyEngine(ca.DefaultPolicies()))
	if err != nil {
		st.Close()
		return nil, nil, err
	}
	if err := certAuthority.EnsureCAKeys(ctx); err != nil {
		st.Close()
		return nil, nil, fmt.Errorf("ca-keys bootstrappen: %w", err)
	}
	return certAuthority, st, nil
}
