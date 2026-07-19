// gssh-server ist der API-Server von guided-ssh (CA, OIDC-Endpunkte, Host-API, UI).
// Phase 2: CA-Bootstrap (Migrationen, CA-Keys) und CA-Bundle-Endpoint;
// Phase 3: OIDC-Token-Validierung, POST /v1/sign/user, Gruppen-Sync;
// Phase 5: Host-Enrollment (POST /v1/enroll), Agent-API hinter mTLS,
// Subkommando enroll-token;
// Phase 6: Grant-Verwaltung (/v1/admin/grants…, GSSH_ADMIN_GROUP).
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
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

	// Agent-API (Phase 5): SANs des mTLS-Server-Zertifikats, Komma-getrennt.
	envAgentTLSNames = "GSSH_AGENT_TLS_NAMES" // Default: localhost,127.0.0.1

	// Admin-API (Phase 6): IdP-Gruppe der Admins; leer ⇒ Admin-API deaktiviert.
	envAdminGroup = "GSSH_ADMIN_GROUP"
)

// defaultSyncInterval ist das Standard-Intervall des Gruppen-Syncs.
const defaultSyncInterval = 5 * time.Minute

func main() {
	os.Exit(run(os.Stdout, os.Stderr, os.Args[1:]))
}

// run enthält die eigentliche Logik, damit sie testbar bleibt; main ist nur ein
// dünner Wrapper um Exit-Code-Handling.
func run(stdout, stderr io.Writer, args []string) int {
	if len(args) > 0 && args[0] == "enroll-token" {
		return runEnrollToken(stdout, stderr, args[1:])
	}

	fs := flag.NewFlagSet("gssh-server", flag.ContinueOnError)
	fs.SetOutput(stderr)
	showVersion := fs.Bool("version", false, "Version ausgeben und beenden")
	listen := fs.String("listen", "", "Listen-Adresse der HTTP-API (z. B. :8080); leer = nicht starten")
	agentListen := fs.String("agent-listen", "", "Listen-Adresse der Agent-API mit mTLS (z. B. :8443); leer = deaktiviert")
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
	if err := serve(logger, *listen, *agentListen); err != nil {
		logger.Error("serverstart fehlgeschlagen", "error", err)
		return 1
	}
	return 0
}

// runEnrollToken erzeugt ein einmaliges Enrollment-Token (Subkommando
// `gssh-server enroll-token`): Klartext geht nach stdout, in der DB liegt
// nur der Hash.
func runEnrollToken(stdout, stderr io.Writer, args []string) int {
	fs := flag.NewFlagSet("gssh-server enroll-token", flag.ContinueOnError)
	fs.SetOutput(stderr)
	name := fs.String("name", "", "optional: Token an diesen Hostnamen binden")
	tagsFlag := fs.String("tags", "", "Host-Tags, z. B. env=prod,role=web")
	ttl := fs.Duration("ttl", 24*time.Hour, "Gültigkeitsdauer des Tokens")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	tags, err := parseTags(*tagsFlag)
	if err != nil {
		fmt.Fprintf(stderr, "gssh-server: %v\n", err)
		return 2
	}

	ctx := context.Background()
	st, err := setupStore(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "gssh-server: %v\n", err)
		return 1
	}
	defer st.Close()

	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		fmt.Fprintf(stderr, "gssh-server: token erzeugen: %v\n", err)
		return 1
	}
	token := "gssh-et-" + base64.RawURLEncoding.EncodeToString(buf)
	hash := sha256.Sum256([]byte(token))

	record := &store.EnrollmentToken{
		TokenHash: hash[:],
		Tags:      tags,
		ExpiresAt: time.Now().Add(*ttl),
	}
	if *name != "" {
		record.HostName = name
	}
	if err := st.CreateEnrollmentToken(ctx, record); err != nil {
		fmt.Fprintf(stderr, "gssh-server: token speichern: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "%s\n", token)
	fmt.Fprintf(stderr, "einmaliges enrollment-token, gültig bis %s — der klartext wird nicht gespeichert\n",
		record.ExpiresAt.Format(time.RFC3339))
	return 0
}

// parseTags parst "k=v,k2=v2" in eine Map.
func parseTags(raw string) (map[string]string, error) {
	tags := map[string]string{}
	if raw == "" {
		return tags, nil
	}
	for _, pair := range strings.Split(raw, ",") {
		key, value, found := strings.Cut(pair, "=")
		if !found || key == "" {
			return nil, fmt.Errorf("ungültiges tag %q (erwartet key=value)", pair)
		}
		tags[key] = value
	}
	return tags, nil
}

// serve startet die HTTP-API, optional die Agent-API (mTLS) und ggf. den
// Gruppen-Sync; blockiert bis SIGINT/SIGTERM.
func serve(logger *slog.Logger, listen, agentListen string) error {
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

	adminGroup := os.Getenv(envAdminGroup)
	if adminGroup == "" {
		logger.Warn("admin-api nicht konfiguriert — grant-verwaltung deaktiviert", "env", envAdminGroup)
	}
	server := &http.Server{
		Addr: listen,
		Handler: api.New(api.Deps{
			CA: certAuthority, Store: st, Hosts: st, Grants: st, Admin: st,
			Verifier: verifier, Logger: logger, AdminGroup: adminGroup,
		}),
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 2)
	go func() { errCh <- server.ListenAndServe() }()
	logger.Info("gssh-server gestartet", "listen", listen, "version", version.String())

	var agentServer *http.Server
	if agentListen != "" {
		agentServer, err = newAgentServer(ctx, certAuthority, st, logger, agentListen)
		if err != nil {
			return err
		}
		go func() { errCh <- agentServer.ListenAndServeTLS("", "") }()
		logger.Info("agent-api gestartet (mtls)", "listen", agentListen)
	}

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if agentServer != nil {
			_ = agentServer.Shutdown(shutdownCtx)
		}
		return server.Shutdown(shutdownCtx)
	}
}

// newAgentServer baut den mTLS-Server der Agent-API: Server-Zertifikat aus
// der eigenen mTLS-CA, Client-Zertifikate werden gegen dieselbe CA verlangt
// und verifiziert.
func newAgentServer(ctx context.Context, certAuthority *ca.CA, st *store.Store, logger *slog.Logger, listen string) (*http.Server, error) {
	if err := certAuthority.EnsureMTLSCA(ctx); err != nil {
		return nil, fmt.Errorf("mtls-ca bootstrappen: %w", err)
	}
	names := strings.Split(os.Getenv(envAgentTLSNames), ",")
	if os.Getenv(envAgentTLSNames) == "" {
		names = []string{"localhost", "127.0.0.1"}
	}
	serverCert, err := certAuthority.IssueServerCert(ctx, names)
	if err != nil {
		return nil, fmt.Errorf("agent-server-zertifikat: %w", err)
	}
	pool, err := certAuthority.MTLSCAPool(ctx)
	if err != nil {
		return nil, err
	}
	return &http.Server{
		Addr:    listen,
		Handler: api.NewAgent(api.AgentDeps{CA: certAuthority, Hosts: st, Logger: logger}),
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{serverCert},
			ClientCAs:    pool,
			ClientAuth:   tls.RequireAndVerifyClientCert,
		},
		ReadHeaderTimeout: 10 * time.Second,
	}, nil
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

// setupStore liest die DSN aus der Umgebung, migriert die Datenbank und
// öffnet den Store.
func setupStore(ctx context.Context) (*store.Store, error) {
	dsn := os.Getenv(envDSN)
	if dsn == "" {
		return nil, fmt.Errorf("%s nicht gesetzt", envDSN)
	}
	if err := store.Migrate(ctx, dsn); err != nil {
		return nil, fmt.Errorf("migrationen: %w", err)
	}
	return store.New(ctx, dsn)
}

// setup liest die Einstellungen aus der Umgebung, migriert die Datenbank und
// bootstrapt die CA (inkl. CA-Keys, falls noch keine existieren).
func setup(ctx context.Context) (*ca.CA, *store.Store, error) {
	masterKey, err := base64.StdEncoding.DecodeString(os.Getenv(envMasterKey))
	if err != nil {
		return nil, nil, fmt.Errorf("%s dekodieren: %w", envMasterKey, err)
	}
	st, err := setupStore(ctx)
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
