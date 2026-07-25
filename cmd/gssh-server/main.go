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
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/guided-traffic/guided-ssh/internal/agentdist"
	"github.com/guided-traffic/guided-ssh/internal/api"
	"github.com/guided-traffic/guided-ssh/internal/auditstream"
	"github.com/guided-traffic/guided-ssh/internal/auth"
	"github.com/guided-traffic/guided-ssh/internal/ca"
	"github.com/guided-traffic/guided-ssh/internal/metrics"
	"github.com/guided-traffic/guided-ssh/internal/pintls"
	"github.com/guided-traffic/guided-ssh/internal/store"
	"github.com/guided-traffic/guided-ssh/internal/version"
)

// Umgebungsvariablen des Servers (Werte kommen im Kubernetes-Deployment
// aus Secrets, siehe Plan Phase 11).
const (
	// PostgreSQL-Verbindung: einzelne Variablen statt einer DSN, damit die
	// Werte 1:1 aus einem Kubernetes-Secret kommen können (z. B. dem
	// App-Secret von CloudNativePG) — kein zusammengesetztes DSN-Secret nötig.
	envDBHost     = "GSSH_DB_HOST"     // Pflicht
	envDBPort     = "GSSH_DB_PORT"     // leer ⇒ 5432 (Treiber-Default)
	envDBUser     = "GSSH_DB_USER"     // Pflicht
	envDBPassword = "GSSH_DB_PASSWORD" //nolint:gosec // Name der Env-Variable, kein Secret; Pflicht
	envDBName     = "GSSH_DB_NAME"     // Pflicht (Datenbank-Name)
	envDBSSLMode  = "GSSH_DB_SSLMODE"  // leer ⇒ prefer (Treiber-Default)

	envMasterKey = "GSSH_CA_MASTER_KEY" // Base64, 32 Bytes (AES-256)

	// Source of the CA key material (SELF_MANAGED_CA.md, D2/D3): "managed"
	// (default) keeps the keys encrypted in the database, "self-managed" takes
	// all three CAs from mounted files and never writes private key material to
	// the database. The four key-file variables belong to self-managed mode and
	// must be unset in managed mode.
	envCAMode         = "GSSH_CA_MODE"           // managed | self-managed; leer ⇒ managed
	envCAUserKeyFile  = "GSSH_CA_USER_KEY_FILE"  // OpenSSH private key PEM
	envCAHostKeyFile  = "GSSH_CA_HOST_KEY_FILE"  // OpenSSH private key PEM
	envCAMTLSKeyFile  = "GSSH_CA_MTLS_KEY_FILE"  //nolint:gosec // Name der Env-Variable, kein Secret; PKCS#8 PEM
	envCAMTLSCertFile = "GSSH_CA_MTLS_CERT_FILE" // X.509 CA certificate PEM

	// OIDC (Phase 3); ohne Issuer bleibt der Sign-Endpoint deaktiviert (503).
	envOIDCIssuer   = "GSSH_OIDC_ISSUER"    // Issuer-URL des IdP
	envOIDCClientID = "GSSH_OIDC_CLIENT_ID" // erwartete Audience der ID-Tokens

	// GitLab-CI (Phase 7); ohne Issuer bleibt /v1/sign/ci deaktiviert (503).
	envCIIssuer   = "GSSH_CI_ISSUER"   // GitLab-Basis-URL (OIDC-Issuer)
	envCIAudience = "GSSH_CI_AUDIENCE" // erwartete Audience, Default guided-ssh

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

	// Web-UI-Rollen (Phase 8): Auditor darf Audit-Log lesen/exportieren,
	// Read-only die Ressourcen-Ansichten; Admin schließt beides ein.
	envAuditorGroup  = "GSSH_AUDITOR_GROUP"
	envReadOnlyGroup = "GSSH_READONLY_GROUP"

	// OIDC-Client der Web-UI; Default ist die Client-ID aus
	// GSSH_OIDC_CLIENT_ID. Mit gesetztem Client-Secret führt der Server den
	// Login selbst aus (BFF: Authorization Code + PKCE + Secret, Session-
	// Cookie); ohne Secret bleiben die /v1/auth-Endpunkte deaktiviert.
	envUIOIDCClientID     = "GSSH_UI_OIDC_CLIENT_ID"
	envUIOIDCClientSecret = "GSSH_UI_OIDC_CLIENT_SECRET" //nolint:gosec // Name der Env-Variable, kein Secret
	envUIOIDCScopes       = "GSSH_UI_OIDC_SCOPES"        // Komma-getrennt; Default openid,profile,email,groups
	envUIBaseURL          = "GSSH_UI_BASE_URL"           // externe Basis-URL der UI; leer = aus Request ableiten
	envUISessionTTL       = "GSSH_UI_SESSION_TTL"        // Go-Duration, Default 12h

	// Audit-Streaming (Phase 8): committete Audit-Events als strukturierte
	// JSON-Logs (SIEM) und optional an einen Webhook.
	envAuditStream         = "GSSH_AUDIT_STREAM"          // "true" aktiviert Log-Streaming
	envAuditWebhookURL     = "GSSH_AUDIT_WEBHOOK_URL"     // optionaler Webhook
	envAuditStreamInterval = "GSSH_AUDIT_STREAM_INTERVAL" // Go-Duration, Default 10s

	// Rate-Limiting der Sign-/Enroll-Endpunkte (Phase 10): Requests bzw.
	// erlaubte Fehlversuche (401/403) pro Client-IP und Minute; "0" bei
	// GSSH_SIGN_RATE_PER_MINUTE deaktiviert das Rate-Limiting komplett.
	envRatePerMinute = "GSSH_SIGN_RATE_PER_MINUTE" // Default 60
	envFailPerMinute = "GSSH_SIGN_FAIL_PER_MINUTE" // Default 10
	envRateTrustXFF  = "GSSH_RATE_TRUST_PROXY"     // "true": Client-IP aus X-Forwarded-For

	// Laufzeit ausgestellter Host-Zertifikate (Enrollment + Renew); Go-Duration,
	// leer = 30 Tage. Kurze Werte machen die Rotation testbar (E2E, Phase 13).
	envHostCertValidity = "GSSH_HOST_CERT_VALIDITY"

	// One-Command-Host-Install: externe URLs und Pin-Quellen. Fehlt eine
	// Voraussetzung, bleibt der Host-Rollout deaktiviert (503) — nie ungepinnt.
	envPublicURL        = "GSSH_PUBLIC_URL"           // externe Public-Basis-URL; leer ⇒ Fallback GSSH_UI_BASE_URL
	envAgentPublicURL   = "GSSH_AGENT_PUBLIC_URL"     // externe mTLS-Agent-URL; wird nie abgeleitet
	envPublicPin        = "GSSH_PUBLIC_PIN"           // Pin-Quelle 1: statischer Base64-SPKI-Pin
	envPublicPinCert    = "GSSH_PUBLIC_PIN_CERT_FILE" // Pin-Quelle 2: PEM-Zertifikat (erster Block = Leaf)
	envPublicPinRefresh = "GSSH_PUBLIC_PIN_REFRESH"   // Refresh-Intervall des Selbst-Dials, Default 5m
)

// defaultSyncInterval ist das Standard-Intervall des Gruppen-Syncs.
const defaultSyncInterval = 5 * time.Minute

// defaultUISessionTTL ist die Standard-Lebensdauer der UI-Session; solange
// bleiben die Gruppen-Claims des Logins wirksam (vergleichbar mit der
// bisherigen ID-Token-Laufzeit). Deaktivierte Benutzer blockt der Server
// unabhängig davon bei jedem Request.
const defaultUISessionTTL = 12 * time.Hour

// defaultUIScopes sind die OIDC-Scopes des UI-Logins; groups liefert die
// Gruppen-Claims für das Rollen-Mapping (Dex gibt sie nur auf Anfrage heraus).
var defaultUIScopes = []string{"openid", "profile", "email", "groups"}

// hostCertValidityFromEnv parst GSSH_HOST_CERT_VALIDITY; leer ⇒ 0 (Default
// 30 Tage in internal/api). Ungültige Werte sind ein Konfigurationsfehler
// (fail-fast statt still 30-Tage-Zertifikate auszustellen).
func hostCertValidityFromEnv() (time.Duration, error) {
	raw := os.Getenv(envHostCertValidity)
	if raw == "" {
		return 0, nil
	}
	validity, err := time.ParseDuration(raw)
	if err != nil || validity <= 0 {
		return 0, fmt.Errorf("%s: ungültige dauer %q (go-duration > 0 erwartet)", envHostCertValidity, raw)
	}
	return validity, nil
}

// publicBaseURL liefert die externe Basis-URL des Public-Listeners:
// GSSH_PUBLIC_URL, ersatzweise die UI-Basis-URL. Leer ⇒ Rollout-Gate zu.
func publicBaseURL() string {
	base := os.Getenv(envPublicURL)
	if base == "" {
		base = os.Getenv(envUIBaseURL)
	}
	return strings.TrimSuffix(base, "/")
}

// pinConfigFromEnv baut die Pin-Konfiguration des Host-Rollouts. Ein
// ungültiger statischer Pin oder ein unbrauchbares Refresh-Intervall ist ein
// Konfigurationsfehler und bricht den Start ab (fail-fast wie bei
// GSSH_HOST_CERT_VALIDITY) — still ohne Pin weiterzulaufen wäre die
// gefährlichere Variante.
func pinConfigFromEnv() (api.PinProviderConfig, error) {
	cfg := api.PinProviderConfig{
		StaticPin: os.Getenv(envPublicPin),
		CertFile:  os.Getenv(envPublicPinCert),
		DialURL:   publicBaseURL(),
	}
	if cfg.StaticPin != "" {
		if _, err := pintls.DecodePin(cfg.StaticPin); err != nil {
			return api.PinProviderConfig{}, fmt.Errorf("%s: %w", envPublicPin, err)
		}
	}
	if raw := os.Getenv(envPublicPinRefresh); raw != "" {
		refresh, err := time.ParseDuration(raw)
		if err != nil || refresh <= 0 {
			return api.PinProviderConfig{}, fmt.Errorf("%s: ungültige dauer %q (go-duration > 0 erwartet)", envPublicPinRefresh, raw)
		}
		cfg.Refresh = refresh
	}
	return cfg, nil
}

// Betriebsmodi der CA-Keys (GSSH_CA_MODE).
const (
	caModeManaged     = "managed"
	caModeSelfManaged = "self-managed"
)

// caModeFromEnv parses GSSH_CA_MODE and the key-file variables and enforces the
// validation matrix of SELF_MANAGED_CA.md (D2): the modes are exclusive, so
// self-managed needs all four key files and managed must have none of them —
// a half-configured deployment fails at startup instead of silently ignoring
// mounted keys. Errors name every offending variable at once.
func caModeFromEnv() (string, ca.ExternalKeyPaths, error) {
	mode := os.Getenv(envCAMode)
	if mode == "" {
		mode = caModeManaged
	}
	if mode != caModeManaged && mode != caModeSelfManaged {
		return "", ca.ExternalKeyPaths{}, fmt.Errorf("%s: unknown mode %q (expected %q or %q)",
			envCAMode, mode, caModeManaged, caModeSelfManaged)
	}
	paths := ca.ExternalKeyPaths{
		UserKeyFile:  os.Getenv(envCAUserKeyFile),
		HostKeyFile:  os.Getenv(envCAHostKeyFile),
		MTLSKeyFile:  os.Getenv(envCAMTLSKeyFile),
		MTLSCertFile: os.Getenv(envCAMTLSCertFile),
	}
	keyFiles := []struct{ env, path string }{
		{envCAUserKeyFile, paths.UserKeyFile},
		{envCAHostKeyFile, paths.HostKeyFile},
		{envCAMTLSKeyFile, paths.MTLSKeyFile},
		{envCAMTLSCertFile, paths.MTLSCertFile},
	}
	var missing, unexpected []string
	for _, f := range keyFiles {
		switch {
		case mode == caModeSelfManaged && f.path == "":
			missing = append(missing, f.env)
		case mode == caModeManaged && f.path != "":
			unexpected = append(unexpected, f.env)
		}
	}
	if len(missing) > 0 {
		return "", ca.ExternalKeyPaths{}, fmt.Errorf(
			"%s=%s requires all four ca key files, not set: %s",
			envCAMode, caModeSelfManaged, strings.Join(missing, ", "))
	}
	if len(unexpected) > 0 {
		return "", ca.ExternalKeyPaths{}, fmt.Errorf(
			"ca mode %s does not use mounted ca keys, but these are set: %s — unset them or set %s=%s",
			caModeManaged, strings.Join(unexpected, ", "), envCAMode, caModeSelfManaged)
	}
	return mode, paths, nil
}

func main() {
	os.Exit(run(os.Stdout, os.Stderr, os.Args[1:]))
}

// run enthält die eigentliche Logik, damit sie testbar bleibt; main ist nur ein
// dünner Wrapper um Exit-Code-Handling.
func run(stdout, stderr io.Writer, args []string) int {
	if len(args) > 0 && args[0] == "enroll-token" {
		return runEnrollToken(stdout, stderr, args[1:])
	}
	if len(args) > 0 && args[0] == "migrate" {
		return runMigrate(stdout, stderr)
	}
	if len(args) > 0 && args[0] == "gen-mtls-ca" {
		return runGenMTLSCA(stdout, stderr, args[1:])
	}

	fs := flag.NewFlagSet("gssh-server", flag.ContinueOnError)
	fs.SetOutput(stderr)
	showVersion := fs.Bool("version", false, "Version ausgeben und beenden")
	listen := fs.String("listen", "", "Listen-Adresse der HTTP-API (z. B. :8080); leer = nicht starten")
	agentListen := fs.String("agent-listen", "", "Listen-Adresse der Agent-API mit mTLS (z. B. :8443); leer = deaktiviert")
	metricsListen := fs.String("metrics-listen", "", "Listen-Adresse des Prometheus-Endpoints /metrics (z. B. :9090); leer = deaktiviert")
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
	if err := serve(logger, *listen, *agentListen, *metricsListen); err != nil {
		logger.Error("serverstart fehlgeschlagen", "error", err)
		return 1
	}
	return 0
}

// dbConnString baut die PostgreSQL-Verbindungs-URL aus den einzelnen
// GSSH_DB_*-Variablen. Benutzer und Passwort werden URL-escaped — Sonderzeichen
// im Passwort sind damit unkritisch. Port und SSL-Mode sind optional und
// fallen auf die Treiber-Defaults zurück (5432 bzw. prefer).
func dbConnString() (string, error) {
	var missing []string
	for _, v := range []string{envDBHost, envDBUser, envDBPassword, envDBName} {
		if os.Getenv(v) == "" {
			missing = append(missing, v)
		}
	}
	if len(missing) > 0 {
		return "", fmt.Errorf("datenbank-konfiguration unvollständig: %s nicht gesetzt", strings.Join(missing, ", "))
	}
	host := os.Getenv(envDBHost)
	if port := os.Getenv(envDBPort); port != "" {
		host = net.JoinHostPort(host, port)
	}
	u := &url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(os.Getenv(envDBUser), os.Getenv(envDBPassword)),
		Host:   host,
		Path:   "/" + os.Getenv(envDBName),
	}
	if sslmode := os.Getenv(envDBSSLMode); sslmode != "" {
		u.RawQuery = url.Values{"sslmode": {sslmode}}.Encode()
	}
	return u.String(), nil
}

// runMigrate wendet die Datenbank-Migrationen an und beendet sich (Subkommando
// `gssh-server migrate`, für den Init-Container im Kubernetes-Deployment,
// Plan Phase 11). Konkurrierende Läufe serialisiert ein Advisory-Lock.
func runMigrate(stdout, stderr io.Writer) int {
	dsn, err := dbConnString()
	if err != nil {
		fmt.Fprintf(stderr, "gssh-server: %v\n", err)
		return 2
	}
	if err := store.Migrate(context.Background(), dsn); err != nil {
		fmt.Fprintf(stderr, "gssh-server: migrationen: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, "migrationen angewendet")
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

// runGenMTLSCA generates the agent mTLS CA for self-managed deployments
// (subcommand `gssh-server gen-mtls-ca`): the operator commits the result
// SOPS-encrypted and mounts it via GSSH_CA_MTLS_KEY_FILE/GSSH_CA_MTLS_CERT_FILE.
// No database is involved — the CA never enters this process' store.
func runGenMTLSCA(stdout, stderr io.Writer, args []string) int {
	fs := flag.NewFlagSet("gssh-server gen-mtls-ca", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "", "output prefix; writes <prefix>.key (PKCS#8, mode 0600) and <prefix>.crt")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *out == "" {
		fmt.Fprintln(stderr, "gssh-server: gen-mtls-ca: -out is required (e.g. -out mtls-ca)")
		return 2
	}

	certPEM, keyPEM, err := ca.GenerateMTLSCA()
	if err != nil {
		fmt.Fprintf(stderr, "gssh-server: %v\n", err)
		return 1
	}
	keyPath, certPath := *out+".key", *out+".crt"
	if err := writeNewFile(keyPath, keyPEM, 0o600); err != nil {
		fmt.Fprintf(stderr, "gssh-server: %v\n", err)
		return 1
	}
	if err := writeNewFile(certPath, certPEM, 0o644); err != nil {
		// A private key without its certificate is useless — don't leave it behind.
		_ = os.Remove(keyPath)
		fmt.Fprintf(stderr, "gssh-server: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "%s\n%s\n", keyPath, certPath)
	fmt.Fprintf(stderr, "mtls ca written (%s: %s, %s: %s) — %s is ca private key material, encrypt it before committing\n",
		envCAMTLSKeyFile, keyPath, envCAMTLSCertFile, certPath, keyPath)
	return 0
}

// writeNewFile writes data to path and refuses to overwrite an existing file
// (O_EXCL): re-running gen-mtls-ca must never silently replace a CA that hosts
// already trust.
func writeNewFile(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if errors.Is(err, os.ErrExist) {
		return fmt.Errorf("%s already exists — refusing to overwrite ca material", path)
	}
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	return f.Close()
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

// serve startet die HTTP-API, optional die Agent-API (mTLS), den
// Metrics-Endpoint und ggf. den Gruppen-Sync; blockiert bis SIGINT/SIGTERM.
func serve(logger *slog.Logger, listen, agentListen, metricsListen string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	certAuthority, st, err := setup(ctx)
	if err != nil {
		return err
	}
	defer st.Close()

	hostCertValidity, err := hostCertValidityFromEnv()
	if err != nil {
		return err
	}

	uiClientID := os.Getenv(envUIOIDCClientID)
	if uiClientID == "" {
		uiClientID = os.Getenv(envOIDCClientID)
	}
	verifier, ciVerifier, uiAuth, err := setupVerifiers(ctx, logger, uiClientID)
	if err != nil {
		return err
	}
	startGroupSync(ctx, st, logger)

	adminGroup := os.Getenv(envAdminGroup)
	if adminGroup == "" {
		logger.Warn("admin-api nicht konfiguriert — grant-verwaltung deaktiviert", "env", envAdminGroup)
	}
	startAuditStream(ctx, st, logger)

	pinCfg, err := pinConfigFromEnv()
	if err != nil {
		return err
	}
	pins := api.NewPinProvider(pinCfg, logger)
	go pins.Run(ctx)

	server := &http.Server{
		Addr: listen,
		Handler: api.New(api.Deps{
			CA: certAuthority, Store: st, Hosts: st, Grants: st, Admin: st, UI: st,
			Verifier: verifier, CIVerifier: ciVerifier, CIStore: st,
			RateLimit:        setupRateLimit(logger),
			HostCertValidity: hostCertValidity,
			Logger:           logger, AdminGroup: adminGroup,
			AuditorGroup:  os.Getenv(envAuditorGroup),
			ReadOnlyGroup: os.Getenv(envReadOnlyGroup),
			UIConfig: api.UIConfig{
				OIDCIssuer:   os.Getenv(envOIDCIssuer),
				OIDCClientID: uiClientID,
			},
			UIAuth: uiAuth,
			// Host-Rollout (One-Command-Install): Binaries aus dem Image, Pin
			// und externe URLs. Fehlt etwas, bleibt das Gate zu (503).
			Agents:         agentdist.New(),
			Pins:           pins,
			AgentPublicURL: strings.TrimSuffix(os.Getenv(envAgentPublicURL), "/"),
			PublicBaseURL:  publicBaseURL(),
		}),
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 3)
	go func() { errCh <- server.ListenAndServe() }()
	logger.Info("gssh-server gestartet", "listen", listen, "version", version.String())

	var agentServer *http.Server
	if agentListen != "" {
		agentServer, err = newAgentServer(ctx, certAuthority, st, logger, agentListen, hostCertValidity)
		if err != nil {
			return err
		}
		go func() { errCh <- agentServer.ListenAndServeTLS("", "") }()
		logger.Info("agent-api gestartet (mtls)", "listen", agentListen)
	}

	// Metrics auf eigenem Listener: wird nicht über den Ingress exponiert,
	// sondern nur vom Prometheus-Scraper erreicht (Phase 11).
	var metricsServer *http.Server
	if metricsListen != "" {
		metricsMux := http.NewServeMux()
		metricsMux.Handle("GET /metrics", metrics.Handler())
		metricsServer = &http.Server{Addr: metricsListen, Handler: metricsMux, ReadHeaderTimeout: 10 * time.Second}
		go func() { errCh <- metricsServer.ListenAndServe() }()
		logger.Info("metrics-endpoint gestartet", "listen", metricsListen)
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
		if metricsServer != nil {
			_ = metricsServer.Shutdown(shutdownCtx)
		}
		return server.Shutdown(shutdownCtx)
	}
}

// newAgentServer baut den mTLS-Server der Agent-API: Server-Zertifikat aus
// der eigenen mTLS-CA, Client-Zertifikate werden gegen dieselbe CA verlangt
// und verifiziert.
func newAgentServer(ctx context.Context, certAuthority *ca.CA, st *store.Store, logger *slog.Logger, listen string, hostCertValidity time.Duration) (*http.Server, error) {
	// In self-managed mode the mTLS CA comes from the mounted files and was
	// already adopted by setup(); the bootstrap refuses to run there.
	if !certAuthority.SelfManaged() {
		if err := certAuthority.EnsureMTLSCA(ctx); err != nil {
			return nil, fmt.Errorf("mtls-ca bootstrappen: %w", err)
		}
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
		Handler: api.NewAgent(api.AgentDeps{CA: certAuthority, Hosts: st, Sessions: st, Logger: logger, HostCertValidity: hostCertValidity}),
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
// Issuer bleibt der Sign-Endpoint deaktiviert. Eine fehlende Client-ID ist
// ein Konfigurationsfehler (fail-fast statt Ablehnung aller Tokens zur
// Laufzeit — Security-Review Phase 10).
func setupOIDC(ctx context.Context, logger *slog.Logger) (api.TokenVerifier, error) {
	issuer := os.Getenv(envOIDCIssuer)
	if issuer == "" {
		logger.Warn("oidc nicht konfiguriert — /v1/sign/user deaktiviert", "env", envOIDCIssuer)
		return nil, nil //nolint:nilnil // nil-Interface schaltet den Endpoint gezielt ab
	}
	clientID := os.Getenv(envOIDCClientID)
	if clientID == "" {
		return nil, fmt.Errorf("%s ist gesetzt, aber %s fehlt — ohne erwartete audience ist keine token-validierung möglich", envOIDCIssuer, envOIDCClientID)
	}
	verifier, err := auth.NewVerifier(ctx, auth.VerifierConfig{
		IssuerURL: issuer,
		ClientID:  clientID,
	})
	if err != nil {
		return nil, err
	}
	logger.Info("oidc konfiguriert", "issuer", issuer)
	return verifier, nil
}

// setupVerifiers bündelt die OIDC-Konfiguration des Servers: Benutzer- und
// CI-Token-Verifier, Audience-Separation und den server-seitigen UI-Login.
func setupVerifiers(ctx context.Context, logger *slog.Logger, uiClientID string) (api.TokenVerifier, api.CITokenVerifier, *api.UIAuthConfig, error) {
	verifier, err := setupOIDC(ctx, logger)
	if err != nil {
		return nil, nil, nil, err
	}
	ciVerifier, err := setupCIOIDC(ctx, logger)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := checkAudienceSeparation(); err != nil {
		return nil, nil, nil, err
	}
	uiAuth, err := setupUIAuth(ctx, logger, uiClientID)
	if err != nil {
		return nil, nil, nil, err
	}
	return verifier, ciVerifier, uiAuth, nil
}

// setupUIAuth baut die Konfiguration des server-seitigen UI-Logins (BFF),
// falls ein Client-Secret gesetzt ist; ohne Secret bleiben die
// /v1/auth-Endpunkte deaktiviert (503). Der Session-Schlüssel wird aus dem
// CA-Master-Key abgeleitet — kein zusätzliches Secret nötig.
func setupUIAuth(ctx context.Context, logger *slog.Logger, clientID string) (*api.UIAuthConfig, error) {
	secret := os.Getenv(envUIOIDCClientSecret)
	if secret == "" {
		logger.Warn("ui-login nicht konfiguriert — /v1/auth deaktiviert", "env", envUIOIDCClientSecret)
		return nil, nil //nolint:nilnil // nil-Config schaltet die Endpunkte gezielt ab
	}
	issuer := os.Getenv(envOIDCIssuer)
	if issuer == "" {
		return nil, fmt.Errorf("%s ist gesetzt, aber %s fehlt", envUIOIDCClientSecret, envOIDCIssuer)
	}
	if clientID == "" {
		return nil, fmt.Errorf("%s ist gesetzt, aber %s fehlt", envUIOIDCClientSecret, envOIDCClientID)
	}
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("ui-login: oidc-discovery für %s: %w", issuer, err)
	}
	// Eigener Verifier: die Audience der UI-Tokens ist die UI-Client-ID,
	// die von GSSH_OIDC_CLIENT_ID abweichen kann.
	verifier, err := auth.NewVerifier(ctx, auth.VerifierConfig{IssuerURL: issuer, ClientID: clientID})
	if err != nil {
		return nil, err
	}
	masterKey, err := base64.StdEncoding.DecodeString(os.Getenv(envMasterKey))
	if err != nil {
		return nil, fmt.Errorf("%s dekodieren: %w", envMasterKey, err)
	}
	codec, err := auth.NewSessionCodec(masterKey)
	if err != nil {
		return nil, err
	}
	scopes := defaultUIScopes
	if raw := os.Getenv(envUIOIDCScopes); raw != "" {
		scopes = strings.Split(raw, ",")
		for i := range scopes {
			scopes[i] = strings.TrimSpace(scopes[i])
		}
	}
	sessionTTL := defaultUISessionTTL
	if raw := os.Getenv(envUISessionTTL); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil || parsed <= 0 {
			return nil, fmt.Errorf("%s: ungültige dauer %q (go-duration > 0 erwartet)", envUISessionTTL, raw)
		}
		sessionTTL = parsed
	}
	logger.Info("ui-login konfiguriert (server-seitiges oidc)", "issuer", issuer, "client_id", clientID, "session_ttl", sessionTTL)
	return &api.UIAuthConfig{
		OAuth: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: secret,
			Endpoint:     provider.Endpoint(),
			Scopes:       scopes,
		},
		Verifier:   verifier,
		Codec:      codec,
		BaseURL:    strings.TrimSuffix(os.Getenv(envUIBaseURL), "/"),
		SessionTTL: sessionTTL,
	}, nil
}

// setupRateLimit baut den Rate-Limiter der Sign-/Enroll-Endpunkte aus der
// Umgebung; GSSH_SIGN_RATE_PER_MINUTE=0 deaktiviert ihn bewusst (Lasttests).
func setupRateLimit(logger *slog.Logger) *api.RateLimiter {
	cfg := api.DefaultRateLimiterConfig()
	if raw := os.Getenv(envRatePerMinute); raw != "" {
		parsed, err := strconv.ParseFloat(raw, 64)
		switch {
		case err != nil || parsed < 0:
			logger.Warn("ungültige rate, nutze default", "env", envRatePerMinute, "value", raw)
		case parsed == 0:
			logger.Warn("rate-limiting der sign-/enroll-endpunkte deaktiviert", "env", envRatePerMinute)
			return nil
		default:
			cfg.RequestsPerMinute = parsed
			cfg.Burst = max(10, parsed/3)
		}
	}
	if raw := os.Getenv(envFailPerMinute); raw != "" {
		if parsed, err := strconv.ParseFloat(raw, 64); err == nil && parsed > 0 {
			cfg.FailuresPerMinute = parsed
			cfg.FailureBurst = parsed
		} else {
			logger.Warn("ungültige fehlversuchs-rate, nutze default", "env", envFailPerMinute, "value", raw)
		}
	}
	cfg.TrustProxyHeader = os.Getenv(envRateTrustXFF) == "true"
	return api.NewRateLimiter(cfg)
}

// checkAudienceSeparation verhindert Audience-Confusion (Security-Review
// Phase 10): laufen Benutzer-OIDC und GitLab-CI gegen denselben Issuer,
// müssen sich die erwarteten Audiences unterscheiden — sonst wären Benutzer-
// und CI-Tokens an beiden Endpunkten austauschbar.
func checkAudienceSeparation() error {
	issuer := os.Getenv(envOIDCIssuer)
	if issuer == "" || issuer != os.Getenv(envCIIssuer) {
		return nil
	}
	ciAudience := os.Getenv(envCIAudience)
	if ciAudience == "" {
		ciAudience = auth.DefaultCIAudience
	}
	if ciAudience == os.Getenv(envOIDCClientID) {
		return fmt.Errorf("gleicher issuer und gleiche audience für benutzer-oidc und gitlab-ci (%s/%s) — tokens wären an beiden sign-endpunkten austauschbar", envOIDCClientID, envCIAudience)
	}
	return nil
}

// setupCIOIDC baut den Verifier für GitLab-Job-Tokens, falls konfiguriert;
// ohne Issuer bleibt /v1/sign/ci deaktiviert.
func setupCIOIDC(ctx context.Context, logger *slog.Logger) (api.CITokenVerifier, error) {
	issuer := os.Getenv(envCIIssuer)
	if issuer == "" {
		logger.Warn("gitlab-ci nicht konfiguriert — /v1/sign/ci deaktiviert", "env", envCIIssuer)
		return nil, nil //nolint:nilnil // nil-Interface schaltet den Endpoint gezielt ab
	}
	verifier, err := auth.NewCIVerifier(ctx, auth.CIVerifierConfig{
		IssuerURL: issuer,
		Audience:  os.Getenv(envCIAudience),
	})
	if err != nil {
		return nil, err
	}
	logger.Info("gitlab-ci konfiguriert", "issuer", issuer)
	return verifier, nil
}

// startAuditStream startet das Audit-Streaming (strukturierte JSON-Logs auf
// stdout und/oder Webhook), falls konfiguriert.
func startAuditStream(ctx context.Context, st *store.Store, logger *slog.Logger) {
	streamLogs := os.Getenv(envAuditStream) == "true"
	webhookURL := os.Getenv(envAuditWebhookURL)
	if !streamLogs && webhookURL == "" {
		return
	}
	cfg := auditstream.Config{Logger: logger, LogEvents: streamLogs, WebhookURL: webhookURL}
	if raw := os.Getenv(envAuditStreamInterval); raw != "" {
		if parsed, err := time.ParseDuration(raw); err == nil && parsed > 0 {
			cfg.Interval = parsed
		} else {
			logger.Warn("ungültiges audit-stream-intervall, nutze default", "value", raw)
		}
	}
	streamer := auditstream.New(st, cfg)
	go streamer.Run(ctx)
	logger.Info("audit-streaming gestartet", "logs", streamLogs, "webhook", webhookURL != "")
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

// setupStore baut die Verbindungs-URL aus der Umgebung, migriert die
// Datenbank und öffnet den Store.
func setupStore(ctx context.Context) (*store.Store, error) {
	dsn, err := dbConnString()
	if err != nil {
		return nil, err
	}
	if err := store.Migrate(ctx, dsn); err != nil {
		return nil, fmt.Errorf("migrationen: %w", err)
	}
	return store.New(ctx, dsn)
}

// setup liest die Einstellungen aus der Umgebung, migriert die Datenbank und
// bootstrapt die CA (inkl. CA-Keys, falls noch keine existieren).
// In self-managed mode the mounted key files replace the bootstrap: they are
// loaded before the database is touched and adopted afterwards (D2/D4).
// GSSH_CA_MASTER_KEY stays mandatory in both modes (D7).
func setup(ctx context.Context) (*ca.CA, *store.Store, error) {
	masterKey, err := base64.StdEncoding.DecodeString(os.Getenv(envMasterKey))
	if err != nil {
		return nil, nil, fmt.Errorf("%s dekodieren: %w", envMasterKey, err)
	}
	mode, keyPaths, err := caModeFromEnv()
	if err != nil {
		return nil, nil, err
	}
	var opts []ca.Option
	if mode == caModeSelfManaged {
		keys, err := ca.LoadExternalKeys(keyPaths)
		if err != nil {
			return nil, nil, err
		}
		opts = append(opts, ca.WithExternalKeys(keys))
	}
	st, err := setupStore(ctx)
	if err != nil {
		return nil, nil, err
	}
	certAuthority, err := ca.New(st, masterKey, ca.NewPolicyEngine(ca.DefaultPolicies()), opts...)
	if err != nil {
		st.Close()
		return nil, nil, err
	}
	if certAuthority.SelfManaged() {
		if err := certAuthority.AdoptExternalKeys(ctx); err != nil {
			st.Close()
			return nil, nil, fmt.Errorf("adopt external ca keys: %w", err)
		}
		return certAuthority, st, nil
	}
	if err := certAuthority.EnsureCAKeys(ctx); err != nil {
		st.Close()
		return nil, nil, fmt.Errorf("ca-keys bootstrappen: %w", err)
	}
	return certAuthority, st, nil
}
