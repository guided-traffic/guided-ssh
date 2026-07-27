// gssh-server is the API server of guided-ssh (CA, OIDC endpoints, host API, UI).
// Phase 2: CA bootstrap (migrations, CA keys) and the CA bundle endpoint;
// Phase 3: OIDC token validation, POST /v1/sign/user, group sync;
// Phase 5: host enrollment (POST /v1/enroll), agent API behind mTLS,
// enroll-token subcommand;
// Phase 6: grant management (/v1/admin/grants…, GSSH_ADMIN_GROUP).
package main

import (
	"context"
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
	"github.com/guided-traffic/guided-ssh/internal/clientdist"
	"github.com/guided-traffic/guided-ssh/internal/metrics"
	"github.com/guided-traffic/guided-ssh/internal/pintls"
	"github.com/guided-traffic/guided-ssh/internal/store"
	"github.com/guided-traffic/guided-ssh/internal/version"
)

// Environment variables of the server (values come from Kubernetes Secrets in
// the deployment, see plan Phase 11).
const (
	// PostgreSQL connection: individual variables instead of a DSN, so the
	// values can come 1:1 from a Kubernetes Secret (e.g. CloudNativePG's app
	// secret) — no need for a combined DSN secret.
	envDBHost     = "GSSH_DB_HOST"     // required
	envDBPort     = "GSSH_DB_PORT"     // empty ⇒ 5432 (driver default)
	envDBUser     = "GSSH_DB_USER"     // required
	envDBPassword = "GSSH_DB_PASSWORD" //nolint:gosec // name of the env var, not a secret; required
	envDBName     = "GSSH_DB_NAME"     // required (database name)
	envDBSSLMode  = "GSSH_DB_SSLMODE"  // empty ⇒ prefer (driver default)

	envMasterKey = "GSSH_CA_MASTER_KEY" // Base64, 32 Bytes (AES-256)

	// Source of the CA key material (SELF_MANAGED_CA.md, D2/D3): "managed"
	// (default) keeps the keys encrypted in the database, "self-managed" takes
	// all three CAs from mounted files and never writes private key material to
	// the database. The four key-file variables belong to self-managed mode and
	// must be unset in managed mode.
	envCAMode         = "GSSH_CA_MODE"           // managed | self-managed; empty ⇒ managed
	envCAUserKeyFile  = "GSSH_CA_USER_KEY_FILE"  // OpenSSH private key PEM
	envCAHostKeyFile  = "GSSH_CA_HOST_KEY_FILE"  // OpenSSH private key PEM
	envCAMTLSKeyFile  = "GSSH_CA_MTLS_KEY_FILE"  //nolint:gosec // name of the env var, not a secret; PKCS#8 PEM
	envCAMTLSCertFile = "GSSH_CA_MTLS_CERT_FILE" // X.509 CA certificate PEM

	// User OIDC (Phase 3); without an issuer the sign endpoint stays disabled
	// (503). The issuer is shared by both OIDC clients: the CLIs' public
	// client (below) and the server's own confidential client (GSSH_SERVER_*).
	envOIDCIssuer         = "GSSH_OIDC_ISSUER"           // issuer URL of the IdP
	envClientOIDCClientID = "GSSH_CLIENT_OIDC_CLIENT_ID" // public client of the gssh/gssh-admin CLIs; expected audience of bearer ID tokens

	// GitLab CI (Phase 7); without an issuer /v1/sign/ci stays disabled (503).
	envCIIssuer   = "GSSH_CI_ISSUER"   // GitLab base URL (OIDC issuer)
	envCIAudience = "GSSH_CI_AUDIENCE" // expected audience, default guided-ssh

	// Group sync via the Keycloak admin API (optional; disabled without a client ID).
	envKCBaseURL      = "GSSH_KC_BASE_URL"      // Keycloak base URL
	envKCRealm        = "GSSH_KC_REALM"         // realm
	envKCClientID     = "GSSH_KC_CLIENT_ID"     // service-account client
	envKCClientSecret = "GSSH_KC_CLIENT_SECRET" //nolint:gosec // name of the env var, not a secret
	envSyncInterval   = "GSSH_KC_SYNC_INTERVAL" // Go duration, default 5m

	// Agent API (Phase 5): SANs of the mTLS server certificate, comma-separated.
	envAgentTLSNames = "GSSH_AGENT_TLS_NAMES" // default: localhost,127.0.0.1

	// Admin API (Phase 6): IdP group of the admins; empty ⇒ admin API disabled.
	envAdminGroup = "GSSH_ADMIN_GROUP"

	// INSECURE developer mode for local frontend development (ng serve):
	// the exact value "insecure" makes every request act as a logged-in
	// admin ("dev") without any IdP. Any other non-empty value is a
	// configuration error (fail-fast, no accidental "true"/"1" activation).
	envDevUIAuth = "GSSH_DEV_UI_AUTH"

	// Web UI roles (Phase 8): auditor may read/export the audit log,
	// read-only the resource views; admin includes both.
	envAuditorGroup  = "GSSH_AUDITOR_GROUP"
	envReadOnlyGroup = "GSSH_READONLY_GROUP"

	// OIDC client of the server itself (confidential, WITH a client secret):
	// the server performs the UI login (BFF: authorization code + PKCE +
	// secret, session cookie). Client ID and secret must be set together;
	// with both empty the /v1/auth endpoints stay disabled. Must be a
	// different IdP client than GSSH_CLIENT_OIDC_CLIENT_ID — the clients
	// authenticate without a secret (public), the server with one.
	envServerOIDCClientID     = "GSSH_SERVER_OIDC_CLIENT_ID"
	envServerOIDCClientSecret = "GSSH_SERVER_OIDC_CLIENT_SECRET" //nolint:gosec // name of the env var, not a secret
	envServerOIDCScopes       = "GSSH_SERVER_OIDC_SCOPES"        // comma-separated; default openid,profile,email,groups
	envUISessionTTL           = "GSSH_UI_SESSION_TTL"            // Go duration, default 12h

	// Audit streaming (Phase 8): committed audit events as structured
	// JSON logs (SIEM) and optionally to a webhook.
	envAuditStream         = "GSSH_AUDIT_STREAM"          // "true" enables log streaming
	envAuditWebhookURL     = "GSSH_AUDIT_WEBHOOK_URL"     // optional webhook
	envAuditStreamInterval = "GSSH_AUDIT_STREAM_INTERVAL" // Go duration, default 10s

	// Rate limiting of the sign/enroll endpoints (Phase 10): requests, and
	// allowed failed attempts (401/403), per client IP and minute; "0" on
	// GSSH_SIGN_RATE_PER_MINUTE disables rate limiting entirely.
	envRatePerMinute = "GSSH_SIGN_RATE_PER_MINUTE" // default 60
	envFailPerMinute = "GSSH_SIGN_FAIL_PER_MINUTE" // default 10
	envRateTrustXFF  = "GSSH_RATE_TRUST_PROXY"     // "true": client IP from X-Forwarded-For

	// Validity of issued host certificates (enrollment + renew); Go duration,
	// empty = 30 days. Short values make rotation testable (E2E, Phase 13).
	envHostCertValidity = "GSSH_HOST_CERT_VALIDITY"

	// One-command host install: external URLs and pin sources. If a
	// prerequisite is missing, host rollout stays disabled (503) — never unpinned.
	envPublicURL        = "GSSH_PUBLIC_URL"           // external public base URL (UI login redirect, install_command, client gate, pin dial)
	envAgentPublicURL   = "GSSH_AGENT_PUBLIC_URL"     // external mTLS agent URL; never derived
	envPublicPin        = "GSSH_PUBLIC_PIN"           // pin source 1: static base64 SPKI pin
	envPublicPinCert    = "GSSH_PUBLIC_PIN_CERT_FILE" // pin source 2: PEM certificate (first block = leaf)
	envPublicPinRefresh = "GSSH_PUBLIC_PIN_REFRESH"   // refresh interval of the self-dial, default 5m
	envAgentDownloadRPM = "GSSH_AGENT_DOWNLOAD_RPM"   // binary downloads per client IP and minute, default 10 ("0" = off)
)

// defaultAgentDownloadRPM/Burst throttle the binary download considerably
// tighter than the sign/enroll endpoints (15–40 MB per fetch). 10/min stops a
// single source just as well as a tighter value, but doesn't choke bulk
// rollouts behind corporate NAT (one IP, an Ansible loop over many hosts).
const (
	defaultAgentDownloadRPM   = 10
	defaultAgentDownloadBurst = 5
)

// defaultSyncInterval is the default interval of the group sync.
const defaultSyncInterval = 5 * time.Minute

// defaultUISessionTTL is the default lifetime of the UI session; the login's
// group claims stay in effect for that long (comparable to the previous
// ID-token lifetime). Disabled users are blocked by the server on every
// request regardless of this.
const defaultUISessionTTL = 12 * time.Hour

// defaultUIScopes are the OIDC scopes of the UI login; groups delivers the
// group claims for the role mapping (Dex only hands them out on request).
var defaultUIScopes = []string{"openid", "profile", "email", "groups"}

// hostCertValidityFromEnv parses GSSH_HOST_CERT_VALIDITY; empty ⇒ 0 (default
// 30 days in internal/api). Invalid values are a configuration error
// (fail-fast instead of silently issuing 30-day certificates).
func hostCertValidityFromEnv() (time.Duration, error) {
	raw := os.Getenv(envHostCertValidity)
	if raw == "" {
		return 0, nil
	}
	validity, err := time.ParseDuration(raw)
	if err != nil || validity <= 0 {
		return 0, fmt.Errorf("%s: invalid duration %q (expected a go-duration > 0)", envHostCertValidity, raw)
	}
	return validity, nil
}

// publicBaseURL returns the external base URL of the public listener
// (GSSH_PUBLIC_URL). Empty ⇒ the rollout/client gates stay closed and the
// UI login derives its redirect URL from the request.
func publicBaseURL() string {
	return strings.TrimSuffix(os.Getenv(envPublicURL), "/")
}

// pinConfigFromEnv builds the pin configuration of the host rollout. An
// invalid static pin or an unusable refresh interval is a configuration
// error and aborts startup (fail-fast, like GSSH_HOST_CERT_VALIDITY) —
// silently continuing without a pin would be the more dangerous option.
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
			return api.PinProviderConfig{}, fmt.Errorf("%s: invalid duration %q (expected a go-duration > 0)", envPublicPinRefresh, raw)
		}
		cfg.Refresh = refresh
	}
	return cfg, nil
}

// Operating modes of the CA keys (GSSH_CA_MODE).
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

// legacyOIDCEnv maps the env vars removed by the server/client OIDC split to
// their replacements. Renamed without aliases: the old names mixed the
// server's confidential client with the clients' public client, and a stale
// deployment must not silently run with parts of auth disabled.
var legacyOIDCEnv = []struct{ old, replacement string }{
	{"GSSH_OIDC_CLIENT_ID", envClientOIDCClientID},
	{"GSSH_UI_OIDC_CLIENT_ID", envServerOIDCClientID},
	{"GSSH_UI_OIDC_CLIENT_SECRET", envServerOIDCClientSecret},
	{"GSSH_UI_OIDC_SCOPES", envServerOIDCScopes},
	{"GSSH_UI_BASE_URL", envPublicURL},
}

// checkLegacyOIDCEnv fails startup while a pre-split variable is still set.
// Errors name every offending variable at once (like caModeFromEnv) and run
// before any database work so a stale deployment stops at the first message.
func checkLegacyOIDCEnv() error {
	var stale []string
	for _, m := range legacyOIDCEnv {
		if os.Getenv(m.old) != "" {
			stale = append(stale, fmt.Sprintf("%s (now %s)", m.old, m.replacement))
		}
	}
	if len(stale) == 0 {
		return nil
	}
	return fmt.Errorf("the server/client oidc split renamed these variables — set: %s (migration notes in the chart README)", strings.Join(stale, ", "))
}

func main() {
	os.Exit(run(os.Stdout, os.Stderr, os.Args[1:]))
}

// run holds the actual logic so it stays testable; main is just a thin
// wrapper around exit-code handling.
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
	showVersion := fs.Bool("version", false, "print version and exit")
	listen := fs.String("listen", "", "listen address of the HTTP API (e.g. :8080); empty = do not start")
	agentListen := fs.String("agent-listen", "", "listen address of the mTLS agent API (e.g. :8443); empty = disabled")
	metricsListen := fs.String("metrics-listen", "", "listen address of the Prometheus /metrics endpoint (e.g. :9090); empty = disabled")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *showVersion {
		fmt.Fprintln(stdout, version.String())
		return 0
	}

	if *listen == "" {
		fmt.Fprintln(stderr, "gssh-server: -listen is missing (e.g. -listen :8080)")
		return 2
	}

	logger := slog.New(slog.NewJSONHandler(stdout, nil))
	if err := serve(logger, *listen, *agentListen, *metricsListen); err != nil {
		logger.Error("server start failed", "error", err)
		return 1
	}
	return 0
}

// dbConnString builds the PostgreSQL connection URL from the individual
// GSSH_DB_* variables. User and password are URL-escaped, so special
// characters in the password are not a problem. Port and SSL mode are
// optional and fall back to the driver defaults (5432 and prefer).
func dbConnString() (string, error) {
	var missing []string
	for _, v := range []string{envDBHost, envDBUser, envDBPassword, envDBName} {
		if os.Getenv(v) == "" {
			missing = append(missing, v)
		}
	}
	if len(missing) > 0 {
		return "", fmt.Errorf("database configuration incomplete: %s not set", strings.Join(missing, ", "))
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

// runMigrate applies the database migrations and exits (subcommand
// `gssh-server migrate`, for the init container in the Kubernetes
// deployment, plan Phase 11). An advisory lock serializes concurrent runs.
func runMigrate(stdout, stderr io.Writer) int {
	dsn, err := dbConnString()
	if err != nil {
		fmt.Fprintf(stderr, "gssh-server: %v\n", err)
		return 2
	}
	if err := store.Migrate(context.Background(), dsn); err != nil {
		fmt.Fprintf(stderr, "gssh-server: migrations: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, "migrations applied")
	return 0
}

// runEnrollToken generates a one-time enrollment token (subcommand
// `gssh-server enroll-token`): the plaintext goes to stdout, only the hash
// is stored in the DB.
func runEnrollToken(stdout, stderr io.Writer, args []string) int {
	fs := flag.NewFlagSet("gssh-server enroll-token", flag.ContinueOnError)
	fs.SetOutput(stderr)
	name := fs.String("name", "", "optional: bind the token to this hostname")
	tagsFlag := fs.String("tags", "", "host tags, e.g. env=prod,role=web")
	ttl := fs.Duration("ttl", 24*time.Hour, "validity duration of the token")
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

	token, record, err := store.NewEnrollmentToken(*name, tags, *ttl)
	if err != nil {
		fmt.Fprintf(stderr, "gssh-server: generate token: %v\n", err)
		return 1
	}
	if err := st.CreateEnrollmentToken(ctx, record); err != nil {
		fmt.Fprintf(stderr, "gssh-server: store token: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "%s\n", token)
	fmt.Fprintf(stderr, "one-time enrollment token, valid until %s — the plaintext is not stored\n",
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

// parseTags parses "k=v,k2=v2" into a map.
func parseTags(raw string) (map[string]string, error) {
	tags := map[string]string{}
	if raw == "" {
		return tags, nil
	}
	for _, pair := range strings.Split(raw, ",") {
		key, value, found := strings.Cut(pair, "=")
		if !found || key == "" {
			return nil, fmt.Errorf("invalid tag %q (expected key=value)", pair)
		}
		tags[key] = value
	}
	return tags, nil
}

// serve starts the HTTP API, optionally the agent API (mTLS), the metrics
// endpoint, and — if configured — the group sync; blocks until SIGINT/SIGTERM.
func serve(logger *slog.Logger, listen, agentListen, metricsListen string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := checkLegacyOIDCEnv(); err != nil {
		return err
	}

	certAuthority, st, err := setup(ctx)
	if err != nil {
		return err
	}
	defer st.Close()

	hostCertValidity, err := hostCertValidityFromEnv()
	if err != nil {
		return err
	}

	verifier, ciVerifier, uiAuth, err := setupVerifiers(ctx, logger)
	if err != nil {
		return err
	}
	startGroupSync(ctx, st, logger)

	adminGroup := os.Getenv(envAdminGroup)
	if adminGroup == "" {
		logger.Warn("admin api not configured — grant management disabled", "env", envAdminGroup)
	}

	devUser, adminGroup, err := setupDevUIAuth(logger, adminGroup)
	if err != nil {
		return err
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
			RateLimit:         setupRateLimit(logger),
			DownloadRateLimit: setupDownloadRateLimit(logger),
			HostCertValidity:  hostCertValidity,
			Logger:            logger, AdminGroup: adminGroup,
			AuditorGroup:  os.Getenv(envAuditorGroup),
			ReadOnlyGroup: os.Getenv(envReadOnlyGroup),
			// Advertised to CLI installs (/v1/ui/config, client.sh): always
			// the clients' public client, never the server's confidential one.
			UIConfig: api.UIConfig{
				OIDCIssuer:   os.Getenv(envOIDCIssuer),
				OIDCClientID: os.Getenv(envClientOIDCClientID),
			},
			UIAuth:  uiAuth,
			DevUser: devUser,
			// Host rollout (one-command install): binaries from the image, the
			// pin, and external URLs. If anything is missing, the gate stays closed (503).
			Agents: agentdist.New(),
			// Client install: the version-matched gssh binaries from the same
			// image; without them the client gate stays closed (503).
			Clients:        clientdist.New(),
			Pins:           pins,
			AgentPublicURL: strings.TrimSuffix(os.Getenv(envAgentPublicURL), "/"),
			PublicBaseURL:  publicBaseURL(),
		}),
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 3)
	go func() { errCh <- server.ListenAndServe() }()
	logger.Info("gssh-server started", "listen", listen, "version", version.String())

	var agentServer *http.Server
	if agentListen != "" {
		agentServer, err = newAgentServer(ctx, certAuthority, st, logger, agentListen, hostCertValidity)
		if err != nil {
			return err
		}
		go func() { errCh <- agentServer.ListenAndServeTLS("", "") }()
		logger.Info("agent api started (mtls)", "listen", agentListen)
	}

	// Metrics on its own listener: not exposed via the ingress, only reachable
	// by the Prometheus scraper (Phase 11).
	var metricsServer *http.Server
	if metricsListen != "" {
		metricsMux := http.NewServeMux()
		metricsMux.Handle("GET /metrics", metrics.Handler())
		metricsServer = &http.Server{Addr: metricsListen, Handler: metricsMux, ReadHeaderTimeout: 10 * time.Second}
		go func() { errCh <- metricsServer.ListenAndServe() }()
		logger.Info("metrics endpoint started", "listen", metricsListen)
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

// newAgentServer builds the mTLS server of the agent API: the server
// certificate comes from the own mTLS CA, and client certificates are
// required and verified against the same CA.
func newAgentServer(ctx context.Context, certAuthority *ca.CA, st *store.Store, logger *slog.Logger, listen string, hostCertValidity time.Duration) (*http.Server, error) {
	// In self-managed mode the mTLS CA comes from the mounted files and was
	// already adopted by setup(); the bootstrap refuses to run there.
	if !certAuthority.SelfManaged() {
		if err := certAuthority.EnsureMTLSCA(ctx); err != nil {
			return nil, fmt.Errorf("bootstrap mtls ca: %w", err)
		}
	}
	names := strings.Split(os.Getenv(envAgentTLSNames), ",")
	if os.Getenv(envAgentTLSNames) == "" {
		names = []string{"localhost", "127.0.0.1"}
	}
	serverCert, err := certAuthority.IssueServerCert(ctx, names)
	if err != nil {
		return nil, fmt.Errorf("agent server certificate: %w", err)
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

// setupOIDC builds the token verifier if OIDC is configured; without an
// issuer the sign endpoint stays disabled. A missing client ID is a
// configuration error (fail-fast instead of rejecting all tokens at
// runtime — security review Phase 10).
func setupOIDC(ctx context.Context, logger *slog.Logger) (api.TokenVerifier, error) {
	issuer := os.Getenv(envOIDCIssuer)
	if issuer == "" {
		logger.Warn("oidc not configured — /v1/sign/user disabled", "env", envOIDCIssuer)
		return nil, nil //nolint:nilnil // nil interface deliberately disables the endpoint
	}
	clientID := os.Getenv(envClientOIDCClientID)
	if clientID == "" {
		return nil, fmt.Errorf("%s is set, but %s is missing — without an expected audience, token validation is not possible", envOIDCIssuer, envClientOIDCClientID)
	}
	verifier, err := auth.NewVerifier(ctx, auth.VerifierConfig{
		IssuerURL: issuer,
		ClientID:  clientID,
	})
	if err != nil {
		return nil, err
	}
	logger.Info("oidc configured", "issuer", issuer)
	return verifier, nil
}

// setupVerifiers bundles the server's OIDC configuration: user and CI token
// verifiers, audience separation, and the server-side UI login.
func setupVerifiers(ctx context.Context, logger *slog.Logger) (api.TokenVerifier, api.CITokenVerifier, *api.UIAuthConfig, error) {
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
	uiAuth, err := setupUIAuth(ctx, logger)
	if err != nil {
		return nil, nil, nil, err
	}
	return verifier, ciVerifier, uiAuth, nil
}

// setupUIAuth builds the configuration of the server-side UI login (BFF)
// from the server's own confidential OIDC client. Client ID and secret must
// be set together (fail-fast on half configuration); with both empty the
// /v1/auth endpoints stay disabled (503). The client must differ from the
// CLIs' public client — one IdP client cannot be public and confidential at
// the same time. The session key is derived from the CA master key — no
// additional secret needed.
func setupUIAuth(ctx context.Context, logger *slog.Logger) (*api.UIAuthConfig, error) {
	clientID := os.Getenv(envServerOIDCClientID)
	secret := os.Getenv(envServerOIDCClientSecret)
	if clientID == "" && secret == "" {
		if os.Getenv(envServerOIDCScopes) != "" {
			return nil, fmt.Errorf("%s is set, but %s and %s are missing", envServerOIDCScopes, envServerOIDCClientID, envServerOIDCClientSecret)
		}
		logger.Warn("ui login not configured — /v1/auth disabled", "env", envServerOIDCClientID+"/"+envServerOIDCClientSecret)
		return nil, nil //nolint:nilnil // nil config deliberately disables the endpoints
	}
	if clientID == "" {
		return nil, fmt.Errorf("%s is set, but %s is missing", envServerOIDCClientSecret, envServerOIDCClientID)
	}
	if secret == "" {
		return nil, fmt.Errorf("%s is set, but %s is missing", envServerOIDCClientID, envServerOIDCClientSecret)
	}
	if clientID == os.Getenv(envClientOIDCClientID) {
		return nil, fmt.Errorf("%s and %s must be different idp clients — the server authenticates with a client secret, the clients without one", envServerOIDCClientID, envClientOIDCClientID)
	}
	issuer := os.Getenv(envOIDCIssuer)
	if issuer == "" {
		return nil, fmt.Errorf("%s is set, but %s is missing", envServerOIDCClientID, envOIDCIssuer)
	}
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("ui login: oidc discovery for %s: %w", issuer, err)
	}
	// Its own verifier: the audience of the login's ID tokens is the
	// server's client ID, not the clients' public client ID.
	verifier, err := auth.NewVerifier(ctx, auth.VerifierConfig{IssuerURL: issuer, ClientID: clientID})
	if err != nil {
		return nil, err
	}
	masterKey, err := base64.StdEncoding.DecodeString(os.Getenv(envMasterKey))
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", envMasterKey, err)
	}
	codec, err := auth.NewSessionCodec(masterKey)
	if err != nil {
		return nil, err
	}
	scopes := defaultUIScopes
	if raw := os.Getenv(envServerOIDCScopes); raw != "" {
		scopes = strings.Split(raw, ",")
		for i := range scopes {
			scopes[i] = strings.TrimSpace(scopes[i])
		}
	}
	sessionTTL := defaultUISessionTTL
	if raw := os.Getenv(envUISessionTTL); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil || parsed <= 0 {
			return nil, fmt.Errorf("%s: invalid duration %q (expected a go-duration > 0)", envUISessionTTL, raw)
		}
		sessionTTL = parsed
	}
	logger.Info("ui login configured (server-side oidc)", "issuer", issuer, "client_id", clientID, "session_ttl", sessionTTL)
	return &api.UIAuthConfig{
		OAuth: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: secret,
			Endpoint:     provider.Endpoint(),
			Scopes:       scopes,
		},
		Verifier:   verifier,
		Codec:      codec,
		BaseURL:    publicBaseURL(),
		SessionTTL: sessionTTL,
	}, nil
}

// setupDevUIAuth parses GSSH_DEV_UI_AUTH and builds the developer mode's
// implicit identity. Only the exact value "insecure" activates it — the
// name states what the operator signs up for: every request without a
// bearer token acts as a logged-in admin, without any IdP. If no admin
// group is configured (the usual dev case), "gssh-dev-admins" is used so
// the admin API's fail-closed gate opens. Returns the (possibly defaulted)
// admin group alongside the dev user.
func setupDevUIAuth(logger *slog.Logger, adminGroup string) (*auth.Claims, string, error) {
	raw := os.Getenv(envDevUIAuth)
	if raw == "" {
		return nil, adminGroup, nil
	}
	if raw != "insecure" {
		return nil, "", fmt.Errorf("%s: unknown value %q — set it to %q to acknowledge that every request runs as an admin, or unset it", envDevUIAuth, raw, "insecure")
	}
	if adminGroup == "" {
		adminGroup = "gssh-dev-admins"
	}
	logger.Warn("INSECURE DEVELOPER MODE ACTIVE — every request without a bearer token is treated as a logged-in admin; local frontend development only, never expose this server",
		"env", envDevUIAuth, "admin_group", adminGroup)
	return &auth.Claims{
		Issuer:            "gssh-dev",
		Subject:           "dev-user",
		Email:             "dev@localhost",
		PreferredUsername: "dev",
		Groups:            []string{adminGroup},
	}, adminGroup, nil
}

// setupRateLimit builds the rate limiter of the sign/enroll endpoints from
// the environment; GSSH_SIGN_RATE_PER_MINUTE=0 deliberately disables it (load tests).
func setupRateLimit(logger *slog.Logger) *api.RateLimiter {
	cfg := api.DefaultRateLimiterConfig()
	if raw := os.Getenv(envRatePerMinute); raw != "" {
		parsed, err := strconv.ParseFloat(raw, 64)
		switch {
		case err != nil || parsed < 0:
			logger.Warn("invalid rate, using default", "env", envRatePerMinute, "value", raw)
		case parsed == 0:
			logger.Warn("rate limiting of the sign/enroll endpoints disabled", "env", envRatePerMinute)
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
			logger.Warn("invalid failure rate, using default", "env", envFailPerMinute, "value", raw)
		}
	}
	cfg.TrustProxyHeader = os.Getenv(envRateTrustXFF) == "true"
	return api.NewRateLimiter(cfg)
}

// setupDownloadRateLimit builds the tighter limiter of the agent binary
// download; GSSH_AGENT_DOWNLOAD_RPM=0 turns it off. TrustProxyHeader comes
// from the same env var as the regular limiter — one source of truth for
// the client IP, otherwise all requests behind the ingress would look like
// the proxy IP and the limit would act globally instead of per host.
func setupDownloadRateLimit(logger *slog.Logger) *api.RateLimiter {
	cfg := api.RateLimiterConfig{
		RequestsPerMinute: defaultAgentDownloadRPM,
		Burst:             defaultAgentDownloadBurst,
		TrustProxyHeader:  os.Getenv(envRateTrustXFF) == "true",
	}
	if raw := os.Getenv(envAgentDownloadRPM); raw != "" {
		parsed, err := strconv.ParseFloat(raw, 64)
		switch {
		case err != nil || parsed < 0:
			logger.Warn("invalid download rate, using default", "env", envAgentDownloadRPM, "value", raw)
		case parsed == 0:
			logger.Warn("rate limiting of the agent download disabled", "env", envAgentDownloadRPM)
			return nil
		default:
			cfg.RequestsPerMinute = parsed
			cfg.Burst = max(1, parsed/2)
		}
	}
	return api.NewRateLimiter(cfg)
}

// checkAudienceSeparation prevents audience confusion (security review
// Phase 10): if user OIDC and GitLab CI run against the same issuer, their
// expected audiences must differ — otherwise user and CI tokens would be
// interchangeable at both endpoints. The server's confidential client needs
// no such check: its verifier only sees the ID token the server itself
// obtains in the login callback, never an inbound bearer token.
func checkAudienceSeparation() error {
	issuer := os.Getenv(envOIDCIssuer)
	if issuer == "" || issuer != os.Getenv(envCIIssuer) {
		return nil
	}
	ciAudience := os.Getenv(envCIAudience)
	if ciAudience == "" {
		ciAudience = auth.DefaultCIAudience
	}
	if ciAudience == os.Getenv(envClientOIDCClientID) {
		return fmt.Errorf("same issuer and same audience for user oidc and gitlab ci (%s/%s) — tokens would be interchangeable at both sign endpoints", envClientOIDCClientID, envCIAudience)
	}
	return nil
}

// setupCIOIDC builds the verifier for GitLab job tokens if configured;
// without an issuer /v1/sign/ci stays disabled.
func setupCIOIDC(ctx context.Context, logger *slog.Logger) (api.CITokenVerifier, error) {
	issuer := os.Getenv(envCIIssuer)
	if issuer == "" {
		logger.Warn("gitlab ci not configured — /v1/sign/ci disabled", "env", envCIIssuer)
		return nil, nil //nolint:nilnil // nil interface deliberately disables the endpoint
	}
	verifier, err := auth.NewCIVerifier(ctx, auth.CIVerifierConfig{
		IssuerURL: issuer,
		Audience:  os.Getenv(envCIAudience),
	})
	if err != nil {
		return nil, err
	}
	logger.Info("gitlab ci configured", "issuer", issuer)
	return verifier, nil
}

// startAuditStream starts audit streaming (structured JSON logs to stdout
// and/or a webhook) if configured.
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
			logger.Warn("invalid audit stream interval, using default", "value", raw)
		}
	}
	streamer := auditstream.New(st, cfg)
	go streamer.Run(ctx)
	logger.Info("audit streaming started", "logs", streamLogs, "webhook", webhookURL != "")
}

// startGroupSync starts the periodic group sync via the Keycloak admin API
// if configured.
func startGroupSync(ctx context.Context, st *store.Store, logger *slog.Logger) {
	clientID := os.Getenv(envKCClientID)
	if clientID == "" {
		logger.Warn("group sync not configured — offboarding only takes effect via token expiry", "env", envKCClientID)
		return
	}
	interval := defaultSyncInterval
	if raw := os.Getenv(envSyncInterval); raw != "" {
		if parsed, err := time.ParseDuration(raw); err == nil && parsed > 0 {
			interval = parsed
		} else {
			logger.Warn("invalid sync interval, using default", "value", raw, "default", interval)
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
	logger.Info("group sync started", "issuer", source.Issuer(), "interval", interval)
}

// setupStore builds the connection URL from the environment, migrates the
// database, and opens the store.
func setupStore(ctx context.Context) (*store.Store, error) {
	dsn, err := dbConnString()
	if err != nil {
		return nil, err
	}
	if err := store.Migrate(ctx, dsn); err != nil {
		return nil, fmt.Errorf("migrations: %w", err)
	}
	return store.New(ctx, dsn)
}

// setup reads the settings from the environment, migrates the database, and
// bootstraps the CA (including CA keys, if none exist yet).
// In self-managed mode the mounted key files replace the bootstrap: they are
// loaded before the database is touched and adopted afterwards (D2/D4).
// GSSH_CA_MASTER_KEY stays mandatory in both modes (D7).
func setup(ctx context.Context) (*ca.CA, *store.Store, error) {
	masterKey, err := base64.StdEncoding.DecodeString(os.Getenv(envMasterKey))
	if err != nil {
		return nil, nil, fmt.Errorf("decode %s: %w", envMasterKey, err)
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
		return nil, nil, fmt.Errorf("bootstrap ca keys: %w", err)
	}
	return certAuthority, st, nil
}
