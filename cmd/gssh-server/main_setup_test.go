package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/guided-traffic/guided-ssh/internal/api"
	"github.com/guided-traffic/guided-ssh/internal/ca"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestHostCertValidityFromEnv(t *testing.T) {
	t.Setenv(envHostCertValidity, "")
	if v, err := hostCertValidityFromEnv(); err != nil || v != 0 {
		t.Fatalf("empty: %v %v (want 0, nil)", v, err)
	}
	t.Setenv(envHostCertValidity, "3m")
	if v, err := hostCertValidityFromEnv(); err != nil || v != 3*time.Minute {
		t.Fatalf("3m: %v %v", v, err)
	}
	for _, invalid := range []string{"garbage", "-5m", "0s"} {
		t.Setenv(envHostCertValidity, invalid)
		if _, err := hostCertValidityFromEnv(); err == nil {
			t.Errorf("%q: expected an error", invalid)
		}
	}
}

// setCAModeEnv sets every CA-mode variable so a subtest never inherits the
// developer's environment or the previous case.
func setCAModeEnv(t *testing.T, mode string, paths ca.ExternalKeyPaths) {
	t.Helper()
	t.Setenv(envCAMode, mode)
	t.Setenv(envCAUserKeyFile, paths.UserKeyFile)
	t.Setenv(envCAHostKeyFile, paths.HostKeyFile)
	t.Setenv(envCAMTLSKeyFile, paths.MTLSKeyFile)
	t.Setenv(envCAMTLSCertFile, paths.MTLSCertFile)
}

// TestCAModeFromEnv covers the validation matrix of SELF_MANAGED_CA.md (D2):
// the modes are exclusive, and a half-configured deployment must fail at
// startup with every offending variable named at once.
func TestCAModeFromEnv(t *testing.T) {
	all := ca.ExternalKeyPaths{
		UserKeyFile:  "/etc/gssh/ca/user-ca",
		HostKeyFile:  "/etc/gssh/ca/host-ca",
		MTLSKeyFile:  "/etc/gssh/ca/mtls-ca.key",
		MTLSCertFile: "/etc/gssh/ca/mtls-ca.crt",
	}
	tests := []struct {
		name  string
		mode  string
		paths ca.ExternalKeyPaths
		// wantMode/wantPaths are checked when no error is expected.
		wantMode  string
		wantPaths ca.ExternalKeyPaths
		// wantVars must appear in the error, skipVars must not.
		wantVars []string
		skipVars []string
	}{
		{
			name:     "unset defaults to managed",
			wantMode: caModeManaged,
		},
		{
			name:     "explicit managed without key files",
			mode:     caModeManaged,
			wantMode: caModeManaged,
		},
		{
			name:     "managed with a single key file",
			mode:     caModeManaged,
			paths:    ca.ExternalKeyPaths{MTLSKeyFile: all.MTLSKeyFile},
			wantVars: []string{envCAMTLSKeyFile},
			skipVars: []string{envCAUserKeyFile, envCAHostKeyFile, envCAMTLSCertFile},
		},
		{
			name:     "managed by default with all key files",
			paths:    all,
			wantVars: []string{envCAUserKeyFile, envCAHostKeyFile, envCAMTLSKeyFile, envCAMTLSCertFile},
		},
		{
			name:      "self-managed with all key files",
			mode:      caModeSelfManaged,
			paths:     all,
			wantMode:  caModeSelfManaged,
			wantPaths: all,
		},
		{
			name: "self-managed without the mtls certificate",
			mode: caModeSelfManaged,
			paths: ca.ExternalKeyPaths{
				UserKeyFile: all.UserKeyFile, HostKeyFile: all.HostKeyFile, MTLSKeyFile: all.MTLSKeyFile,
			},
			wantVars: []string{envCAMTLSCertFile},
			skipVars: []string{envCAUserKeyFile, envCAHostKeyFile, envCAMTLSKeyFile},
		},
		{
			name:     "self-managed with only the user key",
			mode:     caModeSelfManaged,
			paths:    ca.ExternalKeyPaths{UserKeyFile: all.UserKeyFile},
			wantVars: []string{envCAHostKeyFile, envCAMTLSKeyFile, envCAMTLSCertFile},
			skipVars: []string{envCAUserKeyFile},
		},
		{
			name:     "self-managed without any key file",
			mode:     caModeSelfManaged,
			wantVars: []string{envCAUserKeyFile, envCAHostKeyFile, envCAMTLSKeyFile, envCAMTLSCertFile},
		},
		{
			name:     "unknown mode",
			mode:     "gitops",
			wantVars: []string{envCAMode, "gitops", caModeManaged, caModeSelfManaged},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			setCAModeEnv(t, tc.mode, tc.paths)
			mode, paths, err := caModeFromEnv()

			if len(tc.wantVars) == 0 {
				if err != nil {
					t.Fatalf("caModeFromEnv: %v", err)
				}
				if mode != tc.wantMode {
					t.Errorf("mode = %q, want %q", mode, tc.wantMode)
				}
				if paths != tc.wantPaths {
					t.Errorf("paths = %+v, want %+v", paths, tc.wantPaths)
				}
				return
			}

			if err == nil {
				t.Fatalf("expected an error, got mode %q and paths %+v", mode, paths)
			}
			if mode != "" || paths != (ca.ExternalKeyPaths{}) {
				t.Errorf("misconfiguration must not yield a usable config: %q %+v", mode, paths)
			}
			for _, want := range tc.wantVars {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error does not name %s: %v", want, err)
				}
			}
			for _, skip := range tc.skipVars {
				if strings.Contains(err.Error(), skip) {
					t.Errorf("error wrongly names %s: %v", skip, err)
				}
			}
		})
	}
}

// TestCheckLegacyOIDCEnv: variables renamed by the server/client OIDC split
// must stop startup with an old→new hint instead of being silently ignored.
func TestCheckLegacyOIDCEnv(t *testing.T) {
	for _, m := range legacyOIDCEnv {
		t.Setenv(m.old, "")
	}
	if err := checkLegacyOIDCEnv(); err != nil {
		t.Fatalf("no legacy variables: %v", err)
	}

	t.Setenv("GSSH_OIDC_CLIENT_ID", "gssh-cli")
	t.Setenv("GSSH_UI_BASE_URL", "https://gssh.example.com")
	err := checkLegacyOIDCEnv()
	if err == nil {
		t.Fatal("legacy variables must stop startup")
	}
	for _, want := range []string{"GSSH_OIDC_CLIENT_ID", envClientOIDCClientID, "GSSH_UI_BASE_URL", envPublicURL} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not name %s: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "GSSH_UI_OIDC_CLIENT_SECRET") {
		t.Errorf("error wrongly names an unset variable: %v", err)
	}
}

func TestSetupOIDC(t *testing.T) {
	// Without an issuer: endpoint deliberately disabled (nil, nil).
	t.Setenv(envOIDCIssuer, "")
	verifier, err := setupOIDC(context.Background(), discardLogger())
	if verifier != nil || err != nil {
		t.Fatalf("without issuer: %v %v", verifier, err)
	}
	// Issuer without a client ID: fail-fast (security review Phase 10).
	t.Setenv(envOIDCIssuer, "https://idp.example")
	t.Setenv(envClientOIDCClientID, "")
	if _, err := setupOIDC(context.Background(), discardLogger()); err == nil {
		t.Fatal("issuer without a client id must fail")
	}
}

func TestSetupUIAuth(t *testing.T) {
	// Server client ID and secret both empty: BFF deliberately disabled (nil, nil).
	t.Setenv(envServerOIDCClientID, "")
	t.Setenv(envServerOIDCClientSecret, "")
	t.Setenv(envServerOIDCScopes, "")
	t.Setenv(envClientOIDCClientID, "")
	cfg, err := setupUIAuth(context.Background(), discardLogger())
	if cfg != nil || err != nil {
		t.Fatalf("unconfigured: %v %v", cfg, err)
	}
	// Scopes without the client pair: configuration error (fail-fast).
	t.Setenv(envServerOIDCScopes, "openid")
	if _, err := setupUIAuth(context.Background(), discardLogger()); err == nil {
		t.Fatal("scopes without the client pair must fail")
	}
	t.Setenv(envServerOIDCScopes, "")
	// Half-configured pair: configuration error (fail-fast) in both directions.
	t.Setenv(envServerOIDCClientSecret, "secret")
	if _, err := setupUIAuth(context.Background(), discardLogger()); err == nil {
		t.Fatal("secret without client id must fail")
	}
	t.Setenv(envServerOIDCClientSecret, "")
	t.Setenv(envServerOIDCClientID, "gssh-server")
	if _, err := setupUIAuth(context.Background(), discardLogger()); err == nil {
		t.Fatal("client id without secret must fail")
	}
	// Complete pair without an issuer: configuration error.
	t.Setenv(envServerOIDCClientSecret, "secret")
	t.Setenv(envOIDCIssuer, "")
	if _, err := setupUIAuth(context.Background(), discardLogger()); err == nil {
		t.Fatal("server client without issuer must fail")
	}
	// Server client identical to the clients' public client: rejected — one
	// IdP client cannot be public and confidential at the same time.
	t.Setenv(envOIDCIssuer, "https://idp.example")
	t.Setenv(envClientOIDCClientID, "gssh-server")
	if _, err := setupUIAuth(context.Background(), discardLogger()); err == nil {
		t.Fatal("server client == clients' client must fail")
	}
}

// TestSetupUIAuthComplete: a complete configuration against a fake IdP
// (discovery only) — checks scopes override, TTL parsing, and public-URL trimming.
func TestSetupUIAuthComplete(t *testing.T) {
	var idp *httptest.Server
	idp = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                idp.URL,
			"authorization_endpoint":                idp.URL + "/auth",
			"token_endpoint":                        idp.URL + "/token",
			"jwks_uri":                              idp.URL + "/keys",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	}))
	t.Cleanup(idp.Close)

	t.Setenv(envServerOIDCClientID, "gssh-server")
	t.Setenv(envServerOIDCClientSecret, "secret")
	t.Setenv(envClientOIDCClientID, "gssh-cli")
	t.Setenv(envOIDCIssuer, idp.URL)
	t.Setenv(envMasterKey, base64.StdEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv(envServerOIDCScopes, "openid, email")
	t.Setenv(envUISessionTTL, "1h")
	t.Setenv(envPublicURL, "https://gssh.example.com/")

	cfg, err := setupUIAuth(context.Background(), discardLogger())
	if err != nil {
		t.Fatalf("setupUIAuth: %v", err)
	}
	if cfg.OAuth.ClientID != "gssh-server" || cfg.OAuth.ClientSecret != "secret" {
		t.Errorf("oauth-client = %s/%s", cfg.OAuth.ClientID, cfg.OAuth.ClientSecret)
	}
	if !slices.Equal(cfg.OAuth.Scopes, []string{"openid", "email"}) {
		t.Errorf("scopes = %v", cfg.OAuth.Scopes)
	}
	if cfg.SessionTTL != time.Hour {
		t.Errorf("session-ttl = %v", cfg.SessionTTL)
	}
	if cfg.BaseURL != "https://gssh.example.com" {
		t.Errorf("base-url = %q (trailing slash not removed?)", cfg.BaseURL)
	}
	if cfg.Verifier == nil || cfg.Codec == nil {
		t.Error("verifier/codec missing")
	}

	// Invalid session TTL: configuration error (fail-fast).
	t.Setenv(envUISessionTTL, "nope")
	if _, err := setupUIAuth(context.Background(), discardLogger()); err == nil {
		t.Error("invalid ttl must fail")
	}
}

func TestSetupCIOIDCDisabled(t *testing.T) {
	t.Setenv(envCIIssuer, "")
	verifier, err := setupCIOIDC(context.Background(), discardLogger())
	if verifier != nil || err != nil {
		t.Fatalf("without issuer: %v %v", verifier, err)
	}
}

func TestCheckAudienceSeparation(t *testing.T) {
	// Different issuers: no restriction.
	t.Setenv(envOIDCIssuer, "https://idp.example")
	t.Setenv(envCIIssuer, "https://gitlab.example")
	t.Setenv(envClientOIDCClientID, "guided-ssh")
	t.Setenv(envCIAudience, "")
	if err := checkAudienceSeparation(); err != nil {
		t.Fatalf("different issuers: %v", err)
	}
	// Same issuer + colliding audience (CI default guided-ssh): error.
	t.Setenv(envCIIssuer, "https://idp.example")
	if err := checkAudienceSeparation(); err == nil {
		t.Fatal("audience collision must prevent startup")
	}
	// Same issuer, separate audiences: ok.
	t.Setenv(envCIAudience, "gitlab-ci")
	if err := checkAudienceSeparation(); err != nil {
		t.Fatalf("separate audiences: %v", err)
	}
}

func TestSetupRateLimit(t *testing.T) {
	logger := discardLogger()

	t.Setenv(envRatePerMinute, "")
	t.Setenv(envFailPerMinute, "")
	t.Setenv(envRateTrustXFF, "")
	if rl := setupRateLimit(logger); rl == nil {
		t.Fatal("default: expected a limiter")
	}

	t.Setenv(envRatePerMinute, "0")
	if rl := setupRateLimit(logger); rl != nil {
		t.Fatal("\"0\" must disable rate limiting")
	}

	t.Setenv(envRatePerMinute, "120")
	t.Setenv(envFailPerMinute, "30")
	t.Setenv(envRateTrustXFF, "true")
	if rl := setupRateLimit(logger); rl == nil {
		t.Fatal("expected a configured limiter")
	}

	// Invalid values fall back to defaults instead of crashing.
	t.Setenv(envRatePerMinute, "many")
	t.Setenv(envFailPerMinute, "-3")
	if rl := setupRateLimit(logger); rl == nil {
		t.Fatal("invalid values: expected the default limiter")
	}
}

// setPinEnv sets every pin variable so no subtest inherits the developer's
// environment or the previous case.
func setPinEnv(t *testing.T, staticPin, certFile, refresh, publicURL string) {
	t.Helper()
	t.Setenv(envPublicPin, staticPin)
	t.Setenv(envPublicPinCert, certFile)
	t.Setenv(envPublicPinRefresh, refresh)
	t.Setenv(envPublicURL, publicURL)
}

// TestPinConfigFromEnv: an invalid static pin or an unusable refresh
// interval aborts startup (fail-fast) — silently continuing without a pin
// would be the more dangerous option.
func TestPinConfigFromEnv(t *testing.T) {
	setPinEnv(t, "", "", "", "")
	cfg, err := pinConfigFromEnv()
	if err != nil || cfg != (api.PinProviderConfig{}) {
		t.Fatalf("empty: %+v %v (want empty config, nil)", cfg, err)
	}

	// GSSH_PUBLIC_URL is the dial source; the trailing slash does not
	// belong in the base URL.
	setPinEnv(t, "", "", "", "https://gssh.example.com/")
	if cfg, err = pinConfigFromEnv(); err != nil || cfg.DialURL != "https://gssh.example.com" {
		t.Fatalf("public-url: %+v %v", cfg, err)
	}

	validPin := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	setPinEnv(t, validPin, "/etc/gssh/tls.crt", "30s", "")
	cfg, err = pinConfigFromEnv()
	if err != nil {
		t.Fatalf("valid configuration: %v", err)
	}
	if cfg.StaticPin != validPin || cfg.CertFile != "/etc/gssh/tls.crt" || cfg.Refresh != 30*time.Second {
		t.Fatalf("config = %+v", cfg)
	}

	for _, invalid := range []string{"not-base64!", "AAAA"} {
		setPinEnv(t, invalid, "", "", "")
		if _, err := pinConfigFromEnv(); err == nil {
			t.Errorf("pin %q: expected a startup error", invalid)
		}
	}

	for _, invalid := range []string{"garbage", "-5m", "0s"} {
		setPinEnv(t, "", "", invalid, "")
		if _, err := pinConfigFromEnv(); err == nil {
			t.Errorf("refresh %q: expected a startup error", invalid)
		}
	}
}

func TestStartGroupSyncWithoutConfiguration(t *testing.T) {
	// Without GSSH_KC_CLIENT_ID, the sync returns without side effects
	// (no network, no store access).
	t.Setenv(envKCClientID, "")
	startGroupSync(context.Background(), nil, discardLogger())
}

func TestStartAuditStreamWithoutConfiguration(t *testing.T) {
	t.Setenv(envAuditStream, "")
	t.Setenv(envAuditWebhookURL, "")
	startAuditStream(context.Background(), nil, discardLogger())
}

func TestRunEnrollTokenInvalidTags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := run(&stdout, &stderr, []string{"enroll-token", "-tags", "broken"}); got != 2 {
		t.Fatalf("invalid tags = %d, want 2", got)
	}
	if !strings.Contains(stderr.String(), "tag") {
		t.Errorf("stderr without tag hint: %q", stderr.String())
	}
}

// setDBEnv sets a complete DB configuration for tests.
func setDBEnv(t *testing.T, host, port, user, password, name, sslmode string) {
	t.Helper()
	t.Setenv(envDBHost, host)
	t.Setenv(envDBPort, port)
	t.Setenv(envDBUser, user)
	t.Setenv(envDBPassword, password)
	t.Setenv(envDBName, name)
	t.Setenv(envDBSSLMode, sslmode)
}

func TestDBConnString(t *testing.T) {
	// Complete configuration including special characters in the password.
	setDBEnv(t, "db.example.com", "5433", "gssh", "p@ss:word/with?chars", "gsshdb", "require")
	got, err := dbConnString()
	if err != nil {
		t.Fatalf("dbConnString: %v", err)
	}
	want := "postgres://gssh:p%40ss%3Aword%2Fwith%3Fchars@db.example.com:5433/gsshdb?sslmode=require"
	if got != want {
		t.Errorf("dbConnString = %q, want %q", got, want)
	}

	// Port and SSL mode optional: driver defaults apply.
	setDBEnv(t, "db", "", "u", "p", "d", "")
	if got, err := dbConnString(); err != nil || got != "postgres://u:p@db/d" {
		t.Errorf("without port/sslmode: %q, %v", got, err)
	}

	// Missing required variables: the error names all missing variables.
	setDBEnv(t, "", "", "u", "", "d", "")
	if _, err := dbConnString(); err == nil ||
		!strings.Contains(err.Error(), envDBHost) || !strings.Contains(err.Error(), envDBPassword) {
		t.Errorf("missing required variables: %v (expected a hint about %s and %s)", err, envDBHost, envDBPassword)
	}
}

func TestRunMigrateDBUnreachable(t *testing.T) {
	// Port 1 rejects connections immediately — no timeout needed.
	setDBEnv(t, "127.0.0.1", "1", "gssh", "gssh", "gssh", "disable")
	var stdout, stderr bytes.Buffer
	if got := run(&stdout, &stderr, []string{"migrate"}); got != 1 {
		t.Fatalf("unreachable database = %d, want 1 (stderr: %s)", got, stderr.String())
	}
}

func TestServeInvalidHostCertValidity(t *testing.T) {
	// serve fails on the DB configuration before the validity is checked —
	// the env validation itself is covered by TestHostCertValidityFromEnv.
	// Here only the early error path of the server start without a store.
	setDBEnv(t, "", "", "", "", "", "")
	if err := serve(discardLogger(), "127.0.0.1:0", "", ""); err == nil {
		t.Fatal("serve without db configuration must fail")
	}
}

func TestSetupDevUIAuth(t *testing.T) {
	// Unset: disabled, admin group passes through unchanged.
	t.Setenv(envDevUIAuth, "")
	user, group, err := setupDevUIAuth(discardLogger(), "ops")
	if err != nil || user != nil || group != "ops" {
		t.Fatalf("unset: user=%v group=%q err=%v (expected nil/ops/nil)", user, group, err)
	}

	// Any value other than "insecure" is a configuration error (fail-fast).
	for _, invalid := range []string{"true", "1", "yes", "INSECURE"} {
		t.Setenv(envDevUIAuth, invalid)
		if _, _, err := setupDevUIAuth(discardLogger(), ""); err == nil {
			t.Errorf("value %q must be rejected", invalid)
		}
	}

	// "insecure" without an admin group defaults the group so the admin
	// API gate opens; the dev user is a member.
	t.Setenv(envDevUIAuth, "insecure")
	user, group, err = setupDevUIAuth(discardLogger(), "")
	if err != nil {
		t.Fatalf("insecure: %v", err)
	}
	if group == "" || user == nil || !slices.Contains(user.Groups, group) {
		t.Fatalf("insecure: user=%+v group=%q (expected dev user in defaulted group)", user, group)
	}
	if user.Username() != "dev" {
		t.Errorf("username %q (expected dev)", user.Username())
	}

	// A configured admin group is kept.
	user, group, err = setupDevUIAuth(discardLogger(), "ops")
	if err != nil || group != "ops" || !slices.Contains(user.Groups, "ops") {
		t.Fatalf("insecure with group: user=%+v group=%q err=%v", user, group, err)
	}
}
