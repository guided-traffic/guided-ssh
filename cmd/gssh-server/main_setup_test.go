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

	"github.com/guided-traffic/guided-ssh/internal/ca"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestHostCertValidityFromEnv(t *testing.T) {
	t.Setenv(envHostCertValidity, "")
	if v, err := hostCertValidityFromEnv(); err != nil || v != 0 {
		t.Fatalf("leer: %v %v (0, nil erwartet)", v, err)
	}
	t.Setenv(envHostCertValidity, "3m")
	if v, err := hostCertValidityFromEnv(); err != nil || v != 3*time.Minute {
		t.Fatalf("3m: %v %v", v, err)
	}
	for _, invalid := range []string{"quatsch", "-5m", "0s"} {
		t.Setenv(envHostCertValidity, invalid)
		if _, err := hostCertValidityFromEnv(); err == nil {
			t.Errorf("%q: fehler erwartet", invalid)
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

func TestSetupOIDC(t *testing.T) {
	// Ohne Issuer: Endpoint bewusst deaktiviert (nil, nil).
	t.Setenv(envOIDCIssuer, "")
	verifier, err := setupOIDC(context.Background(), discardLogger())
	if verifier != nil || err != nil {
		t.Fatalf("ohne issuer: %v %v", verifier, err)
	}
	// Issuer ohne Client-ID: fail-fast (Security-Review Phase 10).
	t.Setenv(envOIDCIssuer, "https://idp.example")
	t.Setenv(envOIDCClientID, "")
	if _, err := setupOIDC(context.Background(), discardLogger()); err == nil {
		t.Fatal("issuer ohne client-id muss fehlschlagen")
	}
}

func TestSetupUIAuth(t *testing.T) {
	// Ohne Client-Secret: BFF bewusst deaktiviert (nil, nil).
	t.Setenv(envUIOIDCClientSecret, "")
	cfg, err := setupUIAuth(context.Background(), discardLogger(), "gssh-ui")
	if cfg != nil || err != nil {
		t.Fatalf("ohne secret: %v %v", cfg, err)
	}
	// Secret ohne Issuer bzw. ohne Client-ID: Konfigurationsfehler (fail-fast).
	t.Setenv(envUIOIDCClientSecret, "geheim")
	t.Setenv(envOIDCIssuer, "")
	if _, err := setupUIAuth(context.Background(), discardLogger(), "gssh-ui"); err == nil {
		t.Fatal("secret ohne issuer muss fehlschlagen")
	}
	t.Setenv(envOIDCIssuer, "https://idp.example")
	if _, err := setupUIAuth(context.Background(), discardLogger(), ""); err == nil {
		t.Fatal("secret ohne client-id muss fehlschlagen")
	}
}

// TestSetupUIAuthKomplett: vollständige Konfiguration gegen einen Fake-IdP
// (nur Discovery) — prüft Scopes-Override, TTL-Parsing und Base-URL-Trim.
func TestSetupUIAuthKomplett(t *testing.T) {
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

	t.Setenv(envUIOIDCClientSecret, "geheim")
	t.Setenv(envOIDCIssuer, idp.URL)
	t.Setenv(envMasterKey, base64.StdEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv(envUIOIDCScopes, "openid, email")
	t.Setenv(envUISessionTTL, "1h")
	t.Setenv(envUIBaseURL, "https://gssh.example.com/")

	cfg, err := setupUIAuth(context.Background(), discardLogger(), "gssh-ui")
	if err != nil {
		t.Fatalf("setupUIAuth: %v", err)
	}
	if cfg.OAuth.ClientID != "gssh-ui" || cfg.OAuth.ClientSecret != "geheim" {
		t.Errorf("oauth-client = %s/%s", cfg.OAuth.ClientID, cfg.OAuth.ClientSecret)
	}
	if !slices.Equal(cfg.OAuth.Scopes, []string{"openid", "email"}) {
		t.Errorf("scopes = %v", cfg.OAuth.Scopes)
	}
	if cfg.SessionTTL != time.Hour {
		t.Errorf("session-ttl = %v", cfg.SessionTTL)
	}
	if cfg.BaseURL != "https://gssh.example.com" {
		t.Errorf("base-url = %q (trailing slash nicht entfernt?)", cfg.BaseURL)
	}
	if cfg.Verifier == nil || cfg.Codec == nil {
		t.Error("verifier/codec fehlen")
	}

	// Ungültige Session-TTL: Konfigurationsfehler (fail-fast).
	t.Setenv(envUISessionTTL, "nix")
	if _, err := setupUIAuth(context.Background(), discardLogger(), "gssh-ui"); err == nil {
		t.Error("ungültige ttl muss fehlschlagen")
	}
}

func TestSetupCIOIDCDeaktiviert(t *testing.T) {
	t.Setenv(envCIIssuer, "")
	verifier, err := setupCIOIDC(context.Background(), discardLogger())
	if verifier != nil || err != nil {
		t.Fatalf("ohne issuer: %v %v", verifier, err)
	}
}

func TestCheckAudienceSeparation(t *testing.T) {
	// Unterschiedliche Issuer: keine Einschränkung.
	t.Setenv(envOIDCIssuer, "https://idp.example")
	t.Setenv(envCIIssuer, "https://gitlab.example")
	t.Setenv(envOIDCClientID, "guided-ssh")
	t.Setenv(envCIAudience, "")
	if err := checkAudienceSeparation(); err != nil {
		t.Fatalf("verschiedene issuer: %v", err)
	}
	// Gleicher Issuer + kollidierende Audience (CI-Default guided-ssh): Fehler.
	t.Setenv(envCIIssuer, "https://idp.example")
	if err := checkAudienceSeparation(); err == nil {
		t.Fatal("audience-kollision muss den start verhindern")
	}
	// Gleicher Issuer, getrennte Audiences: ok.
	t.Setenv(envCIAudience, "gitlab-ci")
	if err := checkAudienceSeparation(); err != nil {
		t.Fatalf("getrennte audiences: %v", err)
	}
}

func TestSetupRateLimit(t *testing.T) {
	logger := discardLogger()

	t.Setenv(envRatePerMinute, "")
	t.Setenv(envFailPerMinute, "")
	t.Setenv(envRateTrustXFF, "")
	if rl := setupRateLimit(logger); rl == nil {
		t.Fatal("default: limiter erwartet")
	}

	t.Setenv(envRatePerMinute, "0")
	if rl := setupRateLimit(logger); rl != nil {
		t.Fatal("\"0\" muss das rate-limiting deaktivieren")
	}

	t.Setenv(envRatePerMinute, "120")
	t.Setenv(envFailPerMinute, "30")
	t.Setenv(envRateTrustXFF, "true")
	if rl := setupRateLimit(logger); rl == nil {
		t.Fatal("konfigurierter limiter erwartet")
	}

	// Ungültige Werte fallen auf Defaults zurück statt zu crashen.
	t.Setenv(envRatePerMinute, "viele")
	t.Setenv(envFailPerMinute, "-3")
	if rl := setupRateLimit(logger); rl == nil {
		t.Fatal("ungültige werte: default-limiter erwartet")
	}
}

func TestStartGroupSyncOhneKonfiguration(t *testing.T) {
	// Ohne GSSH_KC_CLIENT_ID kehrt der Sync ohne Nebenwirkungen zurück
	// (kein Netz, kein Store-Zugriff).
	t.Setenv(envKCClientID, "")
	startGroupSync(context.Background(), nil, discardLogger())
}

func TestStartAuditStreamOhneKonfiguration(t *testing.T) {
	t.Setenv(envAuditStream, "")
	t.Setenv(envAuditWebhookURL, "")
	startAuditStream(context.Background(), nil, discardLogger())
}

func TestRunEnrollTokenUngueltigeTags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := run(&stdout, &stderr, []string{"enroll-token", "-tags", "kaputt"}); got != 2 {
		t.Fatalf("ungültige tags = %d, erwartet 2", got)
	}
	if !strings.Contains(stderr.String(), "tag") {
		t.Errorf("stderr ohne tag-hinweis: %q", stderr.String())
	}
}

// setDBEnv setzt eine vollständige DB-Konfiguration für Tests.
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
	// Vollständige Konfiguration inkl. Sonderzeichen im Passwort.
	setDBEnv(t, "db.example.com", "5433", "gssh", "p@ss:wort/mit?zeichen", "gsshdb", "require")
	got, err := dbConnString()
	if err != nil {
		t.Fatalf("dbConnString: %v", err)
	}
	want := "postgres://gssh:p%40ss%3Awort%2Fmit%3Fzeichen@db.example.com:5433/gsshdb?sslmode=require"
	if got != want {
		t.Errorf("dbConnString = %q, erwartet %q", got, want)
	}

	// Port und SSL-Mode optional: Treiber-Defaults greifen.
	setDBEnv(t, "db", "", "u", "p", "d", "")
	if got, err := dbConnString(); err != nil || got != "postgres://u:p@db/d" {
		t.Errorf("ohne port/sslmode: %q, %v", got, err)
	}

	// Fehlende Pflicht-Variablen: Fehler nennt alle fehlenden Namen.
	setDBEnv(t, "", "", "u", "", "d", "")
	if _, err := dbConnString(); err == nil ||
		!strings.Contains(err.Error(), envDBHost) || !strings.Contains(err.Error(), envDBPassword) {
		t.Errorf("fehlende pflicht-variablen: %v (erwartet hinweis auf %s und %s)", err, envDBHost, envDBPassword)
	}
}

func TestRunMigrateDBUnerreichbar(t *testing.T) {
	// Port 1 lehnt Verbindungen sofort ab — kein Timeout nötig.
	setDBEnv(t, "127.0.0.1", "1", "gssh", "gssh", "gssh", "disable")
	var stdout, stderr bytes.Buffer
	if got := run(&stdout, &stderr, []string{"migrate"}); got != 1 {
		t.Fatalf("unerreichbare datenbank = %d, erwartet 1 (stderr: %s)", got, stderr.String())
	}
}

func TestServeUngueltigeHostCertValidity(t *testing.T) {
	// serve schlägt an der DB-Konfiguration fehl, bevor die Validity geprüft
	// wird — die Env-Validierung selbst deckt TestHostCertValidityFromEnv ab.
	// Hier nur der frühe Fehlerpfad des Serverstarts ohne Store.
	setDBEnv(t, "", "", "", "", "", "")
	if err := serve(discardLogger(), "127.0.0.1:0", "", ""); err == nil {
		t.Fatal("serve ohne db-konfiguration muss fehlschlagen")
	}
}
