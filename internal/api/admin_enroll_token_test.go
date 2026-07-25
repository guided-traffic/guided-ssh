package api_test

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/guided-traffic/guided-ssh/internal/agentdist"
	"github.com/guided-traffic/guided-ssh/internal/api"
	"github.com/guided-traffic/guided-ssh/internal/store"
)

// testPin ist ein gültig geformter (nie echt vergebener) Base64-SPKI-Pin.
const testPin = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

// enrollTokenResponse ist die Antwort von POST /v1/admin/enroll-tokens.
type enrollTokenResponse struct {
	Token          string    `json:"token"`
	ExpiresAt      time.Time `json:"expires_at"`
	InstallCommand string    `json:"install_command"`
}

// rolloutReady erfüllt alle vier Gate-Bedingungen des Host-Rollouts.
func rolloutReady(deps *api.Deps) {
	deps.Agents = agentdist.NewFromFS(fstest.MapFS{
		"gssh-agentd-linux-amd64": {Data: []byte("amd64-binary")},
	})
	deps.Pins = api.NewPinProvider(api.PinProviderConfig{StaticPin: testPin},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	deps.AgentPublicURL = "https://agent.gssh.example.com"
	deps.PublicBaseURL = "https://gssh.example.com/"
}

// mintToken ruft den Mint-Endpunkt und liefert Status und Rohbody.
func mintToken(t *testing.T, env *uiTestEnv, token string, payload any) (int, []byte) {
	t.Helper()
	return adminCall(t, http.MethodPost, env.srv.URL+"/v1/admin/enroll-tokens", token, payload)
}

// TestMintErfolg: Admin münzt ein Token — Klartext mit Prefix, Ablauf nach der
// gewünschten TTL, Install-Befehl mit Token und Flag, Record mit Hostname und
// Tags, Audit-Event ohne jede Token-Spur.
func TestMintErfolg(t *testing.T) {
	env := newUIServerWithDeps(t, rolloutReady)
	before := time.Now()

	status, body := mintToken(t, env, env.adminToken, map[string]any{
		"hostname": "web-01", "tags": map[string]string{"env": "prod"},
		"ttl_seconds": 3600, "session_audit": true,
	})
	if status != http.StatusCreated {
		t.Fatalf("status = %d (%s), erwartet 201", status, body)
	}
	var resp enrollTokenResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("antwort parsen: %v", err)
	}

	if !strings.HasPrefix(resp.Token, "gssh-et-") {
		t.Errorf("token = %q, erwartet prefix gssh-et-", resp.Token)
	}
	wantExpiry := before.Add(time.Hour)
	if delta := resp.ExpiresAt.Sub(wantExpiry); delta < -time.Minute || delta > time.Minute {
		t.Errorf("expires_at = %s, erwartet ≈ %s", resp.ExpiresAt, wantExpiry)
	}
	wantCmd := "curl -fsSL https://gssh.example.com/install.sh | sudo sh -s -- --token " +
		resp.Token + " --session-audit"
	if resp.InstallCommand != wantCmd {
		t.Errorf("install_command = %q, erwartet %q", resp.InstallCommand, wantCmd)
	}

	if len(env.ui.tokens) != 1 {
		t.Fatalf("%d token-records gespeichert, erwartet 1", len(env.ui.tokens))
	}
	rec := env.ui.tokens[0]
	if rec.HostName == nil || *rec.HostName != "web-01" {
		t.Errorf("host_name = %v, erwartet web-01", rec.HostName)
	}
	if rec.Tags["env"] != "prod" {
		t.Errorf("tags = %v, erwartet env=prod", rec.Tags)
	}
	hash := sha256.Sum256([]byte(resp.Token))
	if string(rec.TokenHash) != string(hash[:]) {
		t.Error("gespeicherter hash passt nicht zum ausgegebenen token")
	}

	if len(env.ui.events) != 1 {
		t.Fatalf("%d audit-events, erwartet 1", len(env.ui.events))
	}
	event := env.ui.events[0]
	if event.EventType != store.EventEnrollTokenCreated {
		t.Errorf("event_type = %q, erwartet %q", event.EventType, store.EventEnrollTokenCreated)
	}
	if event.Actor == "" {
		t.Error("actor fehlt im audit-event")
	}
	payload := string(event.Payload)
	if strings.Contains(payload, resp.Token) || strings.Contains(payload, "hash") {
		t.Errorf("audit-payload enthält token-material: %s", payload)
	}
	for _, want := range []string{`"hostname":"web-01"`, `"ttl_seconds":3600`, `"env":"prod"`, `"expires_at"`} {
		if !strings.Contains(payload, want) {
			t.Errorf("audit-payload %s enthält %s nicht", payload, want)
		}
	}
}

// TestMintDefaults: leerer Body ⇒ TTL-Default 1 h, ungebundenes Token, kein
// --session-audit im Install-Befehl.
func TestMintDefaults(t *testing.T) {
	env := newUIServerWithDeps(t, rolloutReady)
	before := time.Now()

	status, body := mintToken(t, env, env.adminToken, map[string]any{})
	if status != http.StatusCreated {
		t.Fatalf("status = %d (%s), erwartet 201", status, body)
	}
	var resp enrollTokenResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("antwort parsen: %v", err)
	}
	if delta := resp.ExpiresAt.Sub(before.Add(time.Hour)); delta < -time.Minute || delta > time.Minute {
		t.Errorf("expires_at = %s, erwartet ≈ jetzt+1h", resp.ExpiresAt)
	}
	if strings.Contains(resp.InstallCommand, "--session-audit") {
		t.Errorf("install_command = %q, erwartet ohne --session-audit", resp.InstallCommand)
	}
	if rec := env.ui.tokens[0]; rec.HostName != nil {
		t.Errorf("host_name = %v, erwartet ungebunden", *rec.HostName)
	}
}

// TestMintTTLGrenzen: außerhalb 60 ≤ ttl ≤ 86400 gibt es kein Token.
func TestMintTTLGrenzen(t *testing.T) {
	cases := map[string]int64{"zu kurz": 59, "zu lang": 86401, "negativ": -1}
	for name, ttl := range cases {
		t.Run(name, func(t *testing.T) {
			env := newUIServerWithDeps(t, rolloutReady)
			status, _ := mintToken(t, env, env.adminToken, map[string]any{"ttl_seconds": ttl})
			if status != http.StatusBadRequest {
				t.Fatalf("status = %d, erwartet 400", status)
			}
			if len(env.ui.tokens) != 0 {
				t.Error("token trotz ungültiger ttl gespeichert")
			}
		})
	}
}

// TestMintNurAdmin: Auditor und Read-only dürfen nicht minten.
func TestMintNurAdmin(t *testing.T) {
	env := newUIServerWithDeps(t, rolloutReady)
	for name, token := range map[string]string{
		"auditor": env.auditorToken, "readonly": env.readonlyToken, "ohne rolle": env.noRoleToken,
	} {
		t.Run(name, func(t *testing.T) {
			if status, _ := mintToken(t, env, token, map[string]any{}); status != http.StatusForbidden {
				t.Fatalf("status = %d, erwartet 403", status)
			}
		})
	}
	if status, _ := mintToken(t, env, "", map[string]any{}); status != http.StatusUnauthorized {
		t.Errorf("ohne token: status = %d, erwartet 401", status)
	}
	if len(env.ui.tokens) != 0 {
		t.Error("token trotz fehlender berechtigung gespeichert")
	}
}

// TestMintGateGeschlossen: fehlt eine Rollout-Bedingung, gibt es kein Token —
// die Antwort nennt genau die fehlende Bedingung.
func TestMintGateGeschlossen(t *testing.T) {
	env := newUIServerWithDeps(t, func(deps *api.Deps) {
		rolloutReady(deps)
		deps.AgentPublicURL = ""
	})
	status, body := mintToken(t, env, env.adminToken, map[string]any{})
	if status != http.StatusServiceUnavailable {
		t.Fatalf("status = %d (%s), erwartet 503", status, body)
	}
	var resp struct {
		Missing []string `json:"missing"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("antwort parsen: %v", err)
	}
	if len(resp.Missing) != 1 || resp.Missing[0] != "agent_public_url" {
		t.Errorf("missing = %v, erwartet [agent_public_url]", resp.Missing)
	}
	if len(env.ui.tokens) != 0 {
		t.Error("token trotz geschlossenem gate gespeichert")
	}
}

// TestMintStoreFehler: schlägt das Speichern fehl, gibt es weder Token noch
// Audit-Event.
func TestMintStoreFehler(t *testing.T) {
	env := newUIServerWithDeps(t, rolloutReady)
	env.ui.tokenErr = errors.New("datenbank weg")
	status, body := mintToken(t, env, env.adminToken, map[string]any{})
	if status != http.StatusInternalServerError {
		t.Fatalf("status = %d (%s), erwartet 500", status, body)
	}
	if strings.Contains(string(body), "gssh-et-") {
		t.Errorf("fehlerantwort enthält token: %s", body)
	}
	if len(env.ui.events) != 0 {
		t.Error("audit-event trotz fehlgeschlagenem speichern geschrieben")
	}
}
