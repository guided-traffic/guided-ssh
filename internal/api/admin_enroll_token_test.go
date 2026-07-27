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

// testPin is a validly formed (never actually issued) base64 SPKI pin.
const testPin = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

// enrollTokenResponse is the response of POST /v1/admin/enroll-tokens.
type enrollTokenResponse struct {
	Token          string    `json:"token"`
	ExpiresAt      time.Time `json:"expires_at"`
	InstallCommand string    `json:"install_command"`
}

// rolloutReady satisfies all four gate conditions of the host rollout.
func rolloutReady(deps *api.Deps) {
	deps.Agents = agentdist.NewFromFS(fstest.MapFS{
		"gssh-agentd-linux-amd64": {Data: []byte("amd64-binary")},
	})
	deps.Pins = api.NewPinProvider(api.PinProviderConfig{StaticPin: testPin},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	deps.AgentPublicURL = "https://agent.gssh.example.com"
	deps.PublicBaseURL = "https://gssh.example.com/"
}

// mintToken calls the mint endpoint and returns status and raw body.
func mintToken(t *testing.T, env *uiTestEnv, token string, payload any) (int, []byte) {
	t.Helper()
	return adminCall(t, http.MethodPost, env.srv.URL+"/v1/admin/enroll-tokens", token, payload)
}

// TestMintSuccess: admin mints a token — plaintext with prefix, expiry after
// the requested TTL, install command with token and flag, record with
// hostname and tags, audit event with no trace of the token.
func TestMintSuccess(t *testing.T) {
	env := newUIServerWithDeps(t, rolloutReady)
	before := time.Now()

	status, body := mintToken(t, env, env.adminToken, map[string]any{
		"hostname": "web-01", "tags": map[string]string{"env": "prod"},
		"ttl_seconds": 3600, "session_audit": true,
	})
	if status != http.StatusCreated {
		t.Fatalf("status = %d (%s), expected 201", status, body)
	}
	var resp enrollTokenResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}

	if !strings.HasPrefix(resp.Token, "gssh-et-") {
		t.Errorf("token = %q, expected prefix gssh-et-", resp.Token)
	}
	wantExpiry := before.Add(time.Hour)
	if delta := resp.ExpiresAt.Sub(wantExpiry); delta < -time.Minute || delta > time.Minute {
		t.Errorf("expires_at = %s, expected ≈ %s", resp.ExpiresAt, wantExpiry)
	}
	wantCmd := "curl -fsSL https://gssh.example.com/install.sh | sudo sh -s -- --token " +
		resp.Token + " --session-audit"
	if resp.InstallCommand != wantCmd {
		t.Errorf("install_command = %q, expected %q", resp.InstallCommand, wantCmd)
	}

	if len(env.ui.tokens) != 1 {
		t.Fatalf("%d token records saved, expected 1", len(env.ui.tokens))
	}
	rec := env.ui.tokens[0]
	if rec.HostName == nil || *rec.HostName != "web-01" {
		t.Errorf("host_name = %v, expected web-01", rec.HostName)
	}
	if rec.Tags["env"] != "prod" {
		t.Errorf("tags = %v, expected env=prod", rec.Tags)
	}
	hash := sha256.Sum256([]byte(resp.Token))
	if string(rec.TokenHash) != string(hash[:]) {
		t.Error("stored hash does not match the issued token")
	}

	if len(env.ui.events) != 1 {
		t.Fatalf("%d audit events, expected 1", len(env.ui.events))
	}
	event := env.ui.events[0]
	if event.EventType != store.EventEnrollTokenCreated {
		t.Errorf("event_type = %q, expected %q", event.EventType, store.EventEnrollTokenCreated)
	}
	if event.Actor == "" {
		t.Error("actor missing in audit event")
	}
	payload := string(event.Payload)
	if strings.Contains(payload, resp.Token) || strings.Contains(payload, "hash") {
		t.Errorf("audit payload contains token material: %s", payload)
	}
	for _, want := range []string{`"hostname":"web-01"`, `"ttl_seconds":3600`, `"env":"prod"`, `"expires_at"`} {
		if !strings.Contains(payload, want) {
			t.Errorf("audit payload %s does not contain %s", payload, want)
		}
	}
}

// TestMintDefaults: empty body ⇒ TTL default of 1h, unbound token, no
// --session-audit in the install command.
func TestMintDefaults(t *testing.T) {
	env := newUIServerWithDeps(t, rolloutReady)
	before := time.Now()

	status, body := mintToken(t, env, env.adminToken, map[string]any{})
	if status != http.StatusCreated {
		t.Fatalf("status = %d (%s), expected 201", status, body)
	}
	var resp enrollTokenResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}
	if delta := resp.ExpiresAt.Sub(before.Add(time.Hour)); delta < -time.Minute || delta > time.Minute {
		t.Errorf("expires_at = %s, expected ≈ now+1h", resp.ExpiresAt)
	}
	if strings.Contains(resp.InstallCommand, "--session-audit") {
		t.Errorf("install_command = %q, expected without --session-audit", resp.InstallCommand)
	}
	if rec := env.ui.tokens[0]; rec.HostName != nil {
		t.Errorf("host_name = %v, expected unbound", *rec.HostName)
	}
}

// TestMintTTLBounds: outside 60 ≤ ttl ≤ 86400 there is no token.
func TestMintTTLBounds(t *testing.T) {
	cases := map[string]int64{"too short": 59, "too long": 86401, "negative": -1}
	for name, ttl := range cases {
		t.Run(name, func(t *testing.T) {
			env := newUIServerWithDeps(t, rolloutReady)
			status, _ := mintToken(t, env, env.adminToken, map[string]any{"ttl_seconds": ttl})
			if status != http.StatusBadRequest {
				t.Fatalf("status = %d, expected 400", status)
			}
			if len(env.ui.tokens) != 0 {
				t.Error("token saved despite invalid ttl")
			}
		})
	}
}

// TestMintAdminOnly: auditor must not be able to mint.
func TestMintAdminOnly(t *testing.T) {
	env := newUIServerWithDeps(t, rolloutReady)
	for name, token := range map[string]string{
		"auditor": env.auditorToken, "no role": env.noRoleToken,
	} {
		t.Run(name, func(t *testing.T) {
			if status, _ := mintToken(t, env, token, map[string]any{}); status != http.StatusForbidden {
				t.Fatalf("status = %d, expected 403", status)
			}
		})
	}
	if status, _ := mintToken(t, env, "", map[string]any{}); status != http.StatusUnauthorized {
		t.Errorf("without token: status = %d, expected 401", status)
	}
	if len(env.ui.tokens) != 0 {
		t.Error("token saved despite missing authorization")
	}
}

// TestMintGateClosed: if a rollout condition is missing, there is no
// token — the response names exactly the missing condition.
func TestMintGateClosed(t *testing.T) {
	env := newUIServerWithDeps(t, func(deps *api.Deps) {
		rolloutReady(deps)
		deps.AgentPublicURL = ""
	})
	status, body := mintToken(t, env, env.adminToken, map[string]any{})
	if status != http.StatusServiceUnavailable {
		t.Fatalf("status = %d (%s), expected 503", status, body)
	}
	var resp struct {
		Missing []string `json:"missing"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}
	if len(resp.Missing) != 1 || resp.Missing[0] != "agent_public_url" {
		t.Errorf("missing = %v, expected [agent_public_url]", resp.Missing)
	}
	if len(env.ui.tokens) != 0 {
		t.Error("token saved despite closed gate")
	}
}

// TestMintStoreError: if saving fails, there is neither a token nor an
// audit event.
func TestMintStoreError(t *testing.T) {
	env := newUIServerWithDeps(t, rolloutReady)
	env.ui.tokenErr = errors.New("database gone")
	status, body := mintToken(t, env, env.adminToken, map[string]any{})
	if status != http.StatusInternalServerError {
		t.Fatalf("status = %d (%s), expected 500", status, body)
	}
	if strings.Contains(string(body), "gssh-et-") {
		t.Errorf("error response contains token: %s", body)
	}
	if len(env.ui.events) != 0 {
		t.Error("audit event written despite failed save")
	}
}
