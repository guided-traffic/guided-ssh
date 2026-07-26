//go:build integration

package auth_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"golang.org/x/crypto/ssh"

	"github.com/guided-traffic/guided-ssh/internal/api"
	"github.com/guided-traffic/guided-ssh/internal/auth"
	"github.com/guided-traffic/guided-ssh/internal/ca"
	"github.com/guided-traffic/guided-ssh/internal/store"
)

const (
	kcImage      = "quay.io/keycloak/keycloak:26.4"
	kcRealm      = "gssh"
	kcAdminUser  = "admin"
	kcAdminPass  = "admin"
	kcCLIClient  = "gssh-cli"
	kcSyncClient = "gssh-sync"
	kcSyncSecret = "sync-secret"
	kcAlicePass  = "alice-password"
)

// keycloakEnv bundles the URLs of the running Keycloak container.
type keycloakEnv struct {
	baseURL string
	issuer  string
}

// startKeycloak starts Keycloak with the imported gssh realm.
func startKeycloak(t *testing.T, ctx context.Context) *keycloakEnv {
	t.Helper()
	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        kcImage,
			ExposedPorts: []string{"8080/tcp"},
			Env: map[string]string{
				"KC_BOOTSTRAP_ADMIN_USERNAME": kcAdminUser,
				"KC_BOOTSTRAP_ADMIN_PASSWORD": kcAdminPass,
			},
			Cmd: []string{"start-dev", "--import-realm"},
			Files: []testcontainers.ContainerFile{{
				HostFilePath:      "testdata/keycloak-realm.json",
				ContainerFilePath: "/opt/keycloak/data/import/gssh-realm.json",
				FileMode:          0o444,
			}},
			WaitingFor: wait.ForHTTP("/realms/" + kcRealm).
				WithPort("8080/tcp").
				WithStartupTimeout(3 * time.Minute),
		},
		Started: true,
	})
	if ctr != nil {
		t.Cleanup(func() { _ = testcontainers.TerminateContainer(ctr) })
	}
	if err != nil {
		if ctr != nil {
			if logs, logErr := ctr.Logs(context.Background()); logErr == nil {
				raw, _ := io.ReadAll(logs)
				t.Logf("keycloak logs:\n%s", raw)
			}
		}
		t.Fatalf("keycloak container: %v", err)
	}
	endpoint, err := ctr.PortEndpoint(ctx, "8080/tcp", "http")
	if err != nil {
		t.Fatalf("keycloak endpoint: %v", err)
	}
	return &keycloakEnv{
		baseURL: endpoint,
		issuer:  endpoint + "/realms/" + kcRealm,
	}
}

// startPostgres starts Postgres, migrates it, and returns the store.
func startPostgres(t *testing.T, ctx context.Context) *store.Store {
	t.Helper()
	ctr, err := tcpostgres.Run(ctx, "postgres:17-alpine",
		tcpostgres.WithDatabase("guidedssh"),
		tcpostgres.WithUsername("guidedssh"),
		tcpostgres.WithPassword("guidedssh"),
		tcpostgres.BasicWaitStrategies(),
	)
	if ctr != nil {
		t.Cleanup(func() { _ = testcontainers.TerminateContainer(ctr) })
	}
	if err != nil {
		t.Fatalf("postgres container: %v", err)
	}
	dsn, err := ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("postgres dsn: %v", err)
	}
	if err := store.Migrate(ctx, dsn); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	st, err := store.New(ctx, dsn)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(st.Close)
	return st
}

// passwordGrant fetches an ID token for the user via Direct Access Grant.
func (env *keycloakEnv) passwordGrant(t *testing.T, username, password string) string {
	t.Helper()
	resp, err := http.PostForm(env.issuer+"/protocol/openid-connect/token", url.Values{
		"grant_type": {"password"},
		"client_id":  {kcCLIClient},
		"username":   {username},
		"password":   {password},
		"scope":      {"openid"},
	})
	if err != nil {
		t.Fatalf("password grant: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("password grant: status %d: %s", resp.StatusCode, body)
	}
	var token struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &token); err != nil {
		t.Fatalf("token response: %v", err)
	}
	if token.IDToken == "" {
		t.Fatal("no id_token in response")
	}
	return token.IDToken
}

// adminToken fetches an Admin API token via the sync service account
// (additionally granted manage-users in the test realm).
func (env *keycloakEnv) adminToken(t *testing.T) string {
	t.Helper()
	resp, err := http.PostForm(env.issuer+"/protocol/openid-connect/token", url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {kcSyncClient},
		"client_secret": {kcSyncSecret},
	})
	if err != nil {
		t.Fatalf("admin token: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin token: status %d: %s", resp.StatusCode, body)
	}
	var token struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &token); err != nil {
		t.Fatalf("decoding admin token: %v", err)
	}
	return token.AccessToken
}

// adminRequest performs an authenticated Admin API call.
func (env *keycloakEnv) adminRequest(t *testing.T, method, path string, payload, target any) {
	t.Helper()
	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshaling payload: %v", err)
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, env.baseURL+"/admin/realms/"+kcRealm+path, body)
	if err != nil {
		t.Fatalf("building admin request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+env.adminToken(t))
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("admin request %s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		t.Fatalf("admin request %s %s: status %d: %s", method, path, resp.StatusCode, data)
	}
	if target != nil {
		if err := json.Unmarshal(data, target); err != nil {
			t.Fatalf("decoding admin response: %v", err)
		}
	}
}

// userID looks up a user's Keycloak ID.
func (env *keycloakEnv) userID(t *testing.T, username string) string {
	t.Helper()
	var users []map[string]any
	env.adminRequest(t, http.MethodGet, "/users?username="+url.QueryEscape(username)+"&exact=true", nil, &users)
	if len(users) != 1 {
		t.Fatalf("user %q: %d matches", username, len(users))
	}
	id, _ := users[0]["id"].(string)
	if id == "" {
		t.Fatalf("user %q has no id", username)
	}
	return id
}

// TestKeycloakIntegration tests Phase 3 against a real Keycloak + Postgres:
// token validation, sign endpoint, group sync, and offboarding.
// The subtests build on each other (shared IdP/DB state).
func TestKeycloakIntegration(t *testing.T) {
	ctx := context.Background()
	env := startKeycloak(t, ctx)
	st := startPostgres(t, ctx)

	verifier, err := auth.NewVerifier(ctx, auth.VerifierConfig{
		IssuerURL: env.issuer,
		ClientID:  kcCLIClient,
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	masterKey := make([]byte, ca.MasterKeySize)
	certAuthority, err := ca.New(st, masterKey, ca.NewPolicyEngine(ca.DefaultPolicies()))
	if err != nil {
		t.Fatalf("ca.New: %v", err)
	}
	if err := certAuthority.EnsureCAKeys(ctx); err != nil {
		t.Fatalf("EnsureCAKeys: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(t.Output(), nil))
	srv := httptest.NewServer(api.New(api.Deps{
		CA: certAuthority, Store: st, Grants: st, Verifier: verifier, Logger: logger,
	}))
	defer srv.Close()

	source := auth.NewKeycloakSource(ctx, auth.KeycloakConfig{
		BaseURL:      env.baseURL,
		Realm:        kcRealm,
		ClientID:     kcSyncClient,
		ClientSecret: kcSyncSecret,
	})
	syncer := auth.NewSyncer(st, source, logger)

	// Phase 6: without a grant the server issues no certificates. The group
	// is created up front as it would be via the Admin API (the first login
	// or sync links members); "admins" gets a grant onto the local user
	// deploy (empty selector = all hosts).
	adminsGroup := &store.Group{Issuer: env.issuer, Name: "admins"}
	if err := st.CreateGroup(ctx, adminsGroup); err != nil {
		t.Fatalf("creating group admins: %v", err)
	}
	grant := &store.AccessGrant{
		GroupID:            adminsGroup.ID,
		Principals:         []string{"deploy"},
		MaxValiditySeconds: 16 * 3600,
	}
	if err := st.CreateGrant(ctx, "test", grant); err != nil {
		t.Fatalf("creating grant: %v", err)
	}
	// Host for the host ACL checks (AuthorizedPrincipalsCommand path).
	host := &store.Host{Name: "web1.example.com"}
	if err := st.CreateHost(ctx, host); err != nil {
		t.Fatalf("creating host: %v", err)
	}

	idToken := env.passwordGrant(t, "alice", kcAlicePass)

	t.Run("TokenValidationAndClaims", func(t *testing.T) {
		claims, err := verifier.Verify(ctx, idToken)
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if claims.Issuer != env.issuer || claims.PreferredUsername != "alice" || claims.Email != "alice@example.com" {
			t.Errorf("claims wrong: %+v", claims)
		}
		groups := slices.Clone(claims.Groups)
		slices.Sort(groups)
		if !slices.Equal(groups, []string{"admins", "dev"}) {
			t.Errorf("groups: %v", claims.Groups)
		}

		// A tampered token is rejected.
		if _, err := verifier.Verify(ctx, idToken+"x"); err == nil {
			t.Error("tampered token was accepted")
		}
	})

	signOnce := func(t *testing.T, token string) (int, []byte) {
		t.Helper()
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("keygen: %v", err)
		}
		sshPub, err := ssh.NewPublicKey(pub)
		if err != nil {
			t.Fatalf("ssh-key: %v", err)
		}
		payload, _ := json.Marshal(map[string]any{
			"public_key":       strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))),
			"validity_seconds": 3600,
		})
		req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/sign/user", bytes.NewReader(payload))
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST sign: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, body
	}

	t.Run("SignEndpointIssuesCertificate", func(t *testing.T) {
		status, body := signOnce(t, idToken)
		if status != http.StatusOK {
			t.Fatalf("sign: status %d: %s", status, body)
		}
		var resp struct {
			Certificate string   `json:"certificate"`
			Principals  []string `json:"principals"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			t.Fatalf("decoding response: %v", err)
		}
		parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(resp.Certificate))
		if err != nil {
			t.Fatalf("parsing certificate: %v", err)
		}
		cert, ok := parsed.(*ssh.Certificate)
		if !ok {
			t.Fatalf("not a certificate: %T", parsed)
		}
		if !slices.Contains(cert.ValidPrincipals, "alice") || !slices.Contains(cert.ValidPrincipals, "alice@example.com") {
			t.Errorf("principals: %v", cert.ValidPrincipals)
		}

		// Certificate verifies against the CA bundle (TrustedUserCAKeys).
		bundle, err := certAuthority.Bundle(ctx, store.CertTypeUser)
		if err != nil {
			t.Fatalf("bundle: %v", err)
		}
		caPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(bundle))
		if err != nil {
			t.Fatalf("parsing ca key: %v", err)
		}
		checker := &ssh.CertChecker{
			IsUserAuthority: func(k ssh.PublicKey) bool {
				return bytes.Equal(k.Marshal(), caPub.Marshal())
			},
		}
		if err := checker.CheckCert("alice", cert); err != nil {
			t.Errorf("certificate not verifiable against ca: %v", err)
		}

		// User + groups created in the DB.
		user, err := st.GetUserBySubject(ctx, env.issuer, env.userID(t, "alice"))
		if err != nil {
			t.Fatalf("user in db: %v", err)
		}
		groups, err := st.ListUserGroups(ctx, user.ID)
		if err != nil {
			t.Fatalf("groups in db: %v", err)
		}
		if len(groups) != 2 {
			t.Errorf("db groups: %d, expected 2", len(groups))
		}

		// Host ACL: alice is authorized as deploy via the admins grant.
		principals, err := st.ListAuthorizedPrincipals(ctx, host.ID, "deploy")
		if err != nil {
			t.Fatalf("ListAuthorizedPrincipals: %v", err)
		}
		if !slices.Contains(principals, "alice") {
			t.Errorf("host acl without alice: %v", principals)
		}
	})

	t.Run("GroupSyncRemovesGroup", func(t *testing.T) {
		aliceID := env.userID(t, "alice")

		// Revoke the "admins" group in Keycloak.
		var groups []map[string]any
		env.adminRequest(t, http.MethodGet, "/groups", nil, &groups)
		adminsID := ""
		for _, g := range groups {
			if g["name"] == "admins" {
				adminsID, _ = g["id"].(string)
			}
		}
		if adminsID == "" {
			t.Fatal("group admins not found")
		}
		env.adminRequest(t, http.MethodDelete, "/users/"+aliceID+"/groups/"+adminsID, nil, nil)

		if err := syncer.SyncOnce(ctx); err != nil {
			t.Fatalf("SyncOnce: %v", err)
		}
		user, err := st.GetUserBySubject(ctx, env.issuer, aliceID)
		if err != nil {
			t.Fatalf("user in db: %v", err)
		}
		dbGroups, err := st.ListUserGroups(ctx, user.ID)
		if err != nil {
			t.Fatalf("groups in db: %v", err)
		}
		if len(dbGroups) != 1 || dbGroups[0].Name != "dev" {
			t.Errorf("db groups after sync: %+v, expected only dev", dbGroups)
		}
	})

	// E2E Phase 6: group removed (previous subtest) ⇒ the next login with a
	// fresh token fails and the host ACL is updated.
	t.Run("GrantRevocationBlocksIssuanceAndHostACL", func(t *testing.T) {
		freshToken := env.passwordGrant(t, "alice", kcAlicePass)
		status, body := signOnce(t, freshToken)
		if status != http.StatusForbidden {
			t.Fatalf("sign without grant: status %d (expected 403): %s", status, body)
		}
		if !strings.Contains(string(body), "grants") {
			t.Errorf("error message has no mention of grants: %s", body)
		}

		principals, err := st.ListAuthorizedPrincipals(ctx, host.ID, "deploy")
		if err != nil {
			t.Fatalf("ListAuthorizedPrincipals: %v", err)
		}
		if len(principals) != 0 {
			t.Errorf("host acl not updated: %v", principals)
		}
	})

	t.Run("OffboardingBlocksReissuance", func(t *testing.T) {
		aliceID := env.userID(t, "alice")

		// Deactivate the user in Keycloak (PUT the full representation).
		var user map[string]any
		env.adminRequest(t, http.MethodGet, "/users/"+aliceID, nil, &user)
		user["enabled"] = false
		env.adminRequest(t, http.MethodPut, "/users/"+aliceID, user, nil)

		if err := syncer.SyncOnce(ctx); err != nil {
			t.Fatalf("SyncOnce: %v", err)
		}

		// Token is still valid — issuance must still fail (403).
		status, body := signOnce(t, idToken)
		if status != http.StatusForbidden {
			t.Fatalf("sign after offboarding: status %d (expected 403): %s", status, body)
		}

		dbUser, err := st.GetUserBySubject(ctx, env.issuer, aliceID)
		if err != nil {
			t.Fatalf("user in db: %v", err)
		}
		if dbUser.Active {
			t.Error("user still active in db")
		}
		dbGroups, err := st.ListUserGroups(ctx, dbUser.ID)
		if err != nil {
			t.Fatalf("groups in db: %v", err)
		}
		if len(dbGroups) != 0 {
			t.Errorf("groups not revoked: %+v", dbGroups)
		}
	})
}
