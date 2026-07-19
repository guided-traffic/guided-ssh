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

// keycloakEnv bündelt die URLs des laufenden Keycloak-Containers.
type keycloakEnv struct {
	baseURL string
	issuer  string
}

// startKeycloak startet Keycloak mit importiertem gssh-Realm.
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
		t.Fatalf("keycloak-container: %v", err)
	}
	endpoint, err := ctr.PortEndpoint(ctx, "8080/tcp", "http")
	if err != nil {
		t.Fatalf("keycloak-endpoint: %v", err)
	}
	return &keycloakEnv{
		baseURL: endpoint,
		issuer:  endpoint + "/realms/" + kcRealm,
	}
}

// startPostgres startet Postgres, migriert und liefert den Store.
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
		t.Fatalf("postgres-container: %v", err)
	}
	dsn, err := ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("postgres-dsn: %v", err)
	}
	if err := store.Migrate(ctx, dsn); err != nil {
		t.Fatalf("migrationen: %v", err)
	}
	st, err := store.New(ctx, dsn)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(st.Close)
	return st
}

// passwordGrant holt per Direct Access Grant ein ID-Token für den Benutzer.
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
		t.Fatalf("password-grant: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("password-grant: status %d: %s", resp.StatusCode, body)
	}
	var token struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &token); err != nil {
		t.Fatalf("token-antwort: %v", err)
	}
	if token.IDToken == "" {
		t.Fatal("kein id_token in antwort")
	}
	return token.IDToken
}

// adminToken holt ein Admin-API-Token über den Sync-Service-Account
// (im Test-Realm zusätzlich mit manage-users ausgestattet).
func (env *keycloakEnv) adminToken(t *testing.T) string {
	t.Helper()
	resp, err := http.PostForm(env.issuer+"/protocol/openid-connect/token", url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {kcSyncClient},
		"client_secret": {kcSyncSecret},
	})
	if err != nil {
		t.Fatalf("admin-token: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin-token: status %d: %s", resp.StatusCode, body)
	}
	var token struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &token); err != nil {
		t.Fatalf("admin-token dekodieren: %v", err)
	}
	return token.AccessToken
}

// adminRequest führt einen authentifizierten Admin-API-Call aus.
func (env *keycloakEnv) adminRequest(t *testing.T, method, path string, payload, target any) {
	t.Helper()
	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("payload marshalen: %v", err)
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, env.baseURL+"/admin/realms/"+kcRealm+path, body)
	if err != nil {
		t.Fatalf("admin-request bauen: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+env.adminToken(t))
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("admin-request %s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		t.Fatalf("admin-request %s %s: status %d: %s", method, path, resp.StatusCode, data)
	}
	if target != nil {
		if err := json.Unmarshal(data, target); err != nil {
			t.Fatalf("admin-antwort dekodieren: %v", err)
		}
	}
}

// userID sucht die Keycloak-ID eines Benutzers.
func (env *keycloakEnv) userID(t *testing.T, username string) string {
	t.Helper()
	var users []map[string]any
	env.adminRequest(t, http.MethodGet, "/users?username="+url.QueryEscape(username)+"&exact=true", nil, &users)
	if len(users) != 1 {
		t.Fatalf("benutzer %q: %d treffer", username, len(users))
	}
	id, _ := users[0]["id"].(string)
	if id == "" {
		t.Fatalf("benutzer %q ohne id", username)
	}
	return id
}

// TestKeycloakIntegration testet Phase 3 gegen echten Keycloak + Postgres:
// Token-Validierung, Sign-Endpoint, Gruppen-Sync und Offboarding.
// Die Subtests bauen aufeinander auf (gemeinsamer IdP-/DB-Zustand).
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
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := httptest.NewServer(api.New(api.Deps{
		CA: certAuthority, Store: st, Verifier: verifier, Logger: logger,
	}))
	defer srv.Close()

	source := auth.NewKeycloakSource(ctx, auth.KeycloakConfig{
		BaseURL:      env.baseURL,
		Realm:        kcRealm,
		ClientID:     kcSyncClient,
		ClientSecret: kcSyncSecret,
	})
	syncer := auth.NewSyncer(st, source, logger)

	idToken := env.passwordGrant(t, "alice", kcAlicePass)

	t.Run("TokenValidierungUndClaims", func(t *testing.T) {
		claims, err := verifier.Verify(ctx, idToken)
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if claims.Issuer != env.issuer || claims.PreferredUsername != "alice" || claims.Email != "alice@example.com" {
			t.Errorf("claims falsch: %+v", claims)
		}
		groups := slices.Clone(claims.Groups)
		slices.Sort(groups)
		if !slices.Equal(groups, []string{"admins", "dev"}) {
			t.Errorf("groups: %v", claims.Groups)
		}

		// Manipuliertes Token wird abgelehnt.
		if _, err := verifier.Verify(ctx, idToken+"x"); err == nil {
			t.Error("manipuliertes token wurde akzeptiert")
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

	t.Run("SignEndpointStelltZertifikatAus", func(t *testing.T) {
		status, body := signOnce(t, idToken)
		if status != http.StatusOK {
			t.Fatalf("sign: status %d: %s", status, body)
		}
		var resp struct {
			Certificate string   `json:"certificate"`
			Principals  []string `json:"principals"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			t.Fatalf("antwort dekodieren: %v", err)
		}
		parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(resp.Certificate))
		if err != nil {
			t.Fatalf("zertifikat parsen: %v", err)
		}
		cert, ok := parsed.(*ssh.Certificate)
		if !ok {
			t.Fatalf("kein zertifikat: %T", parsed)
		}
		if !slices.Contains(cert.ValidPrincipals, "alice") || !slices.Contains(cert.ValidPrincipals, "alice@example.com") {
			t.Errorf("principals: %v", cert.ValidPrincipals)
		}

		// Zertifikat verifiziert gegen das CA-Bundle (TrustedUserCAKeys).
		bundle, err := certAuthority.Bundle(ctx, store.CertTypeUser)
		if err != nil {
			t.Fatalf("bundle: %v", err)
		}
		caPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(bundle))
		if err != nil {
			t.Fatalf("ca-key parsen: %v", err)
		}
		checker := &ssh.CertChecker{
			IsUserAuthority: func(k ssh.PublicKey) bool {
				return bytes.Equal(k.Marshal(), caPub.Marshal())
			},
		}
		if err := checker.CheckCert("alice", cert); err != nil {
			t.Errorf("zertifikat nicht gegen ca verifizierbar: %v", err)
		}

		// Benutzer + Gruppen in DB angelegt.
		user, err := st.GetUserBySubject(ctx, env.issuer, env.userID(t, "alice"))
		if err != nil {
			t.Fatalf("benutzer in db: %v", err)
		}
		groups, err := st.ListUserGroups(ctx, user.ID)
		if err != nil {
			t.Fatalf("gruppen in db: %v", err)
		}
		if len(groups) != 2 {
			t.Errorf("db-gruppen: %d, erwartet 2", len(groups))
		}
	})

	t.Run("GruppenSyncEntferntGruppe", func(t *testing.T) {
		aliceID := env.userID(t, "alice")

		// Gruppe "admins" in Keycloak entziehen.
		var groups []map[string]any
		env.adminRequest(t, http.MethodGet, "/groups", nil, &groups)
		adminsID := ""
		for _, g := range groups {
			if g["name"] == "admins" {
				adminsID, _ = g["id"].(string)
			}
		}
		if adminsID == "" {
			t.Fatal("gruppe admins nicht gefunden")
		}
		env.adminRequest(t, http.MethodDelete, "/users/"+aliceID+"/groups/"+adminsID, nil, nil)

		if err := syncer.SyncOnce(ctx); err != nil {
			t.Fatalf("SyncOnce: %v", err)
		}
		user, err := st.GetUserBySubject(ctx, env.issuer, aliceID)
		if err != nil {
			t.Fatalf("benutzer in db: %v", err)
		}
		dbGroups, err := st.ListUserGroups(ctx, user.ID)
		if err != nil {
			t.Fatalf("gruppen in db: %v", err)
		}
		if len(dbGroups) != 1 || dbGroups[0].Name != "dev" {
			t.Errorf("db-gruppen nach sync: %+v, erwartet nur dev", dbGroups)
		}
	})

	t.Run("OffboardingBlockiertNeuausstellung", func(t *testing.T) {
		aliceID := env.userID(t, "alice")

		// Benutzer in Keycloak deaktivieren (vollständige Repräsentation PUTten).
		var user map[string]any
		env.adminRequest(t, http.MethodGet, "/users/"+aliceID, nil, &user)
		user["enabled"] = false
		env.adminRequest(t, http.MethodPut, "/users/"+aliceID, user, nil)

		if err := syncer.SyncOnce(ctx); err != nil {
			t.Fatalf("SyncOnce: %v", err)
		}

		// Token ist noch gültig — Ausstellung muss trotzdem scheitern (403).
		status, body := signOnce(t, idToken)
		if status != http.StatusForbidden {
			t.Fatalf("sign nach offboarding: status %d (erwartet 403): %s", status, body)
		}

		dbUser, err := st.GetUserBySubject(ctx, env.issuer, aliceID)
		if err != nil {
			t.Fatalf("benutzer in db: %v", err)
		}
		if dbUser.Active {
			t.Error("benutzer in db noch aktiv")
		}
		dbGroups, err := st.ListUserGroups(ctx, dbUser.ID)
		if err != nil {
			t.Fatalf("gruppen in db: %v", err)
		}
		if len(dbGroups) != 0 {
			t.Errorf("gruppen nicht entzogen: %+v", dbGroups)
		}
	})
}
