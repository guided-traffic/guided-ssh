package api_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/guided-traffic/guided-ssh/internal/api"
	"github.com/guided-traffic/guided-ssh/internal/auth"
	"github.com/guided-traffic/guided-ssh/internal/ca"
	"github.com/guided-traffic/guided-ssh/internal/store"
)

// fakeVerifier akzeptiert genau ein Token und liefert feste Claims.
type fakeVerifier struct {
	token  string
	claims *auth.Claims
}

func (f *fakeVerifier) Verify(_ context.Context, rawToken string) (*auth.Claims, error) {
	if rawToken != f.token {
		return nil, fmt.Errorf("%w: token unbekannt", auth.ErrInvalidToken)
	}
	copied := *f.claims
	return &copied, nil
}

// fakeAuthStore ist ein minimaler In-Memory-Store für den Sign-Endpoint
// (auth.Store-Anteil; der CA-Anteil kommt aus fakeStore in server_test.go).
// Als GrantSource liefert er standardmäßig einen Grant mit 16 h Maximum;
// noGrants bzw. grantMaxSeconds steuern die Phase-6-Fälle.
type fakeAuthStore struct {
	fakeStore
	users           map[uuid.UUID]*store.User
	groups          map[uuid.UUID]*store.Group
	userGroups      map[uuid.UUID][]uuid.UUID
	mappingError    error
	noGrants        bool
	grantMaxSeconds int64
}

func newFakeAuthStore() *fakeAuthStore {
	return &fakeAuthStore{
		users:      map[uuid.UUID]*store.User{},
		groups:     map[uuid.UUID]*store.Group{},
		userGroups: map[uuid.UUID][]uuid.UUID{},
	}
}

func (f *fakeAuthStore) GetUserBySubject(_ context.Context, issuer, subject string) (*store.User, error) {
	if f.mappingError != nil {
		return nil, f.mappingError
	}
	for _, u := range f.users {
		if u.Issuer == issuer && u.Subject == subject {
			copied := *u
			return &copied, nil
		}
	}
	return nil, store.ErrNotFound
}

func (f *fakeAuthStore) CreateUser(_ context.Context, u *store.User) error {
	u.ID = uuid.New()
	copied := *u
	f.users[u.ID] = &copied
	return nil
}

func (f *fakeAuthStore) UpdateUser(_ context.Context, u *store.User) error {
	copied := *u
	f.users[u.ID] = &copied
	return nil
}

func (f *fakeAuthStore) ListUsers(context.Context) ([]store.User, error) { return nil, nil }

func (f *fakeAuthStore) SetUserGroups(_ context.Context, userID uuid.UUID, groupIDs []uuid.UUID) error {
	f.userGroups[userID] = groupIDs
	return nil
}

func (f *fakeAuthStore) GetGroupByName(_ context.Context, issuer, name string) (*store.Group, error) {
	for _, g := range f.groups {
		if g.Issuer == issuer && g.Name == name {
			copied := *g
			return &copied, nil
		}
	}
	return nil, store.ErrNotFound
}

func (f *fakeAuthStore) CreateGroup(_ context.Context, g *store.Group) error {
	g.ID = uuid.New()
	copied := *g
	f.groups[g.ID] = &copied
	return nil
}

func (f *fakeAuthStore) ListGrantsForUser(_ context.Context, _ uuid.UUID) ([]store.AccessGrant, error) {
	if f.noGrants {
		return nil, nil
	}
	maxSeconds := f.grantMaxSeconds
	if maxSeconds == 0 {
		maxSeconds = 16 * 3600
	}
	return []store.AccessGrant{{
		ID: uuid.New(), GroupID: uuid.New(),
		Principals: []string{"deploy"}, MaxValiditySeconds: maxSeconds,
	}}, nil
}

const testToken = "gueltiges-test-token" //#nosec G101 -- Testwert, kein Credential

func testClaims() *auth.Claims {
	return &auth.Claims{
		Issuer:            "https://idp.example.com/realms/gssh",
		Subject:           "alice-id",
		Email:             "alice@example.com",
		PreferredUsername: "alice",
		Groups:            []string{"admins"},
	}
}

// newSignServer baut den Testserver mit Sign-Endpoint (echte CA über fakeStore).
func newSignServer(t *testing.T, fs *fakeAuthStore, verifier api.TokenVerifier) *httptest.Server {
	t.Helper()
	masterKey := make([]byte, ca.MasterKeySize)
	certAuthority, err := ca.New(&fs.fakeStore, masterKey, ca.NewPolicyEngine(ca.DefaultPolicies()))
	if err != nil {
		t.Fatalf("ca.New: %v", err)
	}
	if err := certAuthority.EnsureCAKeys(context.Background()); err != nil {
		t.Fatalf("EnsureCAKeys: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := httptest.NewServer(api.New(api.Deps{
		CA: certAuthority, Store: fs, Grants: fs, Verifier: verifier, Logger: logger,
	}))
	t.Cleanup(srv.Close)
	return srv
}

// testPublicKey erzeugt einen Ed25519-Public-Key im authorized_keys-Format.
func testPublicKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh-public-key: %v", err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
}

// postSign ruft den Sign-Endpoint auf.
func postSign(t *testing.T, url, token string, body any) (int, []byte) {
	t.Helper()
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("body marshalen: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, url+"/v1/sign/user", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("request bauen: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("body lesen: %v", err)
	}
	return resp.StatusCode, data
}

func TestSignUserErfolg(t *testing.T) {
	fs := newFakeAuthStore()
	srv := newSignServer(t, fs, &fakeVerifier{token: testToken, claims: testClaims()})

	status, body := postSign(t, srv.URL, testToken, map[string]any{
		"public_key":       testPublicKey(t),
		"validity_seconds": 3600,
	})
	if status != http.StatusOK {
		t.Fatalf("status %d: %s", status, body)
	}
	var resp struct {
		Certificate string    `json:"certificate"`
		Serial      int64     `json:"serial"`
		KeyID       string    `json:"key_id"`
		Principals  []string  `json:"principals"`
		ValidBefore time.Time `json:"valid_before"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("antwort dekodieren: %v", err)
	}

	// Zertifikat parsen und Inhalte prüfen.
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(resp.Certificate))
	if err != nil {
		t.Fatalf("zertifikat parsen: %v", err)
	}
	cert, ok := parsed.(*ssh.Certificate)
	if !ok {
		t.Fatalf("kein zertifikat: %T", parsed)
	}
	if cert.KeyId != "user:alice-id@https://idp.example.com/realms/gssh" || cert.KeyId != resp.KeyID {
		t.Errorf("keyid: %q vs %q", cert.KeyId, resp.KeyID)
	}
	if !slices.Equal(cert.ValidPrincipals, []string{"alice", "alice@example.com"}) {
		t.Errorf("principals: %v", cert.ValidPrincipals)
	}
	if _, ok := cert.Extensions["permit-pty"]; !ok {
		t.Errorf("permit-pty fehlt: %v", cert.Extensions)
	}
	lifetime := time.Unix(int64(cert.ValidBefore), 0).Sub(time.Unix(int64(cert.ValidAfter), 0)) //nolint:gosec
	if lifetime < time.Hour || lifetime > time.Hour+2*time.Minute {
		t.Errorf("laufzeit %s, erwartet ~1h", lifetime)
	}

	// Benutzer + Gruppe wurden angelegt.
	if len(fs.users) != 1 || len(fs.groups) != 1 {
		t.Errorf("users=%d groups=%d, erwartet je 1", len(fs.users), len(fs.groups))
	}
}

func TestSignUserDefaultLaufzeit(t *testing.T) {
	fs := newFakeAuthStore()
	srv := newSignServer(t, fs, &fakeVerifier{token: testToken, claims: testClaims()})

	status, body := postSign(t, srv.URL, testToken, map[string]any{"public_key": testPublicKey(t)})
	if status != http.StatusOK {
		t.Fatalf("status %d: %s", status, body)
	}
	var resp struct {
		ValidAfter  time.Time `json:"valid_after"`
		ValidBefore time.Time `json:"valid_before"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("antwort dekodieren: %v", err)
	}
	if lifetime := resp.ValidBefore.Sub(resp.ValidAfter); lifetime < 15*time.Hour || lifetime > 17*time.Hour {
		t.Errorf("default-laufzeit %s, erwartet ~16h", lifetime)
	}
}

func TestSignUserFehlerfaelle(t *testing.T) {
	fs := newFakeAuthStore()
	// Grant erlaubt 24 h, damit die Policy (16 h) und nicht der Grant die
	// überlange Anfrage ablehnt.
	fs.grantMaxSeconds = 24 * 3600
	srv := newSignServer(t, fs, &fakeVerifier{token: testToken, claims: testClaims()})
	validKey := testPublicKey(t)

	cases := []struct {
		name       string
		token      string
		body       any
		wantStatus int
	}{
		{"ohne token", "", map[string]any{"public_key": validKey}, http.StatusUnauthorized},
		{"falsches token", "falsch", map[string]any{"public_key": validKey}, http.StatusUnauthorized},
		{"kaputter body", testToken, "kein-json", http.StatusBadRequest},
		{"kaputter key", testToken, map[string]any{"public_key": "kein-key"}, http.StatusBadRequest},
		{"laufzeit über policy-maximum", testToken, map[string]any{
			"public_key": validKey, "validity_seconds": 24 * 3600,
		}, http.StatusBadRequest},
	}
	for _, c := range cases {
		if status, body := postSign(t, srv.URL, c.token, c.body); status != c.wantStatus {
			t.Errorf("%s: status %d (erwartet %d): %s", c.name, status, c.wantStatus, body)
		}
	}
}

func TestSignUserOhneGrantAbgelehnt(t *testing.T) {
	fs := newFakeAuthStore()
	fs.noGrants = true
	srv := newSignServer(t, fs, &fakeVerifier{token: testToken, claims: testClaims()})

	status, body := postSign(t, srv.URL, testToken, map[string]any{"public_key": testPublicKey(t)})
	if status != http.StatusForbidden {
		t.Fatalf("ohne grant: status %d (erwartet 403): %s", status, body)
	}
	if !strings.Contains(string(body), "grants") {
		t.Errorf("fehlermeldung ohne hinweis auf grants: %s", body)
	}
}

func TestSignUserLaufzeitDurchGrantGedeckelt(t *testing.T) {
	fs := newFakeAuthStore()
	fs.grantMaxSeconds = 3600 // Grant erlaubt maximal 1 h
	srv := newSignServer(t, fs, &fakeVerifier{token: testToken, claims: testClaims()})

	// Anfrage über dem Grant-Maximum wird gekappt statt abgelehnt.
	status, body := postSign(t, srv.URL, testToken, map[string]any{
		"public_key": testPublicKey(t), "validity_seconds": 8 * 3600,
	})
	if status != http.StatusOK {
		t.Fatalf("status %d: %s", status, body)
	}
	var resp struct {
		ValidAfter  time.Time `json:"valid_after"`
		ValidBefore time.Time `json:"valid_before"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("antwort dekodieren: %v", err)
	}
	if lifetime := resp.ValidBefore.Sub(resp.ValidAfter); lifetime != time.Hour {
		t.Errorf("laufzeit %s, erwartet 1h (grant-maximum)", lifetime)
	}
}

func TestSignUserZertifikatAlsKeyAbgelehnt(t *testing.T) {
	fs := newFakeAuthStore()
	srv := newSignServer(t, fs, &fakeVerifier{token: testToken, claims: testClaims()})

	// Erst ein echtes Zertifikat holen, dann als public_key einreichen.
	status, body := postSign(t, srv.URL, testToken, map[string]any{"public_key": testPublicKey(t)})
	if status != http.StatusOK {
		t.Fatalf("setup-zertifikat: status %d", status)
	}
	var resp struct {
		Certificate string `json:"certificate"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("antwort dekodieren: %v", err)
	}
	if status, _ := postSign(t, srv.URL, testToken, map[string]any{"public_key": resp.Certificate}); status != http.StatusBadRequest {
		t.Errorf("zertifikat als key: status %d, erwartet 400", status)
	}
}

func TestSignUserInaktiverBenutzer(t *testing.T) {
	fs := newFakeAuthStore()
	srv := newSignServer(t, fs, &fakeVerifier{token: testToken, claims: testClaims()})

	// Benutzer anlegen (erste Ausstellung), dann deaktivieren.
	if status, _ := postSign(t, srv.URL, testToken, map[string]any{"public_key": testPublicKey(t)}); status != http.StatusOK {
		t.Fatal("setup fehlgeschlagen")
	}
	for _, u := range fs.users {
		u.Active = false
	}
	if status, _ := postSign(t, srv.URL, testToken, map[string]any{"public_key": testPublicKey(t)}); status != http.StatusForbidden {
		t.Errorf("inaktiver benutzer: status %d, erwartet 403", status)
	}
}

func TestSignUserMappingFehler(t *testing.T) {
	fs := newFakeAuthStore()
	fs.mappingError = errors.New("db kaputt")
	srv := newSignServer(t, fs, &fakeVerifier{token: testToken, claims: testClaims()})

	if status, _ := postSign(t, srv.URL, testToken, map[string]any{"public_key": testPublicKey(t)}); status != http.StatusInternalServerError {
		t.Errorf("mapping-fehler: status %d, erwartet 500", status)
	}
}

func TestSignUserOhneOIDCKonfiguration(t *testing.T) {
	srv := newTestServer(t, &fakeStore{}) // ohne Verifier/Store
	status, _ := postSign(t, srv.URL, testToken, map[string]any{"public_key": testPublicKey(t)})
	if status != http.StatusServiceUnavailable {
		t.Errorf("status %d, erwartet 503", status)
	}
}
