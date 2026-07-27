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

// fakeVerifier accepts exactly one token and returns fixed claims.
type fakeVerifier struct {
	token  string
	claims *auth.Claims
}

func (f *fakeVerifier) Verify(_ context.Context, rawToken string) (*auth.Claims, error) {
	if rawToken != f.token {
		return nil, fmt.Errorf("%w: unknown token", auth.ErrInvalidToken)
	}
	copied := *f.claims
	return &copied, nil
}

// fakeAuthStore is a minimal in-memory store for the sign endpoint (the
// auth.Store portion; the CA portion comes from fakeStore in
// server_test.go). As a GrantSource it returns by default a grant with a
// 16h maximum; noGrants and grantMaxSeconds control the phase-6 cases.
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

const testToken = "valid-test-token" //#nosec G101 -- test value, not a credential

func testClaims() *auth.Claims {
	return &auth.Claims{
		Issuer:            "https://idp.example.com/realms/gssh",
		Subject:           "alice-id",
		Email:             "alice@example.com",
		PreferredUsername: "alice",
		Groups:            []string{"admins"},
	}
}

// newSignServer builds the test server with the sign endpoint (real CA over fakeStore).
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

// testPublicKey creates an ed25519 public key in authorized_keys format.
func testPublicKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh public key: %v", err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
}

// postSign calls the sign endpoint.
func postSign(t *testing.T, url, token string, body any) (int, []byte) {
	t.Helper()
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshaling body: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, url+"/v1/sign/user", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("building request: %v", err)
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
		t.Fatalf("reading body: %v", err)
	}
	return resp.StatusCode, data
}

func TestSignUserSuccess(t *testing.T) {
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
		t.Fatalf("decoding response: %v", err)
	}

	// Parse the certificate and check its contents.
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(resp.Certificate))
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}
	cert, ok := parsed.(*ssh.Certificate)
	if !ok {
		t.Fatalf("not a certificate: %T", parsed)
	}
	if cert.KeyId != "user:alice-id@https://idp.example.com/realms/gssh" || cert.KeyId != resp.KeyID {
		t.Errorf("keyid: %q vs %q", cert.KeyId, resp.KeyID)
	}
	if !slices.Equal(cert.ValidPrincipals, []string{"alice", "alice@example.com"}) {
		t.Errorf("principals: %v", cert.ValidPrincipals)
	}
	if _, ok := cert.Extensions["permit-pty"]; !ok {
		t.Errorf("permit-pty missing: %v", cert.Extensions)
	}
	lifetime := time.Unix(int64(cert.ValidBefore), 0).Sub(time.Unix(int64(cert.ValidAfter), 0)) //nolint:gosec
	if lifetime < time.Hour || lifetime > time.Hour+2*time.Minute {
		t.Errorf("lifetime %s, expected ~1h", lifetime)
	}

	// User + group were created.
	if len(fs.users) != 1 || len(fs.groups) != 1 {
		t.Errorf("users=%d groups=%d, expected 1 each", len(fs.users), len(fs.groups))
	}
}

func TestSignUserDefaultValidity(t *testing.T) {
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
		t.Fatalf("decoding response: %v", err)
	}
	if lifetime := resp.ValidBefore.Sub(resp.ValidAfter); lifetime < 15*time.Hour || lifetime > 17*time.Hour {
		t.Errorf("default lifetime %s, expected ~16h", lifetime)
	}
}

func TestSignUserErrorCases(t *testing.T) {
	fs := newFakeAuthStore()
	// Grant allows 24h, so the policy (16h) rather than the grant rejects
	// the overlong request.
	fs.grantMaxSeconds = 24 * 3600
	srv := newSignServer(t, fs, &fakeVerifier{token: testToken, claims: testClaims()})
	validKey := testPublicKey(t)

	cases := []struct {
		name       string
		token      string
		body       any
		wantStatus int
	}{
		{"without token", "", map[string]any{"public_key": validKey}, http.StatusUnauthorized},
		{"wrong token", "wrong", map[string]any{"public_key": validKey}, http.StatusUnauthorized},
		{"broken body", testToken, "not-json", http.StatusBadRequest},
		{"broken key", testToken, map[string]any{"public_key": "not-a-key"}, http.StatusBadRequest},
		{"lifetime over policy maximum", testToken, map[string]any{
			"public_key": validKey, "validity_seconds": 24 * 3600,
		}, http.StatusBadRequest},
	}
	for _, c := range cases {
		if status, body := postSign(t, srv.URL, c.token, c.body); status != c.wantStatus {
			t.Errorf("%s: status %d (expected %d): %s", c.name, status, c.wantStatus, body)
		}
	}
}

func TestSignUserRejectedWithoutGrant(t *testing.T) {
	fs := newFakeAuthStore()
	fs.noGrants = true
	srv := newSignServer(t, fs, &fakeVerifier{token: testToken, claims: testClaims()})

	status, body := postSign(t, srv.URL, testToken, map[string]any{"public_key": testPublicKey(t)})
	if status != http.StatusForbidden {
		t.Fatalf("without grant: status %d (expected 403): %s", status, body)
	}
	if !strings.Contains(string(body), "grants") {
		t.Errorf("error message without a reference to grants: %s", body)
	}
	// A token that does carry groups must not get the scope hint — it would
	// point at the wrong cause.
	if strings.Contains(string(body), "groups claim") {
		t.Errorf("scope hint although the token carries groups: %s", body)
	}
}

// TestSignUserWithoutGroupsHintsAtScope: a token entirely without groups is
// almost always a client that never requested the groups scope — the 403
// says so instead of suggesting a missing grant.
func TestSignUserWithoutGroupsHintsAtScope(t *testing.T) {
	fs := newFakeAuthStore()
	fs.noGrants = true
	claims := testClaims()
	claims.Groups = nil
	srv := newSignServer(t, fs, &fakeVerifier{token: testToken, claims: claims})

	status, body := postSign(t, srv.URL, testToken, map[string]any{"public_key": testPublicKey(t)})
	if status != http.StatusForbidden {
		t.Fatalf("without groups: status %d (expected 403): %s", status, body)
	}
	if !strings.Contains(string(body), "groups") || !strings.Contains(string(body), "scope") {
		t.Errorf("403 without a hint at the groups scope: %s", body)
	}
}

func TestSignUserValidityCappedByGrant(t *testing.T) {
	fs := newFakeAuthStore()
	fs.grantMaxSeconds = 3600 // grant allows at most 1h
	srv := newSignServer(t, fs, &fakeVerifier{token: testToken, claims: testClaims()})

	// A request beyond the grant maximum gets capped instead of rejected.
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
		t.Fatalf("decoding response: %v", err)
	}
	if lifetime := resp.ValidBefore.Sub(resp.ValidAfter); lifetime != time.Hour {
		t.Errorf("lifetime %s, expected 1h (grant maximum)", lifetime)
	}
}

func TestSignUserCertificateAsKeyRejected(t *testing.T) {
	fs := newFakeAuthStore()
	srv := newSignServer(t, fs, &fakeVerifier{token: testToken, claims: testClaims()})

	// First get a real certificate, then submit it as public_key.
	status, body := postSign(t, srv.URL, testToken, map[string]any{"public_key": testPublicKey(t)})
	if status != http.StatusOK {
		t.Fatalf("setup certificate: status %d", status)
	}
	var resp struct {
		Certificate string `json:"certificate"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if status, _ := postSign(t, srv.URL, testToken, map[string]any{"public_key": resp.Certificate}); status != http.StatusBadRequest {
		t.Errorf("certificate as key: status %d, expected 400", status)
	}
}

func TestSignUserInactiveUser(t *testing.T) {
	fs := newFakeAuthStore()
	srv := newSignServer(t, fs, &fakeVerifier{token: testToken, claims: testClaims()})

	// Create the user (first issuance), then deactivate them.
	if status, _ := postSign(t, srv.URL, testToken, map[string]any{"public_key": testPublicKey(t)}); status != http.StatusOK {
		t.Fatal("setup failed")
	}
	for _, u := range fs.users {
		u.Active = false
	}
	if status, _ := postSign(t, srv.URL, testToken, map[string]any{"public_key": testPublicKey(t)}); status != http.StatusForbidden {
		t.Errorf("inactive user: status %d, expected 403", status)
	}
}

func TestSignUserMappingError(t *testing.T) {
	fs := newFakeAuthStore()
	fs.mappingError = errors.New("db broken")
	srv := newSignServer(t, fs, &fakeVerifier{token: testToken, claims: testClaims()})

	if status, _ := postSign(t, srv.URL, testToken, map[string]any{"public_key": testPublicKey(t)}); status != http.StatusInternalServerError {
		t.Errorf("mapping error: status %d, expected 500", status)
	}
}

func TestSignUserNegativeValidityFallsBackToDefault(t *testing.T) {
	fs := newFakeAuthStore()
	srv := newSignServer(t, fs, &fakeVerifier{token: testToken, claims: testClaims()})

	status, body := postSign(t, srv.URL, testToken, map[string]any{
		"public_key": testPublicKey(t), "validity_seconds": -3600,
	})
	if status != http.StatusOK {
		t.Fatalf("status %d: %s", status, body)
	}
	var resp struct {
		ValidAfter  time.Time `json:"valid_after"`
		ValidBefore time.Time `json:"valid_before"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if lifetime := resp.ValidBefore.Sub(resp.ValidAfter); lifetime < 15*time.Hour || lifetime > 17*time.Hour {
		t.Errorf("lifetime %s, expected default ~16h", lifetime)
	}
}

func TestSignUserBodyTooLarge(t *testing.T) {
	fs := newFakeAuthStore()
	srv := newSignServer(t, fs, &fakeVerifier{token: testToken, claims: testClaims()})

	// > 64 KiB ⇒ MaxBytesReader aborts decoding ⇒ 400.
	status, _ := postSign(t, srv.URL, testToken, map[string]any{
		"public_key": strings.Repeat("A", 100_000),
	})
	if status != http.StatusBadRequest {
		t.Errorf("oversized body: status %d, expected 400", status)
	}
}

func TestSignUserRateLimitAfterFailedAttempts(t *testing.T) {
	fs := newFakeAuthStore()
	masterKey := make([]byte, ca.MasterKeySize)
	certAuthority, err := ca.New(&fs.fakeStore, masterKey, ca.NewPolicyEngine(ca.DefaultPolicies()))
	if err != nil {
		t.Fatalf("ca.New: %v", err)
	}
	if err := certAuthority.EnsureCAKeys(context.Background()); err != nil {
		t.Fatalf("EnsureCAKeys: %v", err)
	}
	// Effectively no refill during the test: lockout after 2 failed attempts.
	limiter := api.NewRateLimiter(api.RateLimiterConfig{
		RequestsPerMinute: 600, Burst: 100,
		FailuresPerMinute: 0.001, FailureBurst: 2,
	})
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := httptest.NewServer(api.New(api.Deps{
		CA: certAuthority, Store: fs, Grants: fs,
		Verifier:  &fakeVerifier{token: testToken, claims: testClaims()},
		RateLimit: limiter, Logger: logger,
	}))
	t.Cleanup(srv.Close)
	validKey := testPublicKey(t)

	for i := range 2 {
		if status, _ := postSign(t, srv.URL, "wrong", map[string]any{"public_key": validKey}); status != http.StatusUnauthorized {
			t.Fatalf("failed attempt %d: status %d, expected 401", i+1, status)
		}
	}
	// Failure budget exhausted: even a valid request gets throttled.
	if status, _ := postSign(t, srv.URL, testToken, map[string]any{"public_key": validKey}); status != http.StatusTooManyRequests {
		t.Errorf("after failed attempts: status %d, expected 429", status)
	}
}

func TestSignUserWithoutOIDCConfiguration(t *testing.T) {
	srv := newTestServer(t, &fakeStore{}) // without Verifier/Store
	status, _ := postSign(t, srv.URL, testToken, map[string]any{"public_key": testPublicKey(t)})
	if status != http.StatusServiceUnavailable {
		t.Errorf("status %d, expected 503", status)
	}
}
