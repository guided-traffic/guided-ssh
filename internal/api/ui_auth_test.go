package api_test

import (
	"context"
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

	"golang.org/x/oauth2"

	"github.com/guided-traffic/guided-ssh/internal/api"
	"github.com/guided-traffic/guided-ssh/internal/auth"
	"github.com/guided-traffic/guided-ssh/internal/ca"
)

// uiIDToken is the ID token the fake token endpoint returns and the UI
// verifier accepts (separate from the bearer testToken).
const uiIDToken = "ui-id-token" //#nosec G101 -- test value, not a credential

// fakeTokenEndpoint is the fake IdP's token endpoint: returns uiIDToken and
// records the last request (code, PKCE verifier, client auth).
type fakeTokenEndpoint struct {
	srv      *httptest.Server
	lastForm url.Values
	lastUser string
}

func newFakeTokenEndpoint(t *testing.T) *fakeTokenEndpoint {
	t.Helper()
	ep := &fakeTokenEndpoint{}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "form invalid", http.StatusBadRequest)
			return
		}
		ep.lastForm = r.Form
		if user, _, ok := r.BasicAuth(); ok {
			ep.lastUser = user
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"id_token":     uiIDToken,
		})
	})
	ep.srv = httptest.NewServer(mux)
	t.Cleanup(ep.srv.Close)
	return ep
}

// newUIAuthServer builds the test server with BFF login enabled; claims
// are the claims the UI verifier returns for uiIDToken.
func newUIAuthServer(t *testing.T, fs *fakeAuthStore, tokens *fakeTokenEndpoint, claims *auth.Claims) *httptest.Server {
	t.Helper()
	masterKey := make([]byte, ca.MasterKeySize)
	certAuthority, err := ca.New(&fs.fakeStore, masterKey, ca.NewPolicyEngine(ca.DefaultPolicies()))
	if err != nil {
		t.Fatalf("ca.New: %v", err)
	}
	if err := certAuthority.EnsureCAKeys(context.Background()); err != nil {
		t.Fatalf("EnsureCAKeys: %v", err)
	}
	codec, err := auth.NewSessionCodec(make([]byte, 32))
	if err != nil {
		t.Fatalf("NewSessionCodec: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := httptest.NewServer(api.New(api.Deps{
		CA: certAuthority, Store: fs, Grants: fs, Admin: newFakeAdminStore(fs),
		Verifier: &fakeVerifier{token: testToken, claims: adminClaims()},
		Logger:   logger, AdminGroup: adminGroupName,
		UIAuth: &api.UIAuthConfig{
			OAuth: &oauth2.Config{
				ClientID:     "gssh-ui",
				ClientSecret: "ui-secret",
				Endpoint: oauth2.Endpoint{
					AuthURL:  tokens.srv.URL + "/auth",
					TokenURL: tokens.srv.URL + "/token",
				},
				Scopes: []string{"openid", "profile", "email", "groups"},
			},
			Verifier:   &fakeVerifier{token: uiIDToken, claims: claims},
			Codec:      codec,
			SessionTTL: time.Hour,
		},
	}))
	t.Cleanup(srv.Close)
	return srv
}

// noRedirectClient does not follow redirects — the tests check the
// Location header.
func noRedirectClient() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

// startLogin calls /v1/auth/login and returns the authorize URL and state cookie.
func startLogin(t *testing.T, srv *httptest.Server, redirect string) (*url.URL, *http.Cookie) {
	t.Helper()
	loginURL := srv.URL + "/v1/auth/login"
	if redirect != "" {
		loginURL += "?redirect=" + url.QueryEscape(redirect)
	}
	resp, err := noRedirectClient().Get(loginURL)
	if err != nil {
		t.Fatalf("GET /v1/auth/login: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("login status = %d, expected 302", resp.StatusCode)
	}
	authorizeURL, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parsing authorize url: %v", err)
	}
	idx := slices.IndexFunc(resp.Cookies(), func(c *http.Cookie) bool { return c.Name == "gssh_auth_state" })
	if idx < 0 {
		t.Fatal("state cookie missing")
	}
	return authorizeURL, resp.Cookies()[idx]
}

// finishLogin calls the callback with code + state and returns the response.
func finishLogin(t *testing.T, srv *httptest.Server, state string, cookie *http.Cookie) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/v1/auth/callback?code=test-code&state="+url.QueryEscape(state), nil)
	if err != nil {
		t.Fatalf("building callback request: %v", err)
	}
	req.AddCookie(cookie)
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatalf("GET /v1/auth/callback: %v", err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func sessionCookie(t *testing.T, resp *http.Response) *http.Cookie {
	t.Helper()
	idx := slices.IndexFunc(resp.Cookies(), func(c *http.Cookie) bool { return c.Name == "gssh_session" && c.Value != "" })
	if idx < 0 {
		t.Fatal("session cookie missing")
	}
	return resp.Cookies()[idx]
}

// getMe calls /v1/auth/me with an optional session cookie.
func getMe(t *testing.T, srv *httptest.Server, cookie *http.Cookie) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/v1/auth/me", nil)
	if err != nil {
		t.Fatalf("building me request: %v", err)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /v1/auth/me: %v", err)
	}
	defer resp.Body.Close()
	var payload map[string]any
	if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
			t.Fatalf("decoding me response: %v", err)
		}
	}
	return resp.StatusCode, payload
}

func TestUIAuthLoginRedirect(t *testing.T) {
	tokens := newFakeTokenEndpoint(t)
	srv := newUIAuthServer(t, newFakeAuthStore(), tokens, adminClaims())

	authorizeURL, _ := startLogin(t, srv, "/audit")
	query := authorizeURL.Query()
	if got := query.Get("client_id"); got != "gssh-ui" {
		t.Errorf("client_id = %q", got)
	}
	if got := query.Get("redirect_uri"); got != srv.URL+"/v1/auth/callback" {
		t.Errorf("redirect_uri = %q", got)
	}
	if query.Get("state") == "" || query.Get("code_challenge") == "" || query.Get("code_challenge_method") != "S256" {
		t.Errorf("state/pkce missing: %v", query)
	}
	if got := query.Get("scope"); !strings.Contains(got, "groups") {
		t.Errorf("scope = %q, expected groups", got)
	}
}

func TestUIAuthLoginCallbackFlow(t *testing.T) {
	tokens := newFakeTokenEndpoint(t)
	srv := newUIAuthServer(t, newFakeAuthStore(), tokens, adminClaims())

	authorizeURL, stateCookie := startLogin(t, srv, "/audit")
	resp := finishLogin(t, srv, authorizeURL.Query().Get("state"), stateCookie)
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("callback status = %d (%s), expected 302", resp.StatusCode, body)
	}
	if got := resp.Header.Get("Location"); got != "/audit" {
		t.Errorf("callback redirect = %q, expected /audit", got)
	}
	// The code exchange ran server-side with code, PKCE verifier, and client auth.
	if got := tokens.lastForm.Get("code"); got != "test-code" {
		t.Errorf("token request code = %q", got)
	}
	if tokens.lastForm.Get("code_verifier") == "" {
		t.Error("token request without code_verifier (pkce)")
	}
	if tokens.lastUser != "gssh-ui" && tokens.lastForm.Get("client_secret") != "ui-secret" {
		t.Error("token request without client secret")
	}

	// The session cookie carries user and roles.
	session := sessionCookie(t, resp)
	if !session.HttpOnly {
		t.Error("session cookie not httponly")
	}
	status, me := getMe(t, srv, session)
	if status != http.StatusOK || me["authenticated"] != true {
		t.Fatalf("me = %d %v", status, me)
	}
	if me["username"] != "admin" {
		t.Errorf("me username = %v", me["username"])
	}
	roles, _ := me["roles"].([]any)
	if !slices.Contains(roles, any("admin")) {
		t.Errorf("me roles = %v, expected admin", roles)
	}
}

func TestUIAuthCallbackStateMismatch(t *testing.T) {
	tokens := newFakeTokenEndpoint(t)
	srv := newUIAuthServer(t, newFakeAuthStore(), tokens, adminClaims())

	_, stateCookie := startLogin(t, srv, "")
	resp := finishLogin(t, srv, "other-state", stateCookie)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("callback with wrong state = %d, expected 400", resp.StatusCode)
	}
}

func TestUIAuthRedirectSanitized(t *testing.T) {
	tokens := newFakeTokenEndpoint(t)
	srv := newUIAuthServer(t, newFakeAuthStore(), tokens, adminClaims())

	// Absolute and protocol-relative targets are normalized to "/" (no open
	// redirect via the login endpoint).
	for _, target := range []string{"https://evil.example", "//evil.example/path"} {
		authorizeURL, stateCookie := startLogin(t, srv, target)
		resp := finishLogin(t, srv, authorizeURL.Query().Get("state"), stateCookie)
		if got := resp.Header.Get("Location"); got != "/" {
			t.Errorf("redirect %q → Location %q, expected /", target, got)
		}
	}
}

func TestUIAuthMeWithoutSession(t *testing.T) {
	tokens := newFakeTokenEndpoint(t)
	srv := newUIAuthServer(t, newFakeAuthStore(), tokens, adminClaims())

	status, me := getMe(t, srv, nil)
	if status != http.StatusOK || me["authenticated"] != false {
		t.Errorf("me without session = %d %v, expected authenticated=false", status, me)
	}

	// A broken cookie counts as "not logged in", never as a server error.
	status, me = getMe(t, srv, &http.Cookie{Name: "gssh_session", Value: "broken"})
	if status != http.StatusOK || me["authenticated"] != false {
		t.Errorf("me with broken cookie = %d %v", status, me)
	}
}

func TestUIAuthLogout(t *testing.T) {
	tokens := newFakeTokenEndpoint(t)
	srv := newUIAuthServer(t, newFakeAuthStore(), tokens, adminClaims())

	authorizeURL, stateCookie := startLogin(t, srv, "")
	session := sessionCookie(t, finishLogin(t, srv, authorizeURL.Query().Get("state"), stateCookie))

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/auth/logout", nil)
	if err != nil {
		t.Fatalf("building logout request: %v", err)
	}
	req.AddCookie(session)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /v1/auth/logout: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("logout status = %d, expected 204", resp.StatusCode)
	}
	idx := slices.IndexFunc(resp.Cookies(), func(c *http.Cookie) bool { return c.Name == "gssh_session" })
	if idx < 0 || resp.Cookies()[idx].MaxAge >= 0 {
		t.Error("logout does not delete the session cookie")
	}
}

// TestUIAuthAdminWithSession: the admin API accepts the UI session as
// authentication — but only with the X-Requested-With header (CSRF protection).
func TestUIAuthAdminWithSession(t *testing.T) {
	tokens := newFakeTokenEndpoint(t)
	srv := newUIAuthServer(t, newFakeAuthStore(), tokens, adminClaims())

	authorizeURL, stateCookie := startLogin(t, srv, "")
	session := sessionCookie(t, finishLogin(t, srv, authorizeURL.Query().Get("state"), stateCookie))

	call := func(withHeader bool) int {
		req, err := http.NewRequest(http.MethodGet, srv.URL+"/v1/admin/grants", nil)
		if err != nil {
			t.Fatalf("building request: %v", err)
		}
		req.AddCookie(session)
		if withHeader {
			req.Header.Set("X-Requested-With", "XMLHttpRequest")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET /v1/admin/grants: %v", err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}
	if status := call(true); status != http.StatusOK {
		t.Errorf("admin with session+header = %d, expected 200", status)
	}
	if status := call(false); status != http.StatusForbidden {
		t.Errorf("admin with session without header = %d, expected 403", status)
	}
}

func TestUIAuthExpiredSession(t *testing.T) {
	tokens := newFakeTokenEndpoint(t)
	fs := newFakeAuthStore()
	srv := newUIAuthServer(t, fs, tokens, adminClaims())

	// Seal a session with an expired exp directly (same key as the server:
	// zero-byte master key in tests).
	codec, err := auth.NewSessionCodec(make([]byte, 32))
	if err != nil {
		t.Fatalf("NewSessionCodec: %v", err)
	}
	payload, err := json.Marshal(map[string]any{
		"claims": adminClaims(),
		"exp":    time.Now().Add(-time.Minute).Format(time.RFC3339),
	})
	if err != nil {
		t.Fatalf("marshaling payload: %v", err)
	}
	sealed, err := codec.Seal(payload)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	status, me := getMe(t, srv, &http.Cookie{Name: "gssh_session", Value: sealed})
	if status != http.StatusOK || me["authenticated"] != false {
		t.Errorf("me with expired session = %d %v, expected authenticated=false", status, me)
	}
}

func TestUIAuthCallbackErrorPaths(t *testing.T) {
	tokens := newFakeTokenEndpoint(t)
	srv := newUIAuthServer(t, newFakeAuthStore(), tokens, adminClaims())
	client := noRedirectClient()

	get := func(path string, cookie *http.Cookie) int {
		req, err := http.NewRequest(http.MethodGet, srv.URL+path, nil)
		if err != nil {
			t.Fatalf("building request: %v", err)
		}
		if cookie != nil {
			req.AddCookie(cookie)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	// IdP reports an error back.
	if status := get("/v1/auth/callback?error=access_denied", nil); status != http.StatusBadGateway {
		t.Errorf("idp error: status %d, expected 502", status)
	}
	// Without, and with a broken, state cookie.
	if status := get("/v1/auth/callback?code=x&state=s", nil); status != http.StatusBadRequest {
		t.Errorf("without state cookie: status %d, expected 400", status)
	}
	if status := get("/v1/auth/callback?code=x&state=s", &http.Cookie{Name: "gssh_auth_state", Value: "broken"}); status != http.StatusBadRequest {
		t.Errorf("broken state cookie: status %d, expected 400", status)
	}
}

// TestUIAuthCallbackIdPBroken: an error during the code exchange, or a
// rejected/missing ID token, must never create a session.
func TestUIAuthCallbackIdPBroken(t *testing.T) {
	for name, testCase := range map[string]struct {
		handler http.HandlerFunc
		status  int
	}{
		"exchange fails": {
			handler: func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "broken", http.StatusInternalServerError)
			},
			status: http.StatusBadGateway,
		},
		"response without id_token": {
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"access_token":"x","token_type":"Bearer"}`))
			},
			status: http.StatusBadGateway,
		},
		"id_token rejected": {
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"access_token":"x","token_type":"Bearer","id_token":"unknown"}`))
			},
			status: http.StatusUnauthorized,
		},
	} {
		t.Run(name, func(t *testing.T) {
			tokens := newFakeTokenEndpoint(t)
			srv := newUIAuthServer(t, newFakeAuthStore(), tokens, adminClaims())
			tokens.srv.Config.Handler = testCase.handler
			authorizeURL, stateCookie := startLogin(t, srv, "")
			resp := finishLogin(t, srv, authorizeURL.Query().Get("state"), stateCookie)
			if resp.StatusCode != testCase.status {
				t.Errorf("status = %d, expected %d", resp.StatusCode, testCase.status)
			}
			if idx := slices.IndexFunc(resp.Cookies(), func(c *http.Cookie) bool {
				return c.Name == "gssh_session" && c.Value != ""
			}); idx >= 0 {
				t.Error("error case must not set a session")
			}
		})
	}
}

// TestUIAuthMeInactiveUser: /me checks the user on every call —
// deactivation takes effect immediately, not only after session expiry.
func TestUIAuthMeInactiveUser(t *testing.T) {
	tokens := newFakeTokenEndpoint(t)
	fs := newFakeAuthStore()
	srv := newUIAuthServer(t, fs, tokens, adminClaims())

	authorizeURL, stateCookie := startLogin(t, srv, "")
	session := sessionCookie(t, finishLogin(t, srv, authorizeURL.Query().Get("state"), stateCookie))
	for _, u := range fs.users {
		u.Active = false
	}
	status, me := getMe(t, srv, session)
	if status != http.StatusOK || me["authenticated"] != false {
		t.Errorf("me with inactive user = %d %v, expected authenticated=false", status, me)
	}
}

func TestUIAuthNotConfigured(t *testing.T) {
	fs := newFakeAuthStore()
	srv := newAdminServer(t, fs, newFakeAdminStore(fs), &fakeVerifier{token: testToken, claims: adminClaims()}, adminGroupName)

	resp, err := http.Get(srv.URL + "/v1/auth/me")
	if err != nil {
		t.Fatalf("GET /v1/auth/me: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("me without bff configuration = %d, expected 503", resp.StatusCode)
	}
}
