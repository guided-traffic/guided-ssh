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

// uiIDToken ist das ID-Token, das der Fake-Token-Endpoint liefert und der
// UI-Verifier akzeptiert (getrennt vom Bearer-testToken).
const uiIDToken = "ui-id-token" //#nosec G101 -- Testwert, kein Credential

// fakeTokenEndpoint ist der Token-Endpoint des Fake-IdP: liefert uiIDToken
// und protokolliert den letzten Request (Code, PKCE-Verifier, Client-Auth).
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
			http.Error(w, "form ungültig", http.StatusBadRequest)
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

// newUIAuthServer baut den Testserver mit aktiviertem BFF-Login; claims sind
// die Claims, die der UI-Verifier für uiIDToken liefert.
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

// noRedirectClient folgt Redirects nicht — die Tests prüfen Location-Header.
func noRedirectClient() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

// startLogin ruft /v1/auth/login auf und liefert Authorize-URL und State-Cookie.
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
		t.Fatalf("login status = %d, erwartet 302", resp.StatusCode)
	}
	authorizeURL, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("authorize-url parsen: %v", err)
	}
	idx := slices.IndexFunc(resp.Cookies(), func(c *http.Cookie) bool { return c.Name == "gssh_auth_state" })
	if idx < 0 {
		t.Fatal("state-cookie fehlt")
	}
	return authorizeURL, resp.Cookies()[idx]
}

// finishLogin ruft den Callback mit Code + State auf und liefert die Antwort.
func finishLogin(t *testing.T, srv *httptest.Server, state string, cookie *http.Cookie) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/v1/auth/callback?code=test-code&state="+url.QueryEscape(state), nil)
	if err != nil {
		t.Fatalf("callback-request bauen: %v", err)
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
		t.Fatal("session-cookie fehlt")
	}
	return resp.Cookies()[idx]
}

// getMe ruft /v1/auth/me mit optionalem Session-Cookie auf.
func getMe(t *testing.T, srv *httptest.Server, cookie *http.Cookie) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/v1/auth/me", nil)
	if err != nil {
		t.Fatalf("me-request bauen: %v", err)
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
			t.Fatalf("me-antwort dekodieren: %v", err)
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
		t.Errorf("state/pkce fehlen: %v", query)
	}
	if got := query.Get("scope"); !strings.Contains(got, "groups") {
		t.Errorf("scope = %q, erwartet groups", got)
	}
}

func TestUIAuthLoginCallbackFlow(t *testing.T) {
	tokens := newFakeTokenEndpoint(t)
	srv := newUIAuthServer(t, newFakeAuthStore(), tokens, adminClaims())

	authorizeURL, stateCookie := startLogin(t, srv, "/audit")
	resp := finishLogin(t, srv, authorizeURL.Query().Get("state"), stateCookie)
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("callback status = %d (%s), erwartet 302", resp.StatusCode, body)
	}
	if got := resp.Header.Get("Location"); got != "/audit" {
		t.Errorf("callback redirect = %q, erwartet /audit", got)
	}
	// Code-Exchange lief server-seitig mit Code, PKCE-Verifier und Client-Auth.
	if got := tokens.lastForm.Get("code"); got != "test-code" {
		t.Errorf("token-request code = %q", got)
	}
	if tokens.lastForm.Get("code_verifier") == "" {
		t.Error("token-request ohne code_verifier (pkce)")
	}
	if tokens.lastUser != "gssh-ui" && tokens.lastForm.Get("client_secret") != "ui-secret" {
		t.Error("token-request ohne client-secret")
	}

	// Session-Cookie trägt Benutzer und Rollen.
	session := sessionCookie(t, resp)
	if !session.HttpOnly {
		t.Error("session-cookie nicht httponly")
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
		t.Errorf("me roles = %v, erwartet admin", roles)
	}
}

func TestUIAuthCallbackStateMismatch(t *testing.T) {
	tokens := newFakeTokenEndpoint(t)
	srv := newUIAuthServer(t, newFakeAuthStore(), tokens, adminClaims())

	_, stateCookie := startLogin(t, srv, "")
	resp := finishLogin(t, srv, "anderer-state", stateCookie)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("callback mit falschem state = %d, erwartet 400", resp.StatusCode)
	}
}

func TestUIAuthRedirectSanitized(t *testing.T) {
	tokens := newFakeTokenEndpoint(t)
	srv := newUIAuthServer(t, newFakeAuthStore(), tokens, adminClaims())

	// Absolute und protokoll-relative Ziele werden auf "/" normalisiert
	// (kein Open Redirect über den Login-Endpoint).
	for _, target := range []string{"https://evil.example", "//evil.example/pfad"} {
		authorizeURL, stateCookie := startLogin(t, srv, target)
		resp := finishLogin(t, srv, authorizeURL.Query().Get("state"), stateCookie)
		if got := resp.Header.Get("Location"); got != "/" {
			t.Errorf("redirect %q → Location %q, erwartet /", target, got)
		}
	}
}

func TestUIAuthMeOhneSession(t *testing.T) {
	tokens := newFakeTokenEndpoint(t)
	srv := newUIAuthServer(t, newFakeAuthStore(), tokens, adminClaims())

	status, me := getMe(t, srv, nil)
	if status != http.StatusOK || me["authenticated"] != false {
		t.Errorf("me ohne session = %d %v, erwartet authenticated=false", status, me)
	}

	// Kaputtes Cookie zählt als "nicht angemeldet", nie als Serverfehler.
	status, me = getMe(t, srv, &http.Cookie{Name: "gssh_session", Value: "kaputt"})
	if status != http.StatusOK || me["authenticated"] != false {
		t.Errorf("me mit kaputtem cookie = %d %v", status, me)
	}
}

func TestUIAuthLogout(t *testing.T) {
	tokens := newFakeTokenEndpoint(t)
	srv := newUIAuthServer(t, newFakeAuthStore(), tokens, adminClaims())

	authorizeURL, stateCookie := startLogin(t, srv, "")
	session := sessionCookie(t, finishLogin(t, srv, authorizeURL.Query().Get("state"), stateCookie))

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/auth/logout", nil)
	if err != nil {
		t.Fatalf("logout-request bauen: %v", err)
	}
	req.AddCookie(session)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /v1/auth/logout: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("logout status = %d, erwartet 204", resp.StatusCode)
	}
	idx := slices.IndexFunc(resp.Cookies(), func(c *http.Cookie) bool { return c.Name == "gssh_session" })
	if idx < 0 || resp.Cookies()[idx].MaxAge >= 0 {
		t.Error("logout löscht das session-cookie nicht")
	}
}

// TestUIAuthAdminMitSession: die Admin-API akzeptiert die UI-Session als
// Authentifizierung — aber nur mit X-Requested-With-Header (CSRF-Schutz).
func TestUIAuthAdminMitSession(t *testing.T) {
	tokens := newFakeTokenEndpoint(t)
	srv := newUIAuthServer(t, newFakeAuthStore(), tokens, adminClaims())

	authorizeURL, stateCookie := startLogin(t, srv, "")
	session := sessionCookie(t, finishLogin(t, srv, authorizeURL.Query().Get("state"), stateCookie))

	call := func(withHeader bool) int {
		req, err := http.NewRequest(http.MethodGet, srv.URL+"/v1/admin/grants", nil)
		if err != nil {
			t.Fatalf("request bauen: %v", err)
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
		t.Errorf("admin mit session+header = %d, erwartet 200", status)
	}
	if status := call(false); status != http.StatusForbidden {
		t.Errorf("admin mit session ohne header = %d, erwartet 403", status)
	}
}

func TestUIAuthAbgelaufeneSession(t *testing.T) {
	tokens := newFakeTokenEndpoint(t)
	fs := newFakeAuthStore()
	srv := newUIAuthServer(t, fs, tokens, adminClaims())

	// Session mit abgelaufenem exp direkt versiegeln (gleicher Schlüssel wie
	// der Server: Nullbytes-Master-Key der Tests).
	codec, err := auth.NewSessionCodec(make([]byte, 32))
	if err != nil {
		t.Fatalf("NewSessionCodec: %v", err)
	}
	payload, err := json.Marshal(map[string]any{
		"claims": adminClaims(),
		"exp":    time.Now().Add(-time.Minute).Format(time.RFC3339),
	})
	if err != nil {
		t.Fatalf("payload marshalen: %v", err)
	}
	sealed, err := codec.Seal(payload)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	status, me := getMe(t, srv, &http.Cookie{Name: "gssh_session", Value: sealed})
	if status != http.StatusOK || me["authenticated"] != false {
		t.Errorf("me mit abgelaufener session = %d %v, erwartet authenticated=false", status, me)
	}
}

func TestUIAuthCallbackFehlerpfade(t *testing.T) {
	tokens := newFakeTokenEndpoint(t)
	srv := newUIAuthServer(t, newFakeAuthStore(), tokens, adminClaims())
	client := noRedirectClient()

	get := func(path string, cookie *http.Cookie) int {
		req, err := http.NewRequest(http.MethodGet, srv.URL+path, nil)
		if err != nil {
			t.Fatalf("request bauen: %v", err)
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

	// IdP meldet Fehler zurück.
	if status := get("/v1/auth/callback?error=access_denied", nil); status != http.StatusBadGateway {
		t.Errorf("idp-fehler: status %d, erwartet 502", status)
	}
	// Ohne bzw. mit kaputtem State-Cookie.
	if status := get("/v1/auth/callback?code=x&state=s", nil); status != http.StatusBadRequest {
		t.Errorf("ohne state-cookie: status %d, erwartet 400", status)
	}
	if status := get("/v1/auth/callback?code=x&state=s", &http.Cookie{Name: "gssh_auth_state", Value: "kaputt"}); status != http.StatusBadRequest {
		t.Errorf("kaputtes state-cookie: status %d, erwartet 400", status)
	}
}

// TestUIAuthCallbackIdPKaputt: Fehler beim Code-Exchange bzw. ein
// abgelehntes/fehlendes ID-Token dürfen nie eine Session erzeugen.
func TestUIAuthCallbackIdPKaputt(t *testing.T) {
	for name, testCase := range map[string]struct {
		handler http.HandlerFunc
		status  int
	}{
		"exchange schlägt fehl": {
			handler: func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "kaputt", http.StatusInternalServerError)
			},
			status: http.StatusBadGateway,
		},
		"antwort ohne id_token": {
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"access_token":"x","token_type":"Bearer"}`))
			},
			status: http.StatusBadGateway,
		},
		"id_token abgelehnt": {
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"access_token":"x","token_type":"Bearer","id_token":"unbekannt"}`))
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
				t.Errorf("status = %d, erwartet %d", resp.StatusCode, testCase.status)
			}
			if idx := slices.IndexFunc(resp.Cookies(), func(c *http.Cookie) bool {
				return c.Name == "gssh_session" && c.Value != ""
			}); idx >= 0 {
				t.Error("fehlerfall darf keine session setzen")
			}
		})
	}
}

// TestUIAuthMeInaktiverBenutzer: /me prüft den Benutzer bei jedem Aufruf —
// Deaktivierung wirkt sofort, nicht erst nach Session-Ablauf.
func TestUIAuthMeInaktiverBenutzer(t *testing.T) {
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
		t.Errorf("me mit inaktivem benutzer = %d %v, erwartet authenticated=false", status, me)
	}
}

func TestUIAuthNichtKonfiguriert(t *testing.T) {
	fs := newFakeAuthStore()
	srv := newAdminServer(t, fs, newFakeAdminStore(fs), &fakeVerifier{token: testToken, claims: adminClaims()}, adminGroupName)

	resp, err := http.Get(srv.URL + "/v1/auth/me")
	if err != nil {
		t.Fatalf("GET /v1/auth/me: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("me ohne bff-konfiguration = %d, erwartet 503", resp.StatusCode)
	}
}
