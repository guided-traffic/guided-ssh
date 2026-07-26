package api

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/guided-traffic/guided-ssh/internal/auth"
)

// UIAuthConfig configures the web UI's server-side OIDC login (BFF
// pattern): the server performs authorization code + PKCE with a client
// secret, tokens never leave the server — the browser only gets an
// encrypted, HttpOnly session cookie. No CORS against the IdP.
type UIAuthConfig struct {
	// OAuth carries client, secret, endpoint, and scopes; RedirectURL
	// stays empty and is derived per request (BaseURL or the Host header).
	OAuth *oauth2.Config
	// Verifier checks the ID tokens of the code exchange (audience = UI client).
	Verifier TokenVerifier
	// Codec encrypts/decrypts session and state cookies.
	Codec *auth.SessionCodec
	// BaseURL is the UI's external base URL (https://gssh.example.com);
	// empty ⇒ derived from the request (X-Forwarded-Proto + Host).
	BaseURL string
	// SessionTTL is the lifetime of the UI session; within this time the
	// login's group claims stay in effect (like the ID token's lifetime
	// before). EnsureUser blocks disabled users on every request.
	SessionTTL time.Duration
}

// Cookie names of the UI session and the login state (state + PKCE
// verifier between /login and /callback).
const (
	sessionCookieName = "gssh_session"
	stateCookieName   = "gssh_auth_state"
)

// stateCookieTTL bounds the duration of a login attempt.
const stateCookieTTL = 10 * time.Minute

// uiSession is the encrypted content of the session cookie.
type uiSession struct {
	Claims    auth.Claims `json:"claims"`
	ExpiresAt time.Time   `json:"exp"`
}

// uiAuthState is the encrypted content of the state cookie.
type uiAuthState struct {
	State     string    `json:"state"`
	Verifier  string    `json:"verifier"`
	Redirect  string    `json:"redirect"`
	ExpiresAt time.Time `json:"exp"`
}

// sessionFromRequest reads the UI session from the cookie; nil if there is
// none, it is invalid, or it has expired (the caller treats this as "not
// logged in", never as a server error).
func (c *UIAuthConfig) sessionFromRequest(r *http.Request) *auth.Claims {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil
	}
	plaintext, err := c.Codec.Open(cookie.Value)
	if err != nil {
		return nil
	}
	var session uiSession
	if err := json.Unmarshal(plaintext, &session); err != nil || time.Now().After(session.ExpiresAt) {
		return nil
	}
	return &session.Claims
}

// uiAuthContext bundles the dependencies of the /v1/auth handlers.
type uiAuthContext struct {
	cfg           *UIAuthConfig
	mapper        *auth.Mapper
	adminGroup    string
	auditorGroup  string
	readonlyGroup string
	logger        *slog.Logger
}

// registerUIAuthRoutes attaches the web UI's login endpoints to the mux.
// Without a UIAuth configuration, /v1/auth responds with 503 (diagnosable).
func registerUIAuthRoutes(mux *http.ServeMux, deps Deps) {
	if deps.UIAuth == nil || deps.Store == nil {
		mux.HandleFunc("/v1/auth/", func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "ui login not configured (server-side oidc required)", http.StatusServiceUnavailable)
		})
		return
	}
	ui := &uiAuthContext{
		cfg:           deps.UIAuth,
		mapper:        auth.NewMapper(deps.Store),
		adminGroup:    deps.AdminGroup,
		auditorGroup:  deps.AuditorGroup,
		readonlyGroup: deps.ReadOnlyGroup,
		logger:        deps.Logger,
	}
	mux.HandleFunc("GET /v1/auth/login", ui.handleLogin)
	mux.HandleFunc("GET /v1/auth/callback", ui.handleCallback)
	mux.HandleFunc("POST /v1/auth/logout", ui.handleLogout)
	mux.HandleFunc("GET /v1/auth/me", ui.handleMe)
}

// oauthConfig returns the OAuth configuration with this request's redirect
// URL (a copy — the shared config stays unchanged).
func (u *uiAuthContext) oauthConfig(r *http.Request) *oauth2.Config {
	cfg := *u.cfg.OAuth
	base := u.cfg.BaseURL
	if base == "" {
		scheme := "http"
		if isSecureRequest(r) {
			scheme = "https"
		}
		base = scheme + "://" + r.Host
	}
	cfg.RedirectURL = base + "/v1/auth/callback"
	return &cfg
}

// isSecureRequest detects HTTPS even behind the ingress (X-Forwarded-Proto).
func isSecureRequest(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// sanitizeRedirect allows only local paths as the return target (no open
// redirect: no absolute URLs, no protocol-relative "//…").
func sanitizeRedirect(target string) string {
	if !strings.HasPrefix(target, "/") || strings.HasPrefix(target, "//") {
		return "/"
	}
	return target
}

// handleLogin starts the code flow: state + PKCE verifier travel encrypted
// in a short-lived cookie, the browser goes to the IdP.
func (u *uiAuthContext) handleLogin(w http.ResponseWriter, r *http.Request) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		u.logger.Error("ui-auth: generating state failed", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	state := base64.RawURLEncoding.EncodeToString(buf)
	verifier := oauth2.GenerateVerifier()

	payload, err := json.Marshal(uiAuthState{
		State:     state,
		Verifier:  verifier,
		Redirect:  sanitizeRedirect(r.URL.Query().Get("redirect")),
		ExpiresAt: time.Now().Add(stateCookieTTL),
	})
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	sealed, err := u.cfg.Codec.Seal(payload)
	if err != nil {
		u.logger.Error("ui-auth: sealing state cookie failed", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: Secure deliberately dynamic (isSecureRequest ⇒ true behind TLS/ingress, false for local http); HttpOnly and SameSite are set
		Name: stateCookieName, Value: sealed,
		Path: "/v1/auth", MaxAge: int(stateCookieTTL.Seconds()),
		HttpOnly: true, Secure: isSecureRequest(r), SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, u.oauthConfig(r).AuthCodeURL(state, oauth2.S256ChallengeOption(verifier)), http.StatusFound)
}

// callbackState validates the callback's login state (state cookie
// present, decryptable, not expired, state parameter matches); false ⇒ an
// error response was written.
func (u *uiAuthContext) callbackState(w http.ResponseWriter, r *http.Request) (*uiAuthState, bool) {
	cookie, err := r.Cookie(stateCookieName)
	if err != nil {
		http.Error(w, "login state missing (restart the login)", http.StatusBadRequest)
		return nil, false
	}
	u.clearCookie(w, r, stateCookieName, "/v1/auth")
	plaintext, err := u.cfg.Codec.Open(cookie.Value)
	if err != nil {
		http.Error(w, "login state invalid (restart the login)", http.StatusBadRequest)
		return nil, false
	}
	var state uiAuthState
	if err := json.Unmarshal(plaintext, &state); err != nil || time.Now().After(state.ExpiresAt) {
		http.Error(w, "login state expired (restart the login)", http.StatusBadRequest)
		return nil, false
	}
	if stateParam := r.URL.Query().Get("state"); stateParam == "" || stateParam != state.State {
		http.Error(w, "state does not match (restart the login)", http.StatusBadRequest)
		return nil, false
	}
	return &state, true
}

// handleCallback exchanges the code server-side (client secret + PKCE) for
// tokens, checks the ID token, and sets the session cookie.
func (u *uiAuthContext) handleCallback(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	if errCode := query.Get("error"); errCode != "" {
		u.logger.Info("ui-auth: idp reports an error", "error", errCode, "description", query.Get("error_description"))
		http.Error(w, "login failed: idp reports "+errCode, http.StatusBadGateway)
		return
	}
	state, ok := u.callbackState(w, r)
	if !ok {
		return
	}

	token, err := u.oauthConfig(r).Exchange(r.Context(), query.Get("code"), oauth2.VerifierOption(state.Verifier))
	if err != nil {
		u.logger.Error("ui-auth: code exchange failed", "error", err)
		http.Error(w, "login failed: code exchange with the idp failed", http.StatusBadGateway)
		return
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		u.logger.Error("ui-auth: token response without id_token")
		http.Error(w, "login failed: idp did not return an id_token", http.StatusBadGateway)
		return
	}
	claims, err := u.cfg.Verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		u.logger.Info("ui-auth: id token rejected", "error", err)
		http.Error(w, "id token invalid", http.StatusUnauthorized)
		return
	}
	if _, err := u.mapper.EnsureUser(r.Context(), claims); errors.Is(err, auth.ErrUserInactive) {
		http.Error(w, "user is disabled", http.StatusForbidden)
		return
	} else if err != nil {
		u.logger.Error("ui-auth: user mapping failed", "subject", claims.Subject, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	payload, err := json.Marshal(uiSession{Claims: *claims, ExpiresAt: time.Now().Add(u.cfg.SessionTTL)})
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	sealed, err := u.cfg.Codec.Seal(payload)
	if err != nil {
		u.logger.Error("ui-auth: sealing session failed", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: Secure deliberately dynamic (isSecureRequest ⇒ true behind TLS/ingress, false for local http); HttpOnly and SameSite are set
		Name: sessionCookieName, Value: sealed,
		Path: "/", MaxAge: int(u.cfg.SessionTTL.Seconds()),
		HttpOnly: true, Secure: isSecureRequest(r), SameSite: http.SameSiteLaxMode,
	})
	u.logger.Info("ui-auth: login successful", "subject", claims.Subject, "username", claims.Username())
	http.Redirect(w, r, state.Redirect, http.StatusFound)
}

// handleLogout deletes the session cookie. Dex has no RP-initiated
// logout — the IdP session stays alive, the next login may go through
// without re-entering a password.
func (u *uiAuthContext) handleLogout(w http.ResponseWriter, r *http.Request) {
	u.clearCookie(w, r, sessionCookieName, "/")
	w.WriteHeader(http.StatusNoContent)
}

// authMeJSON is the response of GET /v1/auth/me.
type authMeJSON struct {
	Authenticated bool     `json:"authenticated"`
	Username      string   `json:"username,omitempty"`
	Roles         []string `json:"roles,omitempty"`
}

// handleMe returns login state, username, and roles of the session — the
// only auth information the SPA still needs.
func (u *uiAuthContext) handleMe(w http.ResponseWriter, r *http.Request) {
	claims := u.cfg.sessionFromRequest(r)
	if claims == nil {
		writeJSON(w, http.StatusOK, authMeJSON{Authenticated: false})
		return
	}
	if _, err := u.mapper.EnsureUser(r.Context(), claims); errors.Is(err, auth.ErrUserInactive) {
		u.clearCookie(w, r, sessionCookieName, "/")
		writeJSON(w, http.StatusOK, authMeJSON{Authenticated: false})
		return
	} else if err != nil {
		u.logger.Error("ui-auth: user mapping failed", "subject", claims.Subject, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, authMeJSON{
		Authenticated: true,
		Username:      claims.Username(),
		Roles:         uiRoles(claims.Groups, u.adminGroup, u.auditorGroup, u.readonlyGroup),
	})
}

// uiRoles maps group claims onto the role hierarchy (admin ⊃ auditor ⊃
// readonly; an empty group configuration grants nothing — fail-closed,
// consistent with adminContext.hasRole).
func uiRoles(groups []string, adminGroup, auditorGroup, readonlyGroup string) []string {
	in := func(group string) bool {
		return group != "" && slices.Contains(groups, group)
	}
	isAdmin := in(adminGroup)
	isAuditor := isAdmin || in(auditorGroup)
	isReadOnly := isAuditor || in(readonlyGroup)
	roles := make([]string, 0, 3)
	if isAdmin {
		roles = append(roles, roleAdmin)
	}
	if isAuditor {
		roles = append(roles, roleAuditor)
	}
	if isReadOnly {
		roles = append(roles, roleReadOnly)
	}
	return roles
}

// clearCookie deletes a cookie (MaxAge < 0) with identical attributes.
func (u *uiAuthContext) clearCookie(w http.ResponseWriter, r *http.Request, name, path string) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: Secure deliberately dynamic (isSecureRequest ⇒ true behind TLS/ingress, false for local http); HttpOnly and SameSite are set
		Name: name, Value: "", Path: path, MaxAge: -1,
		HttpOnly: true, Secure: isSecureRequest(r), SameSite: http.SameSiteLaxMode,
	})
}
