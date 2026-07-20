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

// UIAuthConfig konfiguriert den server-seitigen OIDC-Login der Web-UI
// (BFF-Muster): der Server führt Authorization Code + PKCE mit Client-Secret
// aus, Tokens verlassen den Server nie — der Browser bekommt nur ein
// verschlüsseltes, HttpOnly-Session-Cookie. Kein CORS gegen den IdP.
type UIAuthConfig struct {
	// OAuth trägt Client, Secret, Endpoint und Scopes; RedirectURL bleibt
	// leer und wird pro Request abgeleitet (BaseURL bzw. Host-Header).
	OAuth *oauth2.Config
	// Verifier prüft die ID-Tokens des Code-Exchange (Audience = UI-Client).
	Verifier TokenVerifier
	// Codec ver-/entschlüsselt Session- und State-Cookies.
	Codec *auth.SessionCodec
	// BaseURL ist die externe Basis-URL der UI (https://gssh.example.com);
	// leer ⇒ Ableitung aus Request (X-Forwarded-Proto + Host).
	BaseURL string
	// SessionTTL ist die Lebensdauer der UI-Session; innerhalb dieser Zeit
	// bleiben die Gruppen-Claims des Logins wirksam (wie zuvor die Laufzeit
	// des ID-Tokens). Deaktivierte Benutzer blockt EnsureUser pro Request.
	SessionTTL time.Duration
}

// Cookie-Namen der UI-Session und des Login-Zustands (State + PKCE-Verifier
// zwischen /login und /callback).
const (
	sessionCookieName = "gssh_session"
	stateCookieName   = "gssh_auth_state"
)

// stateCookieTTL begrenzt die Dauer eines Login-Versuchs.
const stateCookieTTL = 10 * time.Minute

// uiSession ist der verschlüsselte Inhalt des Session-Cookies.
type uiSession struct {
	Claims    auth.Claims `json:"claims"`
	ExpiresAt time.Time   `json:"exp"`
}

// uiAuthState ist der verschlüsselte Inhalt des State-Cookies.
type uiAuthState struct {
	State     string    `json:"state"`
	Verifier  string    `json:"verifier"`
	Redirect  string    `json:"redirect"`
	ExpiresAt time.Time `json:"exp"`
}

// sessionFromRequest liest die UI-Session aus dem Cookie; nil, wenn keines
// da, ungültig oder abgelaufen ist (Aufrufer behandelt das als "nicht
// angemeldet", nie als Serverfehler).
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

// uiAuthContext bündelt die Abhängigkeiten der /v1/auth-Handler.
type uiAuthContext struct {
	cfg           *UIAuthConfig
	mapper        *auth.Mapper
	adminGroup    string
	auditorGroup  string
	readonlyGroup string
	logger        *slog.Logger
}

// registerUIAuthRoutes hängt die Login-Endpunkte der Web-UI an den Mux.
// Ohne UIAuth-Konfiguration antwortet /v1/auth mit 503 (diagnostizierbar).
func registerUIAuthRoutes(mux *http.ServeMux, deps Deps) {
	if deps.UIAuth == nil || deps.Store == nil {
		mux.HandleFunc("/v1/auth/", func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "ui-login nicht konfiguriert (server-seitiges oidc erforderlich)", http.StatusServiceUnavailable)
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

// oauthConfig liefert die OAuth-Konfiguration mit der Redirect-URL dieses
// Requests (Kopie — die geteilte Config bleibt unverändert).
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

// isSecureRequest erkennt HTTPS auch hinter dem Ingress (X-Forwarded-Proto).
func isSecureRequest(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// sanitizeRedirect erlaubt nur lokale Pfade als Rücksprung-Ziel (kein Open
// Redirect: keine absoluten URLs, keine protokoll-relativen "//…").
func sanitizeRedirect(target string) string {
	if !strings.HasPrefix(target, "/") || strings.HasPrefix(target, "//") {
		return "/"
	}
	return target
}

// handleLogin startet den Code-Flow: State + PKCE-Verifier wandern
// verschlüsselt in ein kurzlebiges Cookie, der Browser zum IdP.
func (u *uiAuthContext) handleLogin(w http.ResponseWriter, r *http.Request) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		u.logger.Error("ui-auth: state erzeugen fehlgeschlagen", "error", err)
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
		u.logger.Error("ui-auth: state-cookie versiegeln fehlgeschlagen", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: Secure bewusst dynamisch (isSecureRequest ⇒ hinter TLS/Ingress true, lokal http false); HttpOnly und SameSite sind gesetzt
		Name: stateCookieName, Value: sealed,
		Path: "/v1/auth", MaxAge: int(stateCookieTTL.Seconds()),
		HttpOnly: true, Secure: isSecureRequest(r), SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, u.oauthConfig(r).AuthCodeURL(state, oauth2.S256ChallengeOption(verifier)), http.StatusFound)
}

// callbackState validiert den Login-Zustand des Callbacks (State-Cookie
// vorhanden, entschlüsselbar, nicht abgelaufen, State-Parameter passt);
// false ⇒ Fehlerantwort wurde geschrieben.
func (u *uiAuthContext) callbackState(w http.ResponseWriter, r *http.Request) (*uiAuthState, bool) {
	cookie, err := r.Cookie(stateCookieName)
	if err != nil {
		http.Error(w, "login-state fehlt (login neu starten)", http.StatusBadRequest)
		return nil, false
	}
	u.clearCookie(w, r, stateCookieName, "/v1/auth")
	plaintext, err := u.cfg.Codec.Open(cookie.Value)
	if err != nil {
		http.Error(w, "login-state ungültig (login neu starten)", http.StatusBadRequest)
		return nil, false
	}
	var state uiAuthState
	if err := json.Unmarshal(plaintext, &state); err != nil || time.Now().After(state.ExpiresAt) {
		http.Error(w, "login-state abgelaufen (login neu starten)", http.StatusBadRequest)
		return nil, false
	}
	if stateParam := r.URL.Query().Get("state"); stateParam == "" || stateParam != state.State {
		http.Error(w, "state stimmt nicht überein (login neu starten)", http.StatusBadRequest)
		return nil, false
	}
	return &state, true
}

// handleCallback tauscht den Code server-seitig (Client-Secret + PKCE) gegen
// Tokens, prüft das ID-Token und setzt das Session-Cookie.
func (u *uiAuthContext) handleCallback(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	if errCode := query.Get("error"); errCode != "" {
		u.logger.Info("ui-auth: idp meldet fehler", "error", errCode, "description", query.Get("error_description"))
		http.Error(w, "login fehlgeschlagen: idp meldet "+errCode, http.StatusBadGateway)
		return
	}
	state, ok := u.callbackState(w, r)
	if !ok {
		return
	}

	token, err := u.oauthConfig(r).Exchange(r.Context(), query.Get("code"), oauth2.VerifierOption(state.Verifier))
	if err != nil {
		u.logger.Error("ui-auth: code-exchange fehlgeschlagen", "error", err)
		http.Error(w, "login fehlgeschlagen: code-exchange mit dem idp fehlgeschlagen", http.StatusBadGateway)
		return
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		u.logger.Error("ui-auth: token-antwort ohne id_token")
		http.Error(w, "login fehlgeschlagen: idp lieferte kein id_token", http.StatusBadGateway)
		return
	}
	claims, err := u.cfg.Verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		u.logger.Info("ui-auth: id-token abgelehnt", "error", err)
		http.Error(w, "id-token ungültig", http.StatusUnauthorized)
		return
	}
	if _, err := u.mapper.EnsureUser(r.Context(), claims); errors.Is(err, auth.ErrUserInactive) {
		http.Error(w, "benutzer ist deaktiviert", http.StatusForbidden)
		return
	} else if err != nil {
		u.logger.Error("ui-auth: benutzer-mapping fehlgeschlagen", "subject", claims.Subject, "error", err)
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
		u.logger.Error("ui-auth: session versiegeln fehlgeschlagen", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: Secure bewusst dynamisch (isSecureRequest ⇒ hinter TLS/Ingress true, lokal http false); HttpOnly und SameSite sind gesetzt
		Name: sessionCookieName, Value: sealed,
		Path: "/", MaxAge: int(u.cfg.SessionTTL.Seconds()),
		HttpOnly: true, Secure: isSecureRequest(r), SameSite: http.SameSiteLaxMode,
	})
	u.logger.Info("ui-auth: login erfolgreich", "subject", claims.Subject, "username", claims.Username())
	http.Redirect(w, r, state.Redirect, http.StatusFound)
}

// handleLogout löscht das Session-Cookie. Dex kennt kein RP-initiated
// Logout — die IdP-Session bleibt bestehen, der nächste Login läuft ggf.
// ohne erneute Passwort-Eingabe durch.
func (u *uiAuthContext) handleLogout(w http.ResponseWriter, r *http.Request) {
	u.clearCookie(w, r, sessionCookieName, "/")
	w.WriteHeader(http.StatusNoContent)
}

// authMeJSON ist die Antwort von GET /v1/auth/me.
type authMeJSON struct {
	Authenticated bool     `json:"authenticated"`
	Username      string   `json:"username,omitempty"`
	Roles         []string `json:"roles,omitempty"`
}

// handleMe liefert Login-Zustand, Benutzername und Rollen der Session —
// die einzige Auth-Information, die die SPA noch braucht.
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
		u.logger.Error("ui-auth: benutzer-mapping fehlgeschlagen", "subject", claims.Subject, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, authMeJSON{
		Authenticated: true,
		Username:      claims.Username(),
		Roles:         uiRoles(claims.Groups, u.adminGroup, u.auditorGroup, u.readonlyGroup),
	})
}

// uiRoles bildet Gruppen-Claims auf die Rollen-Hierarchie ab (admin ⊃
// auditor ⊃ readonly; leere Gruppen-Konfiguration vergibt nichts —
// fail-closed, konsistent zu adminContext.hasRole).
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

// clearCookie löscht ein Cookie (MaxAge < 0) mit identischen Attributen.
func (u *uiAuthContext) clearCookie(w http.ResponseWriter, r *http.Request, name, path string) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: Secure bewusst dynamisch (isSecureRequest ⇒ hinter TLS/Ingress true, lokal http false); HttpOnly und SameSite sind gesetzt
		Name: name, Value: "", Path: path, MaxAge: -1,
		HttpOnly: true, Secure: isSecureRequest(r), SameSite: http.SameSiteLaxMode,
	})
}
