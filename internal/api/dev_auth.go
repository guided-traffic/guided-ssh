package api

import (
	"errors"
	"net/http"

	"github.com/guided-traffic/guided-ssh/internal/auth"
)

// registerDevUIAuthRoutes replaces the OIDC login endpoints in the INSECURE
// developer mode (Deps.DevUser): /v1/auth/me always reports the dev user as
// logged in, /v1/auth/login just returns to the app, /v1/auth/logout is a
// no-op. Local frontend development (ng serve) only — the caller (main)
// guards activation behind an explicit env value and a startup warning.
func registerDevUIAuthRoutes(mux *http.ServeMux, deps Deps) {
	mapper := auth.NewMapper(deps.Store)
	mux.HandleFunc("GET /v1/auth/login", func(w http.ResponseWriter, r *http.Request) {
		// G710 taints every request-derived string; its sanitizer list is
		// hard-coded (PathEscape/QueryEscape/strconv only), so a validated
		// local path can never pass. sanitizeRedirect enforces local-path-only
		// (tested incl. backslash folding in ui_auth_test.go).
		//nolint:gosec // G710: sanitizeRedirect restricts the target to a local path
		http.Redirect(w, r, sanitizeRedirect(r.URL.Query().Get("redirect")), http.StatusFound)
	})
	mux.HandleFunc("POST /v1/auth/logout", func(w http.ResponseWriter, _ *http.Request) {
		// No session to clear — the next /me reports the dev user again.
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /v1/auth/me", func(w http.ResponseWriter, r *http.Request) {
		// EnsureUser keeps the dev user present in the database so audit
		// events and views behave like after a real login.
		if _, err := mapper.EnsureUser(r.Context(), deps.DevUser); err != nil && !errors.Is(err, auth.ErrUserInactive) {
			deps.Logger.Error("dev-auth: user mapping failed", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, authMeJSON{
			Authenticated: true,
			Username:      deps.DevUser.Username(),
			Roles:         uiRoles(deps.DevUser.Groups, deps.AdminGroup, deps.AuditorGroup),
		})
	})
}
