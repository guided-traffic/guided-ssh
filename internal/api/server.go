// Package api stellt die HTTP-API des gssh-servers bereit.
// Phase 2: CA-Bundle-Endpoint und Health-Check; Phase 3: POST /v1/sign/user
// (ID-Token rein, SSH-Benutzerzertifikat raus).
package api

import (
	"log/slog"
	"net/http"

	"github.com/guided-traffic/guided-ssh/internal/auth"
	"github.com/guided-traffic/guided-ssh/internal/ca"
	"github.com/guided-traffic/guided-ssh/internal/store"
)

// Deps sind die Abhängigkeiten des HTTP-Handlers. Verifier und Store sind
// optional: ohne sie antwortet der Sign-Endpoint mit 503 (OIDC nicht
// konfiguriert). Ohne Hosts bleibt das Enrollment deaktiviert (Tests).
type Deps struct {
	CA       *ca.CA
	Store    auth.Store
	Hosts    HostStore
	Verifier TokenVerifier
	Logger   *slog.Logger
}

// New baut den HTTP-Handler.
//
// Routen:
//
//	GET  /healthz                  – Liveness
//	GET  /v1/ca/bundle/{purpose}   – CA-Bundle (authorized_keys-Format), purpose: user|host
//	POST /v1/sign/user             – ID-Token gegen SSH-Benutzerzertifikat tauschen
//	POST /v1/enroll                – Host-Enrollment gegen einmaliges Token
//
// Die Agent-Endpunkte (/v1/agent/…) liegen im separaten mTLS-Handler, siehe NewAgent.
func New(deps Deps) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})

	mux.HandleFunc("GET /v1/ca/bundle/{purpose}", func(w http.ResponseWriter, r *http.Request) {
		purpose := r.PathValue("purpose")
		if purpose != store.CertTypeUser && purpose != store.CertTypeHost {
			http.Error(w, "unbekannter zweck (erlaubt: user, host)", http.StatusNotFound)
			return
		}
		bundle, err := deps.CA.Bundle(r.Context(), purpose)
		if err != nil {
			deps.Logger.Error("ca-bundle laden fehlgeschlagen", "purpose", purpose, "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(bundle))
	})

	if deps.Hosts != nil {
		mux.HandleFunc("POST /v1/enroll", handleEnroll(deps.CA, deps.Hosts, deps.Logger))
	}

	if deps.Verifier != nil && deps.Store != nil {
		mux.HandleFunc("POST /v1/sign/user",
			handleSignUser(deps.CA, deps.Verifier, auth.NewMapper(deps.Store), deps.Logger))
	} else {
		mux.HandleFunc("POST /v1/sign/user", func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "oidc nicht konfiguriert", http.StatusServiceUnavailable)
		})
	}

	return mux
}
