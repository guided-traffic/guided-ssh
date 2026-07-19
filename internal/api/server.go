// Package api stellt die HTTP-API des gssh-servers bereit.
// Phase 2: CA-Bundle-Endpoint und Health-Check; Sign-Endpoints folgen ab Phase 3.
package api

import (
	"log/slog"
	"net/http"

	"github.com/guided-traffic/guided-ssh/internal/ca"
	"github.com/guided-traffic/guided-ssh/internal/store"
)

// New baut den HTTP-Handler.
//
// Routen:
//
//	GET /healthz                  – Liveness
//	GET /v1/ca/bundle/{purpose}   – CA-Bundle (authorized_keys-Format), purpose: user|host
func New(certAuthority *ca.CA, logger *slog.Logger) http.Handler {
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
		bundle, err := certAuthority.Bundle(r.Context(), purpose)
		if err != nil {
			logger.Error("ca-bundle laden fehlgeschlagen", "purpose", purpose, "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(bundle))
	})

	return mux
}
