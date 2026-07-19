// Package api stellt die HTTP-API des gssh-servers bereit.
// Phase 2: CA-Bundle-Endpoint und Health-Check; Phase 3: POST /v1/sign/user
// (ID-Token rein, SSH-Benutzerzertifikat raus).
package api

import (
	"io/fs"
	"log/slog"
	"net/http"
	"time"

	"github.com/guided-traffic/guided-ssh/internal/auth"
	"github.com/guided-traffic/guided-ssh/internal/ca"
	"github.com/guided-traffic/guided-ssh/internal/metrics"
	"github.com/guided-traffic/guided-ssh/internal/store"
	"github.com/guided-traffic/guided-ssh/web"
)

// Deps sind die Abhängigkeiten des HTTP-Handlers. Verifier, Store und Grants
// sind optional: ohne sie antwortet der Sign-Endpoint mit 503 (OIDC nicht
// konfiguriert). Ohne CIVerifier/CIStore bleibt /v1/sign/ci deaktiviert (503);
// ohne Hosts bleibt das Enrollment deaktiviert (Tests); ohne Admin/AdminGroup
// antwortet die Admin-API mit 503.
type Deps struct {
	CA         *ca.CA
	Store      auth.Store
	Hosts      HostStore
	Grants     GrantSource
	Admin      AdminStore
	UI         UIStore
	Verifier   TokenVerifier
	CIVerifier CITokenVerifier
	CIStore    CIStore
	Logger     *slog.Logger
	// RateLimit drosselt die unauthentifizierten Endpunkte (Sign, Enroll)
	// pro Client-IP (Phase 10); nil ⇒ kein Rate-Limiting (Tests).
	RateLimit *RateLimiter
	// HostCertValidity ist die Laufzeit ausgestellter Host-Zertifikate;
	// 0 ⇒ Default (30 Tage). Das Policy-Maximum greift immer.
	HostCertValidity time.Duration
	// AdminGroup ist die IdP-Gruppe, deren Mitglieder die Admin-API voll
	// nutzen dürfen; leer ⇒ keine Mutationen möglich (fail-closed).
	AdminGroup string
	// AuditorGroup darf zusätzlich zu den Read-only-Ansichten das Audit-Log
	// lesen und exportieren; AdminGroup schließt die Rolle ein.
	AuditorGroup string
	// ReadOnlyGroup darf die Ressourcen-Ansichten (Hosts, Grants, Benutzer,
	// Service-Accounts) lesen; Auditor und Admin schließen die Rolle ein.
	// Sind alle drei Gruppen leer, bleibt die gesamte Admin-API deaktiviert.
	ReadOnlyGroup string
	// UIConfig wird unauthentifiziert unter /v1/ui/config ausgeliefert und
	// bootstrapt die Web-UI (OIDC-Discovery + Rollen-Mapping im Frontend).
	UIConfig UIConfig
}

// UIConfig ist die öffentliche Bootstrap-Konfiguration der Web-UI.
type UIConfig struct {
	OIDCIssuer    string `json:"oidc_issuer"`
	OIDCClientID  string `json:"oidc_client_id"`
	AdminGroup    string `json:"admin_group"`
	AuditorGroup  string `json:"auditor_group"`
	ReadOnlyGroup string `json:"readonly_group"`
}

// New baut den HTTP-Handler.
//
// Routen:
//
//	GET  /healthz                  – Liveness
//	GET  /v1/ca/bundle/{purpose}   – CA-Bundle (authorized_keys-Format), purpose: user|host
//	POST /v1/sign/user             – ID-Token gegen SSH-Benutzerzertifikat tauschen
//	POST /v1/sign/ci               – GitLab-Job-Token gegen CI-Zertifikat tauschen
//	POST /v1/enroll                – Host-Enrollment gegen einmaliges Token
//	/v1/admin/grants…              – Grant-Verwaltung (CRUD + deklaratives Apply),
//	                                 nur für Mitglieder der Admin-Gruppe
//	/v1/admin/ci-grants…           – CI-Grant-Verwaltung (analog)
//
// Die Agent-Endpunkte (/v1/agent/…) liegen im separaten mTLS-Handler, siehe NewAgent.
func New(deps Deps) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})

	// Bootstrap-Konfiguration der Web-UI: bewusst unauthentifiziert, enthält
	// nur öffentliche Werte (Issuer, Client-ID, Rollen-Gruppennamen).
	mux.HandleFunc("GET /v1/ui/config", func(w http.ResponseWriter, _ *http.Request) {
		cfg := deps.UIConfig
		cfg.AdminGroup = deps.AdminGroup
		cfg.AuditorGroup = deps.AuditorGroup
		cfg.ReadOnlyGroup = deps.ReadOnlyGroup
		writeJSON(w, http.StatusOK, cfg)
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
		mux.HandleFunc("POST /v1/enroll", deps.RateLimit.limit(handleEnroll(deps.CA, deps.Hosts, deps.HostCertValidity, deps.Logger)))
	}

	if deps.Verifier != nil && deps.Store != nil && deps.Grants != nil {
		mux.HandleFunc("POST /v1/sign/user",
			deps.RateLimit.limit(handleSignUser(deps.CA, deps.Verifier, auth.NewMapper(deps.Store), deps.Grants, deps.Logger)))
	} else {
		mux.HandleFunc("POST /v1/sign/user", func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "oidc nicht konfiguriert", http.StatusServiceUnavailable)
		})
	}

	if deps.CIVerifier != nil && deps.CIStore != nil {
		mux.HandleFunc("POST /v1/sign/ci",
			deps.RateLimit.limit(handleSignCI(deps.CA, deps.CIVerifier, deps.CIStore, deps.Logger)))
	} else {
		mux.HandleFunc("POST /v1/sign/ci", func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "gitlab-ci nicht konfiguriert", http.StatusServiceUnavailable)
		})
	}

	registerAdminRoutes(mux, deps)

	// Web-UI (Phase 8): eingebetteter Angular-Build als SPA unter /.
	// Bewusst ohne Methoden-Pattern (Konflikt mit "/v1/admin/"); der Handler
	// beschränkt sich selbst auf GET/HEAD.
	if dist, err := fs.Sub(web.Dist, "dist"); err == nil {
		mux.Handle("/", NewUIHandler(dist))
	}

	// Antwort-Zähler nach Status-Code für die Fehlerraten-Metrik (Phase 11).
	return metrics.Middleware(mux)
}
