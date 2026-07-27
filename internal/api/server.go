// Package api provides the HTTP API of the gssh server.
// Phase 2: CA bundle endpoint and health check; phase 3: POST /v1/sign/user
// (ID token in, SSH user certificate out).
package api

import (
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"time"

	"github.com/guided-traffic/guided-ssh/internal/agentdist"
	"github.com/guided-traffic/guided-ssh/internal/auth"
	"github.com/guided-traffic/guided-ssh/internal/bindist"
	"github.com/guided-traffic/guided-ssh/internal/ca"
	"github.com/guided-traffic/guided-ssh/internal/metrics"
	"github.com/guided-traffic/guided-ssh/internal/store"
	"github.com/guided-traffic/guided-ssh/web"
)

// Deps are the dependencies of the HTTP handler. Verifier, Store, and
// Grants are optional: without them, the sign endpoint responds with 503
// (OIDC not configured). Without CIVerifier/CIStore, /v1/sign/ci stays
// disabled (503); without Hosts, enrollment stays disabled (tests);
// without Admin/AdminGroup, the admin API responds with 503.
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
	// RateLimit throttles the unauthenticated endpoints (sign, enroll)
	// per client IP (phase 10); nil ⇒ no rate limiting (tests).
	RateLimit *RateLimiter
	// DownloadRateLimit throttles only the binary download
	// (GET /v1/agents/{os}/{arch}). Its own, tighter instance: the binary
	// is 15-40 MB in size, the regular 60/min limiter would be too loose
	// as flood protection. nil ⇒ no rate limiting (tests).
	DownloadRateLimit *RateLimiter
	// HostCertValidity is the lifetime of issued host certificates;
	// 0 ⇒ default (30 days). The policy maximum always applies.
	HostCertValidity time.Duration
	// AdminGroup is the IdP group whose members may fully use the admin
	// API; empty ⇒ no mutations possible (fail-closed).
	AdminGroup string
	// AuditorGroup covers all read access: the resource views (hosts,
	// grants, users, service accounts) and reading/exporting the audit
	// log; AdminGroup includes this role. If both groups are empty, the
	// entire admin API stays disabled and the web-UI login rejects everyone.
	AuditorGroup string
	// UIConfig is served unauthenticated under /v1/ui/config and
	// bootstraps the web UI (OIDC discovery + role mapping in the frontend).
	UIConfig UIConfig
	// UIAuth enables the web UI's server-side OIDC login (/v1/auth/…,
	// BFF); nil ⇒ endpoints respond with 503.
	UIAuth *UIAuthConfig
	// DevUser enables the INSECURE developer mode (GSSH_DEV_UI_AUTH):
	// every request without a bearer token acts as this already
	// logged-in user, /v1/auth/… skips the IdP entirely. Local frontend
	// development only; nil ⇒ disabled.
	DevUser *auth.Claims
	// Agents provides the embedded gssh-agentd binaries of the
	// one-command host install; nil or empty ⇒ rollout gate closed.
	Agents AgentSource
	// Clients provides the embedded gssh client binaries of the
	// frontend-driven client install; nil or empty ⇒ client gate closed.
	Clients ClientSource
	// Pins determines the SPKI pin of the public TLS endpoint; nil or
	// "no pin determinable" ⇒ rollout gate closed (fail-closed, rule 3).
	Pins *PinProvider
	// AgentPublicURL is the external mTLS agent URL (GSSH_AGENT_PUBLIC_URL)
	// that enrolled hosts write into their config.yaml; empty ⇒ gate closed.
	AgentPublicURL string
	// PublicBaseURL is the external base URL of the public listener
	// (GSSH_PUBLIC_URL); empty ⇒ gate closed.
	PublicBaseURL string
	// Rules decides which rule domains accept API writes: in-app CRUD is an
	// opt-in, file-owned domains reject every write (GITOPS_EXTERNAL_RULES).
	// The zero value is the production default: CRUD blocked, apply open.
	Rules RulesConfig
}

// AgentSource provides metadata and content of the embedded agent binaries
// (*agentdist.Source satisfies it; tests use agentdist.NewFromFS).
type AgentSource interface {
	List() []agentdist.Info
	// Open streams the binary for os/arch; if none is embedded, the error
	// is agentdist.ErrNotFound.
	Open(osName, arch string) (io.ReadCloser, agentdist.Info, error)
}

// ClientSource provides metadata and content of the embedded gssh client
// binaries (*bindist.Source satisfies it; tests use clientdist.NewFromFS).
// Deliberately its own interface next to AgentSource: the two families come
// from separate embeds and separate gates, and mixing them up would serve
// the wrong binary under the right name.
type ClientSource interface {
	List() []bindist.Info
	// Open streams the binary for os/arch; if none is embedded, the error
	// is bindist.ErrNotFound.
	Open(osName, arch string) (io.ReadCloser, bindist.Info, error)
}

// UIConfig is the web UI's public bootstrap configuration. OIDCIssuer and
// OIDCClientID describe the clients' public OIDC client (CLI setup page,
// client.sh) — never the server's confidential login client.
type UIConfig struct {
	OIDCIssuer   string `json:"oidc_issuer"`
	OIDCClientID string `json:"oidc_client_id"`
	AdminGroup   string `json:"admin_group"`
	AuditorGroup string `json:"auditor_group"`
}

// New builds the HTTP handler.
//
// Routes:
//
//	GET  /healthz                  – liveness
//	GET  /v1/ca/bundle/{purpose}   – CA bundle (authorized_keys format), purpose: user|host
//	POST /v1/sign/user             – exchange ID token for an SSH user certificate
//	POST /v1/sign/ci               – exchange a GitLab job token for a CI certificate
//	POST /v1/enroll                – host enrollment against a one-time token
//	GET  /v1/agents                – manifest of agent binaries + rollout status
//	GET  /v1/agents/{os}/{arch}    – agent binary (one-command host install)
//	GET  /install.sh               – templated install script for hosts
//	GET  /v1/clients               – manifest of gssh client binaries + client status
//	GET  /v1/clients/{os}/{arch}   – gssh client binary (frontend client install)
//	GET  /client.sh                – templated install script for the client
//	/v1/admin/grants…              – grant management (CRUD + declarative apply),
//	                                 members of the admin group only
//	/v1/admin/ci-grants…           – CI grant management (analogous)
//
// The agent endpoints (/v1/agent/…) live in the separate mTLS handler, see NewAgent.
func New(deps Deps) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})

	// Web UI bootstrap configuration: deliberately unauthenticated, contains
	// only public values (issuer, client ID, role group names).
	mux.HandleFunc("GET /v1/ui/config", func(w http.ResponseWriter, _ *http.Request) {
		cfg := deps.UIConfig
		cfg.AdminGroup = deps.AdminGroup
		cfg.AuditorGroup = deps.AuditorGroup
		writeJSON(w, http.StatusOK, cfg)
	})

	mux.HandleFunc("GET /v1/ca/bundle/{purpose}", func(w http.ResponseWriter, r *http.Request) {
		purpose := r.PathValue("purpose")
		if purpose != store.CertTypeUser && purpose != store.CertTypeHost {
			http.Error(w, "unknown purpose (allowed: user, host)", http.StatusNotFound)
			return
		}
		bundle, err := deps.CA.Bundle(r.Context(), purpose)
		if err != nil {
			deps.Logger.Error("loading ca bundle failed", "purpose", purpose, "error", err)
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
			http.Error(w, "oidc not configured", http.StatusServiceUnavailable)
		})
	}

	if deps.CIVerifier != nil && deps.CIStore != nil {
		mux.HandleFunc("POST /v1/sign/ci",
			deps.RateLimit.limit(handleSignCI(deps.CA, deps.CIVerifier, deps.CIStore, deps.Logger)))
	} else {
		mux.HandleFunc("POST /v1/sign/ci", func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "gitlab ci not configured", http.StatusServiceUnavailable)
		})
	}

	registerRolloutRoutes(mux, deps)
	registerClientRoutes(mux, deps)
	registerUIAuthRoutes(mux, deps)
	registerAdminRoutes(mux, deps)

	// Web UI (phase 8): embedded Angular build as an SPA under /.
	// Deliberately without a method pattern (conflicts with "/v1/admin/");
	// the handler restricts itself to GET/HEAD.
	if dist, err := fs.Sub(web.Dist, "dist"); err == nil {
		mux.Handle("/", NewUIHandler(dist))
	}

	// Response counter by status code for the error rate metric (phase 11).
	return metrics.Middleware(mux)
}
