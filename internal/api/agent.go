package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/guided-traffic/guided-ssh/internal/ca"
	"github.com/guided-traffic/guided-ssh/internal/metrics"
	"github.com/guided-traffic/guided-ssh/internal/store"
)

// AgentDeps are the dependencies of the agent API (mTLS listener).
type AgentDeps struct {
	CA     *ca.CA
	Hosts  HostStore
	Logger *slog.Logger
	// HostCertValidity is the lifetime of renewed host certificates;
	// 0 ⇒ default (30 days). The policy maximum always applies.
	HostCertValidity time.Duration
	// Sessions is optional (phase 9): if missing, POST /v1/agent/sessions
	// stays disabled (404). *store.Store satisfies the interface.
	Sessions SessionStore
}

// SessionStore is the set of store methods for recording host session and
// sudo events (*store.Store satisfies it; tests use a fake).
type SessionStore interface {
	OpenHostSession(ctx context.Context, e store.SessionEvent) error
	CloseHostSession(ctx context.Context, e store.SessionEvent) error
	RecordSudoEvent(ctx context.Context, e store.SessionEvent) error
}

// sessionEvent is a reported session/sudo event (wire format). Serial 0
// means "no correlated serial".
type sessionEvent struct {
	Phase      string    `json:"phase"`   // open | close
	Service    string    `json:"service"` // sshd | sudo
	LocalUser  string    `json:"local_user"`
	RemoteUser string    `json:"remote_user"`
	RemoteAddr string    `json:"remote_addr"`
	TTY        string    `json:"tty"`
	Serial     int64     `json:"serial"`
	KeyID      string    `json:"key_id"`
	Command    string    `json:"command"`
	OccurredAt time.Time `json:"occurred_at"`
}

// sessionsRequest is the body of POST /v1/agent/sessions (batch from the spool).
type sessionsRequest struct {
	Events []sessionEvent `json:"events"`
}

// renewRequest is the body of POST /v1/agent/renew.
type renewRequest struct {
	// PublicKey is the SSH host key in authorized_keys format.
	PublicKey string `json:"public_key"`
}

// renewResponse is the response: the renewed host certificate.
type renewResponse struct {
	Certificate string    `json:"certificate"`
	ValidBefore time.Time `json:"valid_before"`
}

// principalsResponse is the response of GET /v1/agent/principals.
type principalsResponse struct {
	Principals []string `json:"principals"`
}

// renewMTLSRequest is the body of POST /v1/agent/renew-mtls (phase 10:
// rotation of the mTLS client certificate over the existing mTLS channel).
type renewMTLSRequest struct {
	// CSR is the PEM-encoded certificate request; the server assigns the
	// identity (CN) from the verified client certificate.
	CSR string `json:"csr"`
}

// renewMTLSResponse is the response: the new mTLS client certificate (PEM).
type renewMTLSResponse struct {
	Certificate string `json:"certificate"`
}

// NewAgent builds the agent API's handler. It runs exclusively behind the
// mTLS listener: the host's identity comes from the CommonName of the
// verified client certificate (host UUID, set during enrollment).
func NewAgent(deps AgentDeps) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /v1/agent/renew", agentRenew(deps))
	mux.HandleFunc("POST /v1/agent/renew-mtls", agentRenewMTLS(deps))
	mux.HandleFunc("GET /v1/agent/principals", agentPrincipals(deps))
	if deps.Sessions != nil {
		mux.HandleFunc("POST /v1/agent/sessions", agentSessions(deps))
	}
	mux.HandleFunc("GET /v1/agent/bundle/user", agentBundleUser(deps))

	// Response counter by status code for the error rate metric (phase 11).
	return metrics.Middleware(mux)
}

// agentRenew renews the SSH host certificate for the submitted host key.
func agentRenew(deps AgentDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host, ok := agentHost(w, r, deps)
		if !ok {
			return
		}
		var req renewRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "request body invalid", http.StatusBadRequest)
			return
		}
		publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.PublicKey))
		if err != nil {
			http.Error(w, "public_key invalid (authorized_keys format expected)", http.StatusBadRequest)
			return
		}
		cert, record, err := issueHostCert(r.Context(), deps.CA, host, publicKey, deps.HostCertValidity)
		if err != nil {
			deps.Logger.Error("agent/renew: issuance failed", "host", host.Name, "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(renewResponse{
			Certificate: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert))),
			ValidBefore: record.ValidBefore,
		})
	}
}

// agentRenewMTLS rotates the mTLS client certificate: the agent
// authenticates with the still-valid certificate and submits a CSR for the
// next one (identity comes exclusively from the verified peer certificate).
func agentRenewMTLS(deps AgentDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host, ok := agentHost(w, r, deps)
		if !ok {
			return
		}
		var req renewMTLSRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBody)).Decode(&req); err != nil {
			http.Error(w, "request body invalid", http.StatusBadRequest)
			return
		}
		certPEM, err := deps.CA.IssueAgentCert(r.Context(), host.ID, []byte(req.CSR))
		if err != nil {
			deps.Logger.Error("agent/renew-mtls: issuance failed", "host", host.Name, "error", err)
			http.Error(w, "csr invalid", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(renewMTLSResponse{Certificate: certPEM})
	}
}

// agentPrincipals returns the authorized principals for a local user.
func agentPrincipals(deps AgentDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host, ok := agentHost(w, r, deps)
		if !ok {
			return
		}
		localUser := r.URL.Query().Get("user")
		if localUser == "" {
			http.Error(w, "query parameter user missing", http.StatusBadRequest)
			return
		}
		principals, err := deps.Hosts.ListAuthorizedPrincipals(r.Context(), host.ID, localUser)
		if err != nil {
			deps.Logger.Error("agent/principals: query failed", "host", host.Name, "user", localUser, "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(principalsResponse{Principals: principals})
	}
}

// agentSessions accepts a batch of session/sudo events from the agent spool.
func agentSessions(deps AgentDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host, ok := agentHost(w, r, deps)
		if !ok {
			return
		}
		var req sessionsRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
			http.Error(w, "request body invalid", http.StatusBadRequest)
			return
		}
		// Errors per event are logged, but the batch is acknowledged: the
		// agent only clears the spool on HTTP 200. A single bad event must
		// not permanently block the whole batch.
		for i := range req.Events {
			if err := ingestSessionEvent(r.Context(), deps.Sessions, host, req.Events[i]); err != nil {
				deps.Logger.Error("agent/sessions: discarding event",
					"host", host.Name, "service", req.Events[i].Service,
					"phase", req.Events[i].Phase, "error", err)
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// agentBundleUser returns the user CA bundle for the sshd configuration.
func agentBundleUser(deps AgentDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := agentHost(w, r, deps); !ok {
			return
		}
		bundle, err := deps.CA.Bundle(r.Context(), store.CertTypeUser)
		if err != nil {
			deps.Logger.Error("agent/bundle: loading failed", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(bundle))
	}
}

// ingestSessionEvent maps a reported event onto the matching store method.
// Unknown combinations (e.g. sudo-close) are silently discarded.
func ingestSessionEvent(ctx context.Context, sessions SessionStore, host *store.Host, ev sessionEvent) error {
	e := store.SessionEvent{
		HostID:     host.ID,
		HostName:   host.Name,
		LocalUser:  ev.LocalUser,
		RemoteUser: ev.RemoteUser,
		RemoteAddr: ev.RemoteAddr,
		TTY:        ev.TTY,
		KeyID:      ev.KeyID,
		Command:    ev.Command,
		OccurredAt: ev.OccurredAt,
	}
	if ev.Serial > 0 {
		serial := ev.Serial
		e.CertSerial = &serial
	}
	switch {
	case ev.Service == "sudo" && ev.Phase == "open":
		return sessions.RecordSudoEvent(ctx, e)
	case ev.Phase == "open":
		return sessions.OpenHostSession(ctx, e)
	case ev.Phase == "close" && ev.Service != "sudo":
		return sessions.CloseHostSession(ctx, e)
	default:
		return nil
	}
}

// agentHost determines the calling host from the mTLS client certificate
// (CN = host UUID) and stamps last_seen_at. Writes the HTTP response itself
// on errors.
func agentHost(w http.ResponseWriter, r *http.Request, deps AgentDeps) (*store.Host, bool) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "client certificate missing", http.StatusUnauthorized)
		return nil, false
	}
	hostID, err := uuid.Parse(r.TLS.PeerCertificates[0].Subject.CommonName)
	if err != nil {
		http.Error(w, "client certificate without host id", http.StatusUnauthorized)
		return nil, false
	}
	host, err := deps.Hosts.GetHost(r.Context(), hostID)
	if errors.Is(err, store.ErrNotFound) {
		http.Error(w, "host unknown", http.StatusUnauthorized)
		return nil, false
	}
	if err != nil {
		deps.Logger.Error("agent: loading host failed", "host_id", hostID, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return nil, false
	}
	if err := deps.Hosts.TouchHostLastSeen(r.Context(), host.ID, remoteIP(r)); err != nil {
		deps.Logger.Warn("agent: updating last_seen failed", "host", host.Name, "error", err)
	} else {
		metrics.AgentHeartbeats.Inc()
	}
	return host, true
}

// remoteIP is the agent's source address without the port. mTLS means a
// direct TCP connection (no L7 proxy can sit in between), so RemoteAddr is
// genuinely the peer's address — no forwarded headers to consider. Behind an
// L4 proxy (passthrough ingress, LB) that peer is the proxy; the address is
// restored at the listener via GSSH_AGENT_PROXY_PROTOCOL, guarded by a trust
// policy so only the proxy itself may rewrite it (internal/proxytrust).
func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
