package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/guided-traffic/guided-ssh/internal/ca"
	"github.com/guided-traffic/guided-ssh/internal/metrics"
	"github.com/guided-traffic/guided-ssh/internal/store"
)

// AgentDeps sind die Abhängigkeiten der Agent-API (mTLS-Listener).
type AgentDeps struct {
	CA     *ca.CA
	Hosts  HostStore
	Logger *slog.Logger
	// HostCertValidity ist die Laufzeit erneuerter Host-Zertifikate;
	// 0 ⇒ Default (30 Tage). Das Policy-Maximum greift immer.
	HostCertValidity time.Duration
	// Sessions ist optional (Phase 9): fehlt es, bleibt POST /v1/agent/sessions
	// deaktiviert (404). *store.Store erfüllt das Interface.
	Sessions SessionStore
}

// SessionStore sind die Store-Methoden zur Aufnahme von Host-Session- und
// sudo-Events (*store.Store erfüllt sie; Tests nutzen einen Fake).
type SessionStore interface {
	OpenHostSession(ctx context.Context, e store.SessionEvent) error
	CloseHostSession(ctx context.Context, e store.SessionEvent) error
	RecordSudoEvent(ctx context.Context, e store.SessionEvent) error
}

// sessionEvent ist ein gemeldetes Session-/sudo-Ereignis (Wire-Format). Serial 0
// bedeutet „kein korrelierter Serial".
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

// sessionsRequest ist der Body von POST /v1/agent/sessions (Batch aus dem Spool).
type sessionsRequest struct {
	Events []sessionEvent `json:"events"`
}

// renewRequest ist der Body von POST /v1/agent/renew.
type renewRequest struct {
	// PublicKey ist der SSH-Host-Key im authorized_keys-Format.
	PublicKey string `json:"public_key"`
}

// renewResponse ist die Antwort: das erneuerte Host-Zertifikat.
type renewResponse struct {
	Certificate string    `json:"certificate"`
	ValidBefore time.Time `json:"valid_before"`
}

// principalsResponse ist die Antwort von GET /v1/agent/principals.
type principalsResponse struct {
	Principals []string `json:"principals"`
}

// renewMTLSRequest ist der Body von POST /v1/agent/renew-mtls (Phase 10:
// Rotation des mTLS-Client-Zertifikats über den bestehenden mTLS-Kanal).
type renewMTLSRequest struct {
	// CSR ist der PEM-kodierte Certificate Request; die Identität (CN)
	// vergibt der Server aus dem verifizierten Client-Zertifikat.
	CSR string `json:"csr"`
}

// renewMTLSResponse ist die Antwort: das neue mTLS-Client-Zertifikat (PEM).
type renewMTLSResponse struct {
	Certificate string `json:"certificate"`
}

// NewAgent baut den Handler der Agent-API. Er läuft ausschließlich hinter
// dem mTLS-Listener: die Identität des Hosts kommt aus dem CommonName des
// verifizierten Client-Zertifikats (Host-UUID, gesetzt beim Enrollment).
func NewAgent(deps AgentDeps) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /v1/agent/renew", agentRenew(deps))
	mux.HandleFunc("POST /v1/agent/renew-mtls", agentRenewMTLS(deps))
	mux.HandleFunc("GET /v1/agent/principals", agentPrincipals(deps))
	if deps.Sessions != nil {
		mux.HandleFunc("POST /v1/agent/sessions", agentSessions(deps))
	}
	mux.HandleFunc("GET /v1/agent/bundle/user", agentBundleUser(deps))

	// Antwort-Zähler nach Status-Code für die Fehlerraten-Metrik (Phase 11).
	return metrics.Middleware(mux)
}

// agentRenew erneuert das SSH-Host-Zertifikat für den eingereichten Host-Key.
func agentRenew(deps AgentDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host, ok := agentHost(w, r, deps)
		if !ok {
			return
		}
		var req renewRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "request-body ungültig", http.StatusBadRequest)
			return
		}
		publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.PublicKey))
		if err != nil {
			http.Error(w, "public_key ungültig (authorized_keys-format erwartet)", http.StatusBadRequest)
			return
		}
		cert, record, err := issueHostCert(r.Context(), deps.CA, host, publicKey, deps.HostCertValidity)
		if err != nil {
			deps.Logger.Error("agent/renew: ausstellung fehlgeschlagen", "host", host.Name, "error", err)
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

// agentRenewMTLS rotiert das mTLS-Client-Zertifikat: der Agent authentifiziert
// sich mit dem noch gültigen Zertifikat und reicht einen CSR für das nächste
// ein (Identität kommt ausschließlich aus dem verifizierten Peer-Zertifikat).
func agentRenewMTLS(deps AgentDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host, ok := agentHost(w, r, deps)
		if !ok {
			return
		}
		var req renewMTLSRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBody)).Decode(&req); err != nil {
			http.Error(w, "request-body ungültig", http.StatusBadRequest)
			return
		}
		certPEM, err := deps.CA.IssueAgentCert(r.Context(), host.ID, []byte(req.CSR))
		if err != nil {
			deps.Logger.Error("agent/renew-mtls: ausstellung fehlgeschlagen", "host", host.Name, "error", err)
			http.Error(w, "csr ungültig", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(renewMTLSResponse{Certificate: certPEM})
	}
}

// agentPrincipals liefert die autorisierten Principals für einen lokalen User.
func agentPrincipals(deps AgentDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host, ok := agentHost(w, r, deps)
		if !ok {
			return
		}
		localUser := r.URL.Query().Get("user")
		if localUser == "" {
			http.Error(w, "query-parameter user fehlt", http.StatusBadRequest)
			return
		}
		principals, err := deps.Hosts.ListAuthorizedPrincipals(r.Context(), host.ID, localUser)
		if err != nil {
			deps.Logger.Error("agent/principals: abfrage fehlgeschlagen", "host", host.Name, "user", localUser, "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(principalsResponse{Principals: principals})
	}
}

// agentSessions nimmt einen Batch Session-/sudo-Events aus dem Agent-Spool an.
func agentSessions(deps AgentDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host, ok := agentHost(w, r, deps)
		if !ok {
			return
		}
		var req sessionsRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
			http.Error(w, "request-body ungültig", http.StatusBadRequest)
			return
		}
		// Fehler je Event werden geloggt, aber der Batch wird bestätigt: der
		// Agent räumt den Spool nur bei HTTP-200. Ein fehlerhaftes Einzelevent
		// darf den gesamten Batch nicht dauerhaft blockieren.
		for i := range req.Events {
			if err := ingestSessionEvent(r.Context(), deps.Sessions, host, req.Events[i]); err != nil {
				deps.Logger.Error("agent/sessions: event verwerfen",
					"host", host.Name, "service", req.Events[i].Service,
					"phase", req.Events[i].Phase, "error", err)
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// agentBundleUser liefert das User-CA-Bundle für die sshd-Konfiguration.
func agentBundleUser(deps AgentDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := agentHost(w, r, deps); !ok {
			return
		}
		bundle, err := deps.CA.Bundle(r.Context(), store.CertTypeUser)
		if err != nil {
			deps.Logger.Error("agent/bundle: laden fehlgeschlagen", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(bundle))
	}
}

// ingestSessionEvent bildet ein gemeldetes Ereignis auf die passende
// Store-Methode ab. Unbekannte Kombinationen (z. B. sudo-close) werden
// stillschweigend verworfen.
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

// agentHost ermittelt den aufrufenden Host aus dem mTLS-Client-Zertifikat
// (CN = Host-UUID) und stempelt last_seen_at. Schreibt bei Fehlern selbst
// die HTTP-Antwort.
func agentHost(w http.ResponseWriter, r *http.Request, deps AgentDeps) (*store.Host, bool) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "client-zertifikat fehlt", http.StatusUnauthorized)
		return nil, false
	}
	hostID, err := uuid.Parse(r.TLS.PeerCertificates[0].Subject.CommonName)
	if err != nil {
		http.Error(w, "client-zertifikat ohne host-id", http.StatusUnauthorized)
		return nil, false
	}
	host, err := deps.Hosts.GetHost(r.Context(), hostID)
	if errors.Is(err, store.ErrNotFound) {
		http.Error(w, "host unbekannt", http.StatusUnauthorized)
		return nil, false
	}
	if err != nil {
		deps.Logger.Error("agent: host laden fehlgeschlagen", "host_id", hostID, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return nil, false
	}
	if err := deps.Hosts.TouchHostLastSeen(r.Context(), host.ID); err != nil {
		deps.Logger.Warn("agent: last_seen aktualisieren fehlgeschlagen", "host", host.Name, "error", err)
	} else {
		metrics.AgentHeartbeats.Inc()
	}
	return host, true
}
