package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/guided-traffic/guided-ssh/internal/ca"
	"github.com/guided-traffic/guided-ssh/internal/store"
)

// AgentDeps sind die Abhängigkeiten der Agent-API (mTLS-Listener).
type AgentDeps struct {
	CA     *ca.CA
	Hosts  HostStore
	Logger *slog.Logger
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

// NewAgent baut den Handler der Agent-API. Er läuft ausschließlich hinter
// dem mTLS-Listener: die Identität des Hosts kommt aus dem CommonName des
// verifizierten Client-Zertifikats (Host-UUID, gesetzt beim Enrollment).
func NewAgent(deps AgentDeps) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /v1/agent/renew", func(w http.ResponseWriter, r *http.Request) {
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
		cert, record, err := issueHostCert(r.Context(), deps.CA, host, publicKey)
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
	})

	mux.HandleFunc("GET /v1/agent/principals", func(w http.ResponseWriter, r *http.Request) {
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
	})

	mux.HandleFunc("GET /v1/agent/bundle/user", func(w http.ResponseWriter, r *http.Request) {
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
	})

	return mux
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
	}
	return host, true
}
