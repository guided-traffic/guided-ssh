package api

import (
	"context"
	"crypto/sha256"
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

// HostStore is the set of store methods needed by enrollment and the agent
// API (*store.Store satisfies it; tests use a fake).
type HostStore interface {
	EnrollHost(ctx context.Context, p store.EnrollHostParams) (*store.Host, error)
	GetHost(ctx context.Context, id uuid.UUID) (*store.Host, error)
	TouchHostLastSeen(ctx context.Context, id uuid.UUID, addr string) error
	ListAuthorizedPrincipals(ctx context.Context, hostID uuid.UUID, localUser string) ([]string, error)
}

// defaultHostValidity is the lifetime of host certificates (the plan's
// policy maximum: 30 days; the agent renews at 2/3 of the lifetime).
const defaultHostValidity = 30 * 24 * time.Hour

// enrollRequest is the body of POST /v1/enroll.
type enrollRequest struct {
	// Token is the one-time enrollment token (plaintext).
	Token string `json:"token"`
	// Hostname the host registers under.
	Hostname string `json:"hostname"`
	// SSHPublicKey is the host key in authorized_keys format.
	SSHPublicKey string `json:"ssh_public_key"`
	// MTLSCSR is the PEM-encoded CSR for the mTLS client certificate.
	MTLSCSR string `json:"mtls_csr"`
	// Tags from the enrollment (token tags take precedence).
	Tags map[string]string `json:"tags,omitempty"`
}

// enrollResponse is the response to a successful enrollment.
type enrollResponse struct {
	HostID          string    `json:"host_id"`
	HostCertificate string    `json:"host_certificate"`
	ValidBefore     time.Time `json:"valid_before"`
	UserCABundle    string    `json:"user_ca_bundle"`
	MTLSCertificate string    `json:"mtls_certificate"`
	MTLSCA          string    `json:"mtls_ca"`
}

// handleEnroll registers a host: consumes the token once, issues the host
// SSH certificate and mTLS client certificate, and hands out CA bundles.
// hostValidity ≤ 0 falls back to defaultHostValidity.
func handleEnroll(certAuthority *ca.CA, hosts HostStore, hostValidity time.Duration, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req enrollRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBody)).Decode(&req); err != nil {
			http.Error(w, "request body invalid", http.StatusBadRequest)
			return
		}
		if req.Token == "" || req.Hostname == "" {
			http.Error(w, "token and hostname are required", http.StatusBadRequest)
			return
		}
		publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.SSHPublicKey))
		if err != nil {
			http.Error(w, "ssh_public_key invalid (authorized_keys format expected)", http.StatusBadRequest)
			return
		}

		tokenHash := sha256.Sum256([]byte(req.Token))
		host, err := hosts.EnrollHost(r.Context(), store.EnrollHostParams{
			TokenHash: tokenHash[:],
			Name:      req.Hostname,
			PublicKey: strings.TrimSpace(req.SSHPublicKey),
			Tags:      req.Tags,
		})
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "enrollment token invalid, consumed, or expired", http.StatusForbidden)
			return
		}
		if errors.Is(err, store.ErrTokenHostMismatch) {
			http.Error(w, "enrollment token is bound to a different hostname", http.StatusForbidden)
			return
		}
		if err != nil {
			logger.Error("enroll: failed", "hostname", req.Hostname, "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		cert, record, err := issueHostCert(r.Context(), certAuthority, host, publicKey, hostValidity)
		if err != nil {
			logger.Error("enroll: host certificate failed", "hostname", host.Name, "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		mtlsCert, err := certAuthority.IssueAgentCert(r.Context(), host.ID, []byte(req.MTLSCSR))
		if err != nil {
			logger.Error("enroll: mtls certificate failed", "hostname", host.Name, "error", err)
			http.Error(w, "mtls_csr invalid", http.StatusBadRequest)
			return
		}
		mtlsCA, err := certAuthority.MTLSCAPEM(r.Context())
		if err != nil {
			logger.Error("enroll: loading mtls ca failed", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		userBundle, err := certAuthority.Bundle(r.Context(), store.CertTypeUser)
		if err != nil {
			logger.Error("enroll: user bundle failed", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		logger.Info("host enrolled", "host", host.Name, "host_id", host.ID)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(enrollResponse{
			HostID:          host.ID.String(),
			HostCertificate: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert))),
			ValidBefore:     record.ValidBefore,
			UserCABundle:    userBundle,
			MTLSCertificate: mtlsCert,
			MTLSCA:          mtlsCA,
		})
	}
}

// issueHostCert issues the SSH host certificate (principals: full name plus
// short name, so clients can verify either variant). validity ≤ 0 falls
// back to defaultHostValidity; the policy maximum (30 days) always applies.
func issueHostCert(ctx context.Context, certAuthority *ca.CA, host *store.Host, publicKey ssh.PublicKey, validity time.Duration) (*ssh.Certificate, *store.Certificate, error) {
	if validity <= 0 {
		validity = defaultHostValidity
	}
	principals := []string{host.Name}
	if short, _, found := strings.Cut(host.Name, "."); found && short != "" {
		principals = append(principals, short)
	}
	validAfter := time.Now().Add(-time.Minute)
	req := ca.CertRequest{
		CertType:    store.CertTypeHost,
		PublicKey:   publicKey,
		KeyID:       ca.HostKeyID(host.Name),
		Principals:  principals,
		ValidAfter:  validAfter,
		ValidBefore: validAfter.Add(validity),
	}
	ref := ca.IssueRef{Actor: "host:" + host.Name, HostID: &host.ID}
	return certAuthority.Issue(ctx, ca.RequesterHost, req, ref)
}
