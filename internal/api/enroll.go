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

// HostStore sind die vom Enrollment und der Agent-API benötigten
// Store-Methoden (*store.Store erfüllt sie; Tests nutzen einen Fake).
type HostStore interface {
	EnrollHost(ctx context.Context, p store.EnrollHostParams) (*store.Host, error)
	GetHost(ctx context.Context, id uuid.UUID) (*store.Host, error)
	TouchHostLastSeen(ctx context.Context, id uuid.UUID) error
	ListAuthorizedPrincipals(ctx context.Context, hostID uuid.UUID, localUser string) ([]string, error)
}

// defaultHostValidity ist die Laufzeit von Host-Zertifikaten (Policy-Maximum
// des Plans: 30 Tage; der Agent erneuert bei 2/3 der Laufzeit).
const defaultHostValidity = 30 * 24 * time.Hour

// enrollRequest ist der Body von POST /v1/enroll.
type enrollRequest struct {
	// Token ist das einmalige Enrollment-Token (Klartext).
	Token string `json:"token"`
	// Hostname, unter dem sich der Host registriert.
	Hostname string `json:"hostname"`
	// SSHPublicKey ist der Host-Key im authorized_keys-Format.
	SSHPublicKey string `json:"ssh_public_key"`
	// MTLSCSR ist der PEM-kodierte CSR für das mTLS-Client-Zertifikat.
	MTLSCSR string `json:"mtls_csr"`
	// Tags aus dem Enrollment (Token-Tags haben Vorrang).
	Tags map[string]string `json:"tags,omitempty"`
}

// enrollResponse ist die Antwort auf ein erfolgreiches Enrollment.
type enrollResponse struct {
	HostID          string    `json:"host_id"`
	HostCertificate string    `json:"host_certificate"`
	ValidBefore     time.Time `json:"valid_before"`
	UserCABundle    string    `json:"user_ca_bundle"`
	MTLSCertificate string    `json:"mtls_certificate"`
	MTLSCA          string    `json:"mtls_ca"`
}

// handleEnroll registriert einen Host: Token einmalig verbrauchen, Host-
// SSH-Zertifikat und mTLS-Client-Zertifikat ausstellen, CA-Bundles mitgeben.
func handleEnroll(certAuthority *ca.CA, hosts HostStore, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req enrollRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "request-body ungültig", http.StatusBadRequest)
			return
		}
		if req.Token == "" || req.Hostname == "" {
			http.Error(w, "token und hostname sind pflicht", http.StatusBadRequest)
			return
		}
		publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.SSHPublicKey))
		if err != nil {
			http.Error(w, "ssh_public_key ungültig (authorized_keys-format erwartet)", http.StatusBadRequest)
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
			http.Error(w, "enrollment-token ungültig, verbraucht oder abgelaufen", http.StatusForbidden)
			return
		}
		if errors.Is(err, store.ErrTokenHostMismatch) {
			http.Error(w, "enrollment-token ist an einen anderen hostnamen gebunden", http.StatusForbidden)
			return
		}
		if err != nil {
			logger.Error("enroll: fehlgeschlagen", "hostname", req.Hostname, "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		cert, record, err := issueHostCert(r.Context(), certAuthority, host, publicKey)
		if err != nil {
			logger.Error("enroll: host-zertifikat fehlgeschlagen", "hostname", host.Name, "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		mtlsCert, err := certAuthority.IssueAgentCert(r.Context(), host.ID, []byte(req.MTLSCSR))
		if err != nil {
			logger.Error("enroll: mtls-zertifikat fehlgeschlagen", "hostname", host.Name, "error", err)
			http.Error(w, "mtls_csr ungültig", http.StatusBadRequest)
			return
		}
		mtlsCA, err := certAuthority.MTLSCAPEM(r.Context())
		if err != nil {
			logger.Error("enroll: mtls-ca laden fehlgeschlagen", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		userBundle, err := certAuthority.Bundle(r.Context(), store.CertTypeUser)
		if err != nil {
			logger.Error("enroll: user-bundle fehlgeschlagen", "error", err)
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

// issueHostCert stellt das SSH-Host-Zertifikat aus (Principals: voller Name
// plus Kurzname, damit Clients beide Varianten verifizieren können).
func issueHostCert(ctx context.Context, certAuthority *ca.CA, host *store.Host, publicKey ssh.PublicKey) (*ssh.Certificate, *store.Certificate, error) {
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
		ValidBefore: validAfter.Add(defaultHostValidity),
	}
	ref := ca.IssueRef{Actor: "host:" + host.Name, HostID: &host.ID}
	return certAuthority.Issue(ctx, ca.RequesterHost, req, ref)
}
