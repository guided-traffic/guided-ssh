package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/guided-traffic/guided-ssh/internal/auth"
	"github.com/guided-traffic/guided-ssh/internal/ca"
	"github.com/guided-traffic/guided-ssh/internal/store"
)

// CITokenVerifier validates raw GitLab job tokens (implemented by
// *auth.CIVerifier; tests use a fake).
type CITokenVerifier interface {
	Verify(ctx context.Context, rawToken string) (*auth.CIClaims, error)
}

// CIStore provides CI access grants and project service accounts
// (*store.Store satisfies the interface, tests use a fake).
type CIStore interface {
	MatchCIGrants(ctx context.Context, m store.CIMatch) ([]store.CIGrant, error)
	EnsureCIServiceAccount(ctx context.Context, issuer, projectPath string) (*store.ServiceAccount, error)
}

// defaultCIValidity is the default lifetime of CI certificates (plan: 1h,
// identical to the policy maximum of the ci requester type).
const defaultCIValidity = time.Hour

// handleSignCI exchanges a validated GitLab job token for a short-lived SSH
// certificate: check the token, map claims onto CI grants (no matching
// grant means no certificate), lifetime capped three ways (grants,
// 1h policy, token expiry = job timeout), sign policy-checked, audit
// transactionally.
//
// The certificate principals are project identity principals
// (ci:<project_path> + namespace ancestors, ADR-019) — which local users
// they can reach is decided by the host based on the CI grants.
func handleSignCI(certAuthority *ca.CA, verifier CITokenVerifier, ciStore CIStore, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rawToken, ok := bearerToken(r)
		if !ok {
			http.Error(w, "authorization: bearer token missing", http.StatusUnauthorized)
			return
		}
		claims, err := verifier.Verify(r.Context(), rawToken)
		if err != nil {
			logger.Info("sign/ci: token rejected", "error", err)
			http.Error(w, "job token invalid", http.StatusUnauthorized)
			return
		}

		publicKey, req, ok := decodeSignRequest(w, r)
		if !ok {
			return
		}

		grants, err := ciStore.MatchCIGrants(r.Context(), store.CIMatch{
			ProjectPath:  claims.ProjectPath,
			Ref:          claims.Ref,
			RefProtected: claims.RefProtected,
			Environment:  claims.Environment,
		})
		if err != nil {
			logger.Error("sign/ci: loading ci grants failed", "project", claims.ProjectPath, "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		if len(grants) == 0 {
			logger.Info("sign/ci: no matching ci grant",
				"project", claims.ProjectPath, "ref", claims.Ref,
				"ref_protected", claims.RefProtected, "environment", claims.Environment)
			http.Error(w, "no matching ci grant for this project/ref — certificate will not be issued", http.StatusForbidden)
			return
		}

		account, err := ciStore.EnsureCIServiceAccount(r.Context(), claims.Issuer, claims.ProjectPath)
		if err != nil {
			logger.Error("sign/ci: service account failed", "project", claims.ProjectPath, "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		if !account.Active {
			http.Error(w, "ci access for this project is disabled", http.StatusForbidden)
			return
		}

		validity := defaultCIValidity
		if req.ValiditySeconds > 0 {
			validity = time.Duration(req.ValiditySeconds) * time.Second
		}
		if allowed := maxCIGrantValidity(grants); validity > allowed {
			validity = allowed
		}
		validAfter := time.Now().Add(-signBackdate)
		validBefore := validAfter.Add(validity)
		// GitLab sets the token expiry to the job timeout — no CI
		// certificate lives longer than the job.
		if !claims.ExpiresAt.IsZero() && validBefore.After(claims.ExpiresAt) {
			validBefore = claims.ExpiresAt
		}
		if !validBefore.After(validAfter) {
			http.Error(w, "job token expires too soon for a certificate", http.StatusBadRequest)
			return
		}

		certReq := ca.CertRequest{
			CertType:    store.CertTypeUser,
			PublicKey:   publicKey,
			KeyID:       ca.CIKeyID(claims.ProjectPath, claims.PipelineID, claims.JobID),
			Principals:  ca.CIPrincipals(claims.ProjectPath),
			ValidAfter:  validAfter,
			ValidBefore: validBefore,
			Extensions:  map[string]string{"permit-pty": ""},
		}
		ref := ca.IssueRef{
			Actor:            certReq.KeyID,
			ServiceAccountID: &account.ID,
			Context: map[string]any{
				"issuer":        claims.Issuer,
				"project_path":  claims.ProjectPath,
				"ref":           claims.Ref,
				"ref_protected": claims.RefProtected,
				"pipeline_id":   claims.PipelineID,
				"job_id":        claims.JobID,
				"environment":   claims.Environment,
				"user_login":    claims.UserLogin,
			},
		}
		cert, record, err := certAuthority.Issue(r.Context(), ca.RequesterCI, certReq, ref)
		var violation *ca.PolicyViolationError
		if errors.As(err, &violation) {
			http.Error(w, violation.Error(), http.StatusBadRequest)
			return
		}
		if err != nil {
			logger.Error("sign/ci: issuance failed", "key_id", certReq.KeyID, "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(signUserResponse{
			Certificate: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert))),
			Serial:      record.Serial,
			KeyID:       record.KeyID,
			Principals:  record.Principals,
			ValidAfter:  record.ValidAfter,
			ValidBefore: record.ValidBefore,
		})
	}
}

// maxCIGrantValidity returns the highest maximum lifetime across all
// matching CI grants (additive semantics as in ADR-018).
func maxCIGrantValidity(grants []store.CIGrant) time.Duration {
	var allowed time.Duration
	for _, g := range grants {
		if v := g.MaxValidity(); v > allowed {
			allowed = v
		}
	}
	return allowed
}
