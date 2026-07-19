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

// CITokenVerifier validiert rohe GitLab-Job-Tokens (implementiert von
// *auth.CIVerifier; Tests nutzen einen Fake).
type CITokenVerifier interface {
	Verify(ctx context.Context, rawToken string) (*auth.CIClaims, error)
}

// CIStore liefert CI-Zugriffsregeln und Projekt-Service-Accounts
// (*store.Store erfüllt das Interface, Tests nutzen einen Fake).
type CIStore interface {
	MatchCIGrants(ctx context.Context, m store.CIMatch) ([]store.CIGrant, error)
	EnsureCIServiceAccount(ctx context.Context, issuer, projectPath string) (*store.ServiceAccount, error)
}

// defaultCIValidity ist die Standard-Laufzeit von CI-Zertifikaten (Plan: 1 h,
// identisch zum Policy-Maximum des Requester-Typs ci).
const defaultCIValidity = time.Hour

// handleSignCI tauscht ein validiertes GitLab-Job-Token gegen ein kurzlebiges
// SSH-Zertifikat: Token prüfen, Claims auf CI-Grants mappen (ohne passenden
// Grant kein Zertifikat), Laufzeit dreifach gedeckelt (Grants, Policy 1 h,
// Token-Ablauf = Job-Timeout), Policy-geprüft signieren, Audit transaktional.
//
// Die Zertifikats-Principals sind Projekt-Identitäts-Principals
// (ci:<project_path> + Namespace-Vorfahren, ADR-019) — welche lokalen
// Benutzer sie erreichen, entscheidet der Host anhand der CI-Grants.
func handleSignCI(certAuthority *ca.CA, verifier CITokenVerifier, ciStore CIStore, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rawToken, ok := bearerToken(r)
		if !ok {
			http.Error(w, "authorization: bearer-token fehlt", http.StatusUnauthorized)
			return
		}
		claims, err := verifier.Verify(r.Context(), rawToken)
		if err != nil {
			logger.Info("sign/ci: token abgelehnt", "error", err)
			http.Error(w, "job-token ungültig", http.StatusUnauthorized)
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
			logger.Error("sign/ci: ci-grants laden fehlgeschlagen", "project", claims.ProjectPath, "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		if len(grants) == 0 {
			logger.Info("sign/ci: kein passender ci-grant",
				"project", claims.ProjectPath, "ref", claims.Ref,
				"ref_protected", claims.RefProtected, "environment", claims.Environment)
			http.Error(w, "kein passender ci-grant für dieses projekt/ref — zertifikat wird nicht ausgestellt", http.StatusForbidden)
			return
		}

		account, err := ciStore.EnsureCIServiceAccount(r.Context(), claims.Issuer, claims.ProjectPath)
		if err != nil {
			logger.Error("sign/ci: service-account fehlgeschlagen", "project", claims.ProjectPath, "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		if !account.Active {
			http.Error(w, "ci-zugang für dieses projekt ist deaktiviert", http.StatusForbidden)
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
		// GitLab setzt den Token-Ablauf auf das Job-Timeout — länger als der
		// Job lebt kein CI-Zertifikat.
		if !claims.ExpiresAt.IsZero() && validBefore.After(claims.ExpiresAt) {
			validBefore = claims.ExpiresAt
		}
		if !validBefore.After(validAfter) {
			http.Error(w, "job-token läuft zu bald ab für ein zertifikat", http.StatusBadRequest)
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
			logger.Error("sign/ci: ausstellung fehlgeschlagen", "key_id", certReq.KeyID, "error", err)
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

// maxCIGrantValidity liefert die höchste maximale Laufzeit über alle
// passenden CI-Grants (additive Semantik wie ADR-018).
func maxCIGrantValidity(grants []store.CIGrant) time.Duration {
	var allowed time.Duration
	for _, g := range grants {
		if v := g.MaxValidity(); v > allowed {
			allowed = v
		}
	}
	return allowed
}
