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

	"github.com/guided-traffic/guided-ssh/internal/auth"
	"github.com/guided-traffic/guided-ssh/internal/ca"
	"github.com/guided-traffic/guided-ssh/internal/store"
)

// TokenVerifier validates raw ID tokens (implemented by *auth.Verifier;
// tests use a fake).
type TokenVerifier interface {
	Verify(ctx context.Context, rawToken string) (*auth.Claims, error)
}

// GrantSource returns the access grants of a user (phase 6; *store.Store
// satisfies the interface, tests use a fake).
type GrantSource interface {
	ListGrantsForUser(ctx context.Context, userID uuid.UUID) ([]store.AccessGrant, error)
}

// signUserRequest is the body of POST /v1/sign/user.
type signUserRequest struct {
	// PublicKey in authorized_keys format (e.g. "ssh-ed25519 AAAA…").
	PublicKey string `json:"public_key"`
	// ValiditySeconds is the requested lifetime; 0 ⇒ server default.
	ValiditySeconds int64 `json:"validity_seconds,omitempty"`
}

// signUserResponse is the response: the signed certificate plus metadata.
type signUserResponse struct {
	Certificate string    `json:"certificate"`
	Serial      int64     `json:"serial"`
	KeyID       string    `json:"key_id"`
	Principals  []string  `json:"principals"`
	ValidAfter  time.Time `json:"valid_after"`
	ValidBefore time.Time `json:"valid_before"`
}

// defaultUserValidity is the default lifetime of user certificates
// (plan: ~16h, the policy maximum applies on top).
const defaultUserValidity = 16 * time.Hour

// signBackdate dates ValidAfter back slightly (clock skew relative to
// hosts); stays under the policy limit of 5 minutes.
const signBackdate = time.Minute

// userExtensions are the default extensions of user certificates.
func userExtensions() map[string]string {
	return map[string]string{
		"permit-X11-forwarding":   "",
		"permit-agent-forwarding": "",
		"permit-port-forwarding":  "",
		"permit-pty":              "",
		"permit-user-rc":          "",
	}
}

// handleSignUser exchanges a validated ID token for a short-lived SSH user
// certificate: check the token, map claims onto a user/groups (including
// an active check), evaluate grants (no grant means no certificate,
// lifetime capped), sign policy-checked, audit transactionally.
//
// The certificate principals stay identity principals (username, email) —
// which local users they can reach on a host is decided by the host via
// AuthorizedPrincipalsCommand based on the grants (ADR-018).
func handleSignUser(certAuthority *ca.CA, verifier TokenVerifier, mapper *auth.Mapper, grants GrantSource, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rawToken, ok := bearerToken(r)
		if !ok {
			http.Error(w, "authorization: bearer token missing", http.StatusUnauthorized)
			return
		}
		claims, err := verifier.Verify(r.Context(), rawToken)
		if err != nil {
			logger.Info("sign/user: token rejected", "error", err)
			http.Error(w, "id token invalid", http.StatusUnauthorized)
			return
		}

		publicKey, req, ok := decodeSignRequest(w, r)
		if !ok {
			return
		}

		user, err := mapper.EnsureUser(r.Context(), claims)
		if errors.Is(err, auth.ErrUserInactive) {
			http.Error(w, "user is disabled", http.StatusForbidden)
			return
		}
		if err != nil {
			logger.Error("sign/user: user mapping failed", "subject", claims.Subject, "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		userGrants, err := grants.ListGrantsForUser(r.Context(), user.ID)
		if err != nil {
			logger.Error("sign/user: loading grants failed", "subject", claims.Subject, "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		if len(userGrants) == 0 {
			logger.Info("sign/user: no grants", "subject", claims.Subject, "groups", claims.Groups)
			http.Error(w, "no access grants for this user — certificate will not be issued", http.StatusForbidden)
			return
		}

		validity := defaultUserValidity
		if req.ValiditySeconds > 0 {
			validity = time.Duration(req.ValiditySeconds) * time.Second
		}
		// Grants are additive: the highest allowed lifetime across all of
		// the user's grants applies; a higher request is capped (ADR-018).
		if allowed := maxGrantValidity(userGrants); validity > allowed {
			validity = allowed
		}
		// Lifetime is counted from the backdated ValidAfter, so the total
		// lifetime matches exactly the requested one (policy maximum).
		validAfter := time.Now().Add(-signBackdate)
		certReq := ca.CertRequest{
			CertType:    store.CertTypeUser,
			PublicKey:   publicKey,
			KeyID:       ca.UserKeyID(claims.Subject, claims.Issuer),
			Principals:  claims.Principals(),
			ValidAfter:  validAfter,
			ValidBefore: validAfter.Add(validity),
			Extensions:  userExtensions(),
		}
		ref := ca.IssueRef{
			Actor:  certReq.KeyID,
			UserID: &user.ID,
			Context: map[string]any{
				"issuer": claims.Issuer,
				"email":  claims.Email,
				"groups": claims.Groups,
			},
		}
		cert, record, err := certAuthority.Issue(r.Context(), ca.RequesterUser, certReq, ref)
		var violation *ca.PolicyViolationError
		if errors.As(err, &violation) {
			http.Error(w, violation.Error(), http.StatusBadRequest)
			return
		}
		if err != nil {
			logger.Error("sign/user: issuance failed", "key_id", certReq.KeyID, "error", err)
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

// maxGrantValidity returns the highest maximum lifetime across all grants
// (additive semantics: each grant independently authorizes up to its own maximum).
func maxGrantValidity(grants []store.AccessGrant) time.Duration {
	var allowed time.Duration
	for _, g := range grants {
		if v := g.MaxValidity(); v > allowed {
			allowed = v
		}
	}
	return allowed
}

// maxRequestBody bounds the bodies of the unauthenticated endpoints
// (public key, CSR, and metadata stay well under it) — memory protection
// against deliberately large requests (phase 10).
const maxRequestBody = 64 << 10

// decodeSignRequest parses the body and public key of a sign request; on
// error the 400 response has already been written (ok = false).
func decodeSignRequest(w http.ResponseWriter, r *http.Request) (ssh.PublicKey, signUserRequest, bool) {
	var req signUserRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBody)).Decode(&req); err != nil {
		http.Error(w, "request body invalid", http.StatusBadRequest)
		return nil, req, false
	}
	publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.PublicKey))
	if err != nil {
		http.Error(w, "public_key invalid (authorized_keys format expected)", http.StatusBadRequest)
		return nil, req, false
	}
	if _, isCert := publicKey.(*ssh.Certificate); isCert {
		http.Error(w, "public_key is already a certificate", http.StatusBadRequest)
		return nil, req, false
	}
	return publicKey, req, true
}

// bearerToken extracts the bearer token from the Authorization header.
func bearerToken(r *http.Request) (string, bool) {
	header := r.Header.Get("Authorization")
	scheme, token, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") || token == "" {
		return "", false
	}
	return token, true
}
