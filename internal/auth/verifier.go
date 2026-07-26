// Package auth implements user authentication via OIDC (Phase 3): token
// validation against the IdP (issuer, audience, signature via JWKS,
// expiry), claim mapping onto internal users including principal
// derivation, CLI login flows (Authorization Code + PKCE, Device Flow), and
// the periodic group sync from the IdP.
package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
)

// ErrInvalidToken wraps all validation errors of an ID token; the API turns
// it into a 401 instead of a 500.
var ErrInvalidToken = errors.New("auth: invalid id token")

// Claims are the guided-ssh-relevant claims of a validated ID token.
type Claims struct {
	Issuer            string
	Subject           string
	Email             string
	PreferredUsername string
	Groups            []string
}

// Username derives the internal username: preferred_username, else the
// local part of the email, else the subject.
func (c *Claims) Username() string {
	if c.PreferredUsername != "" {
		return c.PreferredUsername
	}
	if local, _, found := strings.Cut(c.Email, "@"); found && local != "" {
		return local
	}
	return c.Subject
}

// Principals are the user's SSH principals (username, email). Certificates
// deliberately carry only these identity principals — which local users
// they can reach is decided by the grants on the host (ADR-018); grants
// only control whether and for how long at issuance time.
func (c *Claims) Principals() []string {
	principals := []string{c.Username()}
	if c.Email != "" && c.Email != principals[0] {
		principals = append(principals, c.Email)
	}
	return principals
}

// VerifierConfig configures token validation.
type VerifierConfig struct {
	// IssuerURL is the OIDC issuer URL (discovery under
	// <issuer>/.well-known/openid-configuration).
	IssuerURL string
	// ClientID is the expected audience of the ID tokens.
	ClientID string
}

// Verifier validates ID tokens against the IdP. The JWKS are cached by
// go-oidc and reloaded automatically on an unknown key ID.
type Verifier struct {
	issuer   string
	verifier *oidc.IDTokenVerifier
}

// NewVerifier loads the issuer's OIDC discovery document and builds the
// verifier.
func NewVerifier(ctx context.Context, cfg VerifierConfig) (*Verifier, error) {
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("auth: oidc discovery for %s: %w", cfg.IssuerURL, err)
	}
	return &Verifier{
		issuer:   cfg.IssuerURL,
		verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
	}, nil
}

// Issuer is the configured issuer URL (the users' identity namespace).
func (v *Verifier) Issuer() string { return v.issuer }

// Verify checks signature, issuer, audience, and expiry of the raw ID token
// and extracts the claims. Validation errors come back as ErrInvalidToken.
func (v *Verifier) Verify(ctx context.Context, rawToken string) (*Claims, error) {
	token, err := v.verifier.Verify(ctx, rawToken)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}
	var payload struct {
		Email             string   `json:"email"`
		PreferredUsername string   `json:"preferred_username"`
		Groups            []string `json:"groups"`
	}
	if err := token.Claims(&payload); err != nil {
		return nil, fmt.Errorf("%w: decoding claims: %w", ErrInvalidToken, err)
	}
	return &Claims{
		Issuer:            token.Issuer,
		Subject:           token.Subject,
		Email:             payload.Email,
		PreferredUsername: payload.PreferredUsername,
		Groups:            normalizeGroups(payload.Groups),
	}, nil
}

// normalizeGroups strips leading "/" (Keycloak returns group paths) and
// empty entries.
func normalizeGroups(groups []string) []string {
	out := make([]string, 0, len(groups))
	for _, g := range groups {
		g = strings.TrimPrefix(g, "/")
		if g != "" {
			out = append(out, g)
		}
	}
	return out
}
