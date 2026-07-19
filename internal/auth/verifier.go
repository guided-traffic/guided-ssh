// Package auth implementiert die Benutzer-Authentifizierung über OIDC
// (Phase 3): Token-Validierung gegen den IdP (Issuer, Audience, Signatur via
// JWKS, Ablauf), Claim-Mapping auf interne Benutzer inkl. Principal-Ableitung,
// CLI-Login-Flows (Authorization Code + PKCE, Device-Flow) sowie den
// periodischen Gruppen-Sync vom IdP.
package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
)

// ErrInvalidToken kapselt alle Validierungsfehler eines ID-Tokens; die API
// macht daraus 401 statt 500.
var ErrInvalidToken = errors.New("auth: ungültiges id-token")

// Claims sind die für guided-ssh relevanten Ansprüche eines validierten
// ID-Tokens.
type Claims struct {
	Issuer            string
	Subject           string
	Email             string
	PreferredUsername string
	Groups            []string
}

// Username leitet den internen Benutzernamen ab: preferred_username,
// sonst der lokale Teil der E-Mail, sonst das Subject.
func (c *Claims) Username() string {
	if c.PreferredUsername != "" {
		return c.PreferredUsername
	}
	if local, _, found := strings.Cut(c.Email, "@"); found && local != "" {
		return local
	}
	return c.Subject
}

// Principals sind die SSH-Principals des Benutzers (Username, E-Mail).
// Zertifikate tragen bewusst nur diese Identitäts-Principals — welche
// lokalen Benutzer sie erreichen, entscheiden die Grants auf dem Host
// (ADR-018); Grants steuern bei der Ausstellung nur ob und wie lange.
func (c *Claims) Principals() []string {
	principals := []string{c.Username()}
	if c.Email != "" && c.Email != principals[0] {
		principals = append(principals, c.Email)
	}
	return principals
}

// VerifierConfig konfiguriert die Token-Validierung.
type VerifierConfig struct {
	// IssuerURL ist die OIDC-Issuer-URL (Discovery unter
	// <issuer>/.well-known/openid-configuration).
	IssuerURL string
	// ClientID ist die erwartete Audience der ID-Tokens.
	ClientID string
}

// Verifier validiert ID-Tokens gegen den IdP. Die JWKS werden von go-oidc
// gecacht und bei unbekannter Key-ID automatisch neu geladen.
type Verifier struct {
	issuer   string
	verifier *oidc.IDTokenVerifier
}

// NewVerifier lädt die OIDC-Discovery des Issuers und baut den Verifier.
func NewVerifier(ctx context.Context, cfg VerifierConfig) (*Verifier, error) {
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("auth: oidc-discovery für %s: %w", cfg.IssuerURL, err)
	}
	return &Verifier{
		issuer:   cfg.IssuerURL,
		verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
	}, nil
}

// Issuer ist die konfigurierte Issuer-URL (Identitäts-Namespace der Benutzer).
func (v *Verifier) Issuer() string { return v.issuer }

// Verify prüft Signatur, Issuer, Audience und Ablauf des rohen ID-Tokens und
// extrahiert die Claims. Validierungsfehler kommen als ErrInvalidToken zurück.
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
		return nil, fmt.Errorf("%w: claims dekodieren: %w", ErrInvalidToken, err)
	}
	return &Claims{
		Issuer:            token.Issuer,
		Subject:           token.Subject,
		Email:             payload.Email,
		PreferredUsername: payload.PreferredUsername,
		Groups:            normalizeGroups(payload.Groups),
	}, nil
}

// normalizeGroups entfernt führende "/" (Keycloak liefert Gruppenpfade) und
// leere Einträge.
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
