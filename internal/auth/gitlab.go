package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// DefaultCIAudience ist die erwartete Audience von GitLab-Job-Tokens
// (Plan Phase 7: `aud: guided-ssh` in `id_tokens`).
const DefaultCIAudience = "guided-ssh"

// CIClaims sind die für guided-ssh relevanten Ansprüche eines validierten
// GitLab-Job-Tokens (id_tokens).
type CIClaims struct {
	Issuer      string
	Subject     string
	ProjectPath string
	// NamespacePath ist der Gruppen-/Namespace-Pfad des Projekts.
	NamespacePath string
	Ref           string
	RefType       string
	RefProtected  bool
	PipelineID    string
	JobID         string
	// Environment ist leer, wenn der Job kein Environment hat.
	Environment string
	// UserLogin ist der GitLab-Benutzer, der die Pipeline ausgelöst hat.
	UserLogin string
	// ExpiresAt ist der Token-Ablauf; GitLab setzt ihn auf das Job-Timeout —
	// die Zertifikatslaufzeit wird daran gedeckelt.
	ExpiresAt time.Time
}

// flexString akzeptiert JSON-Strings, -Zahlen und -Booleans als String —
// GitLab kodiert Claims wie pipeline_id und ref_protected als Strings, hat
// die Typen aber in der Vergangenheit schon geändert.
type flexString string

// UnmarshalJSON implementiert json.Unmarshaler.
func (f *flexString) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		*f = flexString(s)
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(data, &n); err == nil {
		*f = flexString(n.String())
		return nil
	}
	var b bool
	if err := json.Unmarshal(data, &b); err == nil {
		*f = flexString(strconv.FormatBool(b))
		return nil
	}
	return fmt.Errorf("weder string noch zahl noch bool: %s", data)
}

// CIVerifierConfig konfiguriert die Validierung von GitLab-Job-Tokens.
type CIVerifierConfig struct {
	// IssuerURL ist die GitLab-Basis-URL (OIDC-Discovery unter
	// <issuer>/.well-known/openid-configuration).
	IssuerURL string
	// Audience ist die erwartete Audience; leer ⇒ DefaultCIAudience.
	Audience string
}

// CIVerifier validiert GitLab-Job-Tokens gegen den GitLab-JWKS-Endpoint.
// Getrennt vom Benutzer-Verifier: eigener Issuer, eigene Audience — CI-Tokens
// werden nie am Benutzer-Endpoint akzeptiert (ADR-019).
type CIVerifier struct {
	issuer   string
	verifier *oidc.IDTokenVerifier
}

// NewCIVerifier lädt die OIDC-Discovery des GitLab-Issuers und baut den Verifier.
func NewCIVerifier(ctx context.Context, cfg CIVerifierConfig) (*CIVerifier, error) {
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("auth: oidc-discovery für %s: %w", cfg.IssuerURL, err)
	}
	audience := cfg.Audience
	if audience == "" {
		audience = DefaultCIAudience
	}
	return &CIVerifier{
		issuer:   cfg.IssuerURL,
		verifier: provider.Verifier(&oidc.Config{ClientID: audience}),
	}, nil
}

// Issuer ist die konfigurierte GitLab-Issuer-URL.
func (v *CIVerifier) Issuer() string { return v.issuer }

// Verify prüft Signatur, Issuer, Audience und Ablauf des rohen Job-Tokens und
// extrahiert die CI-Claims. Validierungsfehler (auch fehlende Pflicht-Claims)
// kommen als ErrInvalidToken zurück.
func (v *CIVerifier) Verify(ctx context.Context, rawToken string) (*CIClaims, error) {
	token, err := v.verifier.Verify(ctx, rawToken)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}
	var payload struct {
		ProjectPath   string     `json:"project_path"`
		NamespacePath string     `json:"namespace_path"`
		Ref           string     `json:"ref"`
		RefType       string     `json:"ref_type"`
		RefProtected  flexString `json:"ref_protected"`
		PipelineID    flexString `json:"pipeline_id"`
		JobID         flexString `json:"job_id"`
		Environment   string     `json:"environment"`
		UserLogin     string     `json:"user_login"`
	}
	if err := token.Claims(&payload); err != nil {
		return nil, fmt.Errorf("%w: claims dekodieren: %w", ErrInvalidToken, err)
	}
	for _, required := range []struct{ name, value string }{
		{"project_path", payload.ProjectPath},
		{"ref", payload.Ref},
		{"pipeline_id", string(payload.PipelineID)},
		{"job_id", string(payload.JobID)},
	} {
		if required.value == "" {
			return nil, fmt.Errorf("%w: pflicht-claim %s fehlt", ErrInvalidToken, required.name)
		}
	}
	return &CIClaims{
		Issuer:        token.Issuer,
		Subject:       token.Subject,
		ProjectPath:   payload.ProjectPath,
		NamespacePath: payload.NamespacePath,
		Ref:           payload.Ref,
		RefType:       payload.RefType,
		RefProtected:  string(payload.RefProtected) == "true",
		PipelineID:    string(payload.PipelineID),
		JobID:         string(payload.JobID),
		Environment:   payload.Environment,
		UserLogin:     payload.UserLogin,
		ExpiresAt:     token.Expiry,
	}, nil
}
