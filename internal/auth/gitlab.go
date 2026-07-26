package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// DefaultCIAudience is the expected audience of GitLab job tokens
// (plan Phase 7: `aud: guided-ssh` in `id_tokens`).
const DefaultCIAudience = "guided-ssh"

// CIClaims are the guided-ssh-relevant claims of a validated GitLab job
// token (id_tokens).
type CIClaims struct {
	Issuer      string
	Subject     string
	ProjectPath string
	// NamespacePath is the project's group/namespace path.
	NamespacePath string
	Ref           string
	RefType       string
	RefProtected  bool
	PipelineID    string
	JobID         string
	// Environment is empty if the job has no environment.
	Environment string
	// UserLogin is the GitLab user who triggered the pipeline.
	UserLogin string
	// ExpiresAt is the token expiry; GitLab sets it to the job timeout —
	// the certificate validity is capped at this value.
	ExpiresAt time.Time
}

// flexString accepts JSON strings, numbers, and booleans as a string —
// GitLab encodes claims like pipeline_id and ref_protected as strings, but
// has changed the types in the past.
type flexString string

// UnmarshalJSON implements json.Unmarshaler.
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
	return fmt.Errorf("neither string nor number nor bool: %s", data)
}

// CIVerifierConfig configures the validation of GitLab job tokens.
type CIVerifierConfig struct {
	// IssuerURL is the GitLab base URL (OIDC discovery under
	// <issuer>/.well-known/openid-configuration).
	IssuerURL string
	// Audience is the expected audience; empty ⇒ DefaultCIAudience.
	Audience string
}

// CIVerifier validates GitLab job tokens against GitLab's JWKS endpoint.
// Separate from the user Verifier: its own issuer, its own audience — CI
// tokens are never accepted at the user endpoint (ADR-019).
type CIVerifier struct {
	issuer   string
	verifier *oidc.IDTokenVerifier
}

// NewCIVerifier loads the GitLab issuer's OIDC discovery document and builds
// the verifier.
func NewCIVerifier(ctx context.Context, cfg CIVerifierConfig) (*CIVerifier, error) {
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("auth: oidc discovery for %s: %w", cfg.IssuerURL, err)
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

// Issuer is the configured GitLab issuer URL.
func (v *CIVerifier) Issuer() string { return v.issuer }

// Verify checks signature, issuer, audience, and expiry of the raw job
// token and extracts the CI claims. Validation errors (including missing
// required claims) come back as ErrInvalidToken.
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
		return nil, fmt.Errorf("%w: decoding claims: %w", ErrInvalidToken, err)
	}
	for _, required := range []struct{ name, value string }{
		{"project_path", payload.ProjectPath},
		{"ref", payload.Ref},
		{"pipeline_id", string(payload.PipelineID)},
		{"job_id", string(payload.JobID)},
	} {
		if required.value == "" {
			return nil, fmt.Errorf("%w: required claim %s missing", ErrInvalidToken, required.name)
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
