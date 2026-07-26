package auth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/guided-traffic/guided-ssh/internal/auth"
)

// ciTokenClaims are valid GitLab job token claims (GitLab traditionally
// encodes numbers and booleans as strings).
func ciTokenClaims() map[string]any {
	return map[string]any{
		"aud":            auth.DefaultCIAudience,
		"sub":            "project_path:infra/ansible:ref_type:branch:ref:main",
		"project_path":   "infra/ansible",
		"namespace_path": "infra",
		"ref":            "main",
		"ref_type":       "branch",
		"ref_protected":  "true",
		"pipeline_id":    "4711",
		"job_id":         "815",
		"environment":    "prod",
		"user_login":     "alice",
	}
}

func newCIVerifier(t *testing.T, idp *fakeIDP) *auth.CIVerifier {
	t.Helper()
	verifier, err := auth.NewCIVerifier(context.Background(), auth.CIVerifierConfig{
		IssuerURL: idp.Issuer(),
	})
	if err != nil {
		t.Fatalf("NewCIVerifier: %v", err)
	}
	if verifier.Issuer() != idp.Issuer() {
		t.Errorf("Issuer() = %q", verifier.Issuer())
	}
	return verifier
}

func TestCIVerifierValidToken(t *testing.T) {
	idp := newFakeIDP(t)
	verifier := newCIVerifier(t, idp)

	claims, err := verifier.Verify(context.Background(), idp.IDToken(ciTokenClaims()))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.ProjectPath != "infra/ansible" || claims.NamespacePath != "infra" {
		t.Errorf("project: %q / %q", claims.ProjectPath, claims.NamespacePath)
	}
	if claims.Ref != "main" || claims.RefType != "branch" || !claims.RefProtected {
		t.Errorf("ref: %+v", claims)
	}
	if claims.PipelineID != "4711" || claims.JobID != "815" {
		t.Errorf("pipeline/job: %q / %q", claims.PipelineID, claims.JobID)
	}
	if claims.Environment != "prod" || claims.UserLogin != "alice" {
		t.Errorf("environment/user: %q / %q", claims.Environment, claims.UserLogin)
	}
	if claims.ExpiresAt.IsZero() || time.Until(claims.ExpiresAt) <= 0 {
		t.Errorf("expiresat: %v", claims.ExpiresAt)
	}
}

func TestCIVerifierNumericAndBoolClaims(t *testing.T) {
	idp := newFakeIDP(t)
	verifier := newCIVerifier(t, idp)

	// GitLab might change the types: numbers and real booleans must also
	// work (flexString).
	overrides := ciTokenClaims()
	overrides["pipeline_id"] = 4711
	overrides["job_id"] = 815
	overrides["ref_protected"] = true

	claims, err := verifier.Verify(context.Background(), idp.IDToken(overrides))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.PipelineID != "4711" || claims.JobID != "815" || !claims.RefProtected {
		t.Errorf("claims: %+v", claims)
	}
}

func TestCIVerifierUnprotectedRef(t *testing.T) {
	idp := newFakeIDP(t)
	verifier := newCIVerifier(t, idp)

	overrides := ciTokenClaims()
	overrides["ref_protected"] = "false"
	claims, err := verifier.Verify(context.Background(), idp.IDToken(overrides))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.RefProtected {
		t.Error("ref_protected=false became true")
	}
}

func TestCIVerifierErrorCases(t *testing.T) {
	idp := newFakeIDP(t)
	verifier := newCIVerifier(t, idp)
	ctx := context.Background()

	// Wrong audience (user client instead of guided-ssh).
	wrongAud := ciTokenClaims()
	wrongAud["aud"] = fakeClientID
	// Expired token.
	expired := ciTokenClaims()
	expired["exp"] = time.Now().Add(-time.Hour).Unix()

	cases := []struct {
		name  string
		token string
	}{
		{"broken token", "not-a-jwt"},
		{"wrong audience", idp.IDToken(wrongAud)},
		{"expired", idp.IDToken(expired)},
		{"project_path missing", idp.IDToken(withDeleted(ciTokenClaims(), "project_path"))},
		{"ref missing", idp.IDToken(withDeleted(ciTokenClaims(), "ref"))},
		{"pipeline_id missing", idp.IDToken(withDeleted(ciTokenClaims(), "pipeline_id"))},
		{"job_id missing", idp.IDToken(withDeleted(ciTokenClaims(), "job_id"))},
	}
	for _, c := range cases {
		_, err := verifier.Verify(ctx, c.token)
		if !errors.Is(err, auth.ErrInvalidToken) {
			t.Errorf("%s: err = %v, expected ErrInvalidToken", c.name, err)
		}
	}
}

// withDeleted marks a claim for removal (fakeIDP removes it when nil).
func withDeleted(claims map[string]any, key string) map[string]any {
	claims[key] = nil
	return claims
}
