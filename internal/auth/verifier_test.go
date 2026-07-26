package auth_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/guided-traffic/guided-ssh/internal/auth"
)

func newVerifier(t *testing.T, idp *fakeIDP) *auth.Verifier {
	t.Helper()
	verifier, err := auth.NewVerifier(context.Background(), auth.VerifierConfig{
		IssuerURL: idp.Issuer(),
		ClientID:  fakeClientID,
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return verifier
}

func TestVerifyValidToken(t *testing.T) {
	idp := newFakeIDP(t)
	verifier := newVerifier(t, idp)

	raw := idp.IDToken(map[string]any{
		"sub":                "alice-id",
		"email":              "alice@example.com",
		"preferred_username": "alice",
		"groups":             []string{"/admins", "dev", ""},
	})
	claims, err := verifier.Verify(context.Background(), raw)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Issuer != idp.Issuer() || claims.Subject != "alice-id" {
		t.Errorf("issuer/subject wrong: %+v", claims)
	}
	if claims.Email != "alice@example.com" || claims.Username() != "alice" {
		t.Errorf("email/username wrong: %+v", claims)
	}
	// Keycloak paths normalized, empty entries removed.
	if !slices.Equal(claims.Groups, []string{"admins", "dev"}) {
		t.Errorf("groups wrong: %v", claims.Groups)
	}
	if !slices.Equal(claims.Principals(), []string{"alice", "alice@example.com"}) {
		t.Errorf("principals wrong: %v", claims.Principals())
	}
	if verifier.Issuer() != idp.Issuer() {
		t.Errorf("Issuer(): %q", verifier.Issuer())
	}
}

func TestVerifyRejectedTokens(t *testing.T) {
	idp := newFakeIDP(t)
	other := newFakeIDP(t) // own key ⇒ signature doesn't match idp's JWKS
	verifier := newVerifier(t, idp)

	cases := map[string]string{
		"wrong audience":    idp.IDToken(map[string]any{"aud": "someone-else"}),
		"expired":           idp.IDToken(map[string]any{"exp": time.Now().Add(-time.Hour).Unix()}),
		"wrong issuer":      idp.IDToken(map[string]any{"iss": "https://evil.example.com"}),
		"foreign signature": other.IDToken(map[string]any{"iss": idp.Issuer()}),
		"not a jwt":         "not.a.jwt.token",
	}
	for name, raw := range cases {
		if _, err := verifier.Verify(context.Background(), raw); !errors.Is(err, auth.ErrInvalidToken) {
			t.Errorf("%s: expected ErrInvalidToken, got %v", name, err)
		}
	}
}

func TestUsernameFallbacks(t *testing.T) {
	cases := []struct {
		claims auth.Claims
		want   string
	}{
		{auth.Claims{PreferredUsername: "bob", Email: "b@x.de", Subject: "s"}, "bob"},
		{auth.Claims{Email: "bob@x.de", Subject: "s"}, "bob"},
		{auth.Claims{Subject: "subject-only"}, "subject-only"},
		{auth.Claims{Email: "@broken", Subject: "s"}, "s"},
	}
	for _, c := range cases {
		if got := c.claims.Username(); got != c.want {
			t.Errorf("Username(%+v) = %q, expected %q", c.claims, got, c.want)
		}
	}
	// Username == Email ⇒ no duplicate in Principals.
	claims := auth.Claims{PreferredUsername: "x@y.de", Email: "x@y.de"}
	if got := claims.Principals(); !slices.Equal(got, []string{"x@y.de"}) {
		t.Errorf("Principals: %v", got)
	}
}

func TestNewVerifierDiscoveryError(t *testing.T) {
	_, err := auth.NewVerifier(context.Background(), auth.VerifierConfig{
		IssuerURL: "http://127.0.0.1:1/realms/nix",
	})
	if err == nil {
		t.Fatal("expected discovery error")
	}
}
