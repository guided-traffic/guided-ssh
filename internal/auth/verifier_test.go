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

func TestVerifyGueltigesToken(t *testing.T) {
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
		t.Errorf("issuer/subject falsch: %+v", claims)
	}
	if claims.Email != "alice@example.com" || claims.Username() != "alice" {
		t.Errorf("email/username falsch: %+v", claims)
	}
	// Keycloak-Pfade normalisiert, leere Einträge entfernt.
	if !slices.Equal(claims.Groups, []string{"admins", "dev"}) {
		t.Errorf("groups falsch: %v", claims.Groups)
	}
	if !slices.Equal(claims.Principals(), []string{"alice", "alice@example.com"}) {
		t.Errorf("principals falsch: %v", claims.Principals())
	}
	if verifier.Issuer() != idp.Issuer() {
		t.Errorf("Issuer(): %q", verifier.Issuer())
	}
}

func TestVerifyAbgelehnteTokens(t *testing.T) {
	idp := newFakeIDP(t)
	other := newFakeIDP(t) // eigener Key ⇒ Signatur passt nicht zum JWKS von idp
	verifier := newVerifier(t, idp)

	cases := map[string]string{
		"falsche audience": idp.IDToken(map[string]any{"aud": "jemand-anderes"}),
		"abgelaufen":       idp.IDToken(map[string]any{"exp": time.Now().Add(-time.Hour).Unix()}),
		"falscher issuer":  idp.IDToken(map[string]any{"iss": "https://boese.example.com"}),
		"fremde signatur":  other.IDToken(map[string]any{"iss": idp.Issuer()}),
		"kein jwt":         "kein.jwt.token",
	}
	for name, raw := range cases {
		if _, err := verifier.Verify(context.Background(), raw); !errors.Is(err, auth.ErrInvalidToken) {
			t.Errorf("%s: erwartete ErrInvalidToken, bekam %v", name, err)
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
		{auth.Claims{Email: "@kaputt", Subject: "s"}, "s"},
	}
	for _, c := range cases {
		if got := c.claims.Username(); got != c.want {
			t.Errorf("Username(%+v) = %q, erwartet %q", c.claims, got, c.want)
		}
	}
	// Username == Email ⇒ kein Duplikat in Principals.
	claims := auth.Claims{PreferredUsername: "x@y.de", Email: "x@y.de"}
	if got := claims.Principals(); !slices.Equal(got, []string{"x@y.de"}) {
		t.Errorf("Principals: %v", got)
	}
}

func TestNewVerifierDiscoveryFehler(t *testing.T) {
	_, err := auth.NewVerifier(context.Background(), auth.VerifierConfig{
		IssuerURL: "http://127.0.0.1:1/realms/nix",
	})
	if err == nil {
		t.Fatal("erwartete discovery-fehler")
	}
}
