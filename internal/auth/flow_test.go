package auth_test

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/guided-traffic/guided-ssh/internal/auth"
)

func newFlow(t *testing.T, idp *fakeIDP) *auth.Flow {
	t.Helper()
	flow, err := auth.NewFlow(context.Background(), auth.FlowConfig{
		IssuerURL: idp.Issuer(),
		ClientID:  fakeClientID,
	})
	if err != nil {
		t.Fatalf("NewFlow: %v", err)
	}
	return flow
}

// browse simulates the browser: follows the authorize URL including the
// redirect to the local callback.
func browse(t *testing.T) func(string) error {
	t.Helper()
	return func(authURL string) error {
		resp, err := http.Get(authURL) //nolint:gosec // test URL from the fake IdP
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("callback status %d", resp.StatusCode)
		}
		return nil
	}
}

func TestAuthCodePKCE(t *testing.T) {
	idp := newFakeIDP(t)
	flow := newFlow(t, idp)

	raw, err := flow.AuthCodePKCE(context.Background(), browse(t))
	if err != nil {
		t.Fatalf("AuthCodePKCE: %v", err)
	}
	if raw == "" {
		t.Fatal("empty id_token")
	}
	// The PKCE verifier must have been sent along with the code exchange.
	if v, _ := idp.lastCodeVerifier.Load().(string); v == "" {
		t.Error("no code_verifier arrived at the token endpoint")
	}
}

func TestAuthCodePKCEIdPError(t *testing.T) {
	idp := newFakeIDP(t)
	flow := newFlow(t, idp)

	// The "browser" calls the callback directly with an IdP error message
	// (state matches, so the IdP's error path is exercised).
	openURL := func(authURL string) error {
		parsed, err := url.Parse(authURL)
		if err != nil {
			return err
		}
		q := parsed.Query()
		callback, err := url.Parse(q.Get("redirect_uri"))
		if err != nil {
			return err
		}
		values := url.Values{"state": {q.Get("state")}, "error": {"access_denied"}}
		callback.RawQuery = values.Encode()
		resp, err := http.Get(callback.String()) //nolint:gosec // local test URL
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		return nil
	}
	if _, err := flow.AuthCodePKCE(context.Background(), openURL); err == nil {
		t.Fatal("expected idp error")
	}
}

func TestAuthCodePKCECanceled(t *testing.T) {
	idp := newFakeIDP(t)
	flow := newFlow(t, idp)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	// openURL opens nothing ⇒ no callback ever arrives.
	if _, err := flow.AuthCodePKCE(ctx, func(string) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestDeviceFlow(t *testing.T) {
	idp := newFakeIDP(t)
	idp.deviceStillPending.Store(1) // first poll: authorization_pending
	flow := newFlow(t, idp)

	var gotURI, gotCode string
	raw, err := flow.DeviceFlow(context.Background(), func(uri, code string) {
		gotURI, gotCode = uri, code
	})
	if err != nil {
		t.Fatalf("DeviceFlow: %v", err)
	}
	if raw == "" {
		t.Fatal("empty id_token")
	}
	if gotCode != fakeUserCode || gotURI == "" {
		t.Errorf("prompt received uri=%q code=%q", gotURI, gotCode)
	}
}

func TestClientCredentials(t *testing.T) {
	idp := newFakeIDP(t)
	flow := newFlow(t, idp)

	raw, err := flow.ClientCredentials(context.Background(), fakeClientSecret)
	if err != nil {
		t.Fatalf("ClientCredentials: %v", err)
	}
	if raw == "" {
		t.Fatal("empty id_token")
	}
}

func TestClientCredentialsWrongSecret(t *testing.T) {
	idp := newFakeIDP(t)
	flow := newFlow(t, idp)

	if _, err := flow.ClientCredentials(context.Background(), "wrong-secret"); err == nil {
		t.Fatal("expected error for wrong client secret")
	}
}

// TestDefaultScopes pins the scope set of a configuration without `scopes`:
// groups has to be requested (grants are matched by group), unless the
// issuer publishes a scopes_supported list without it.
func TestDefaultScopes(t *testing.T) {
	for _, tc := range []struct {
		name            string
		scopesSupported []string
		configured      []string
		want            string
	}{
		{
			name: "no scopes_supported published",
			want: "openid profile email groups",
		},
		{
			name:            "groups advertised",
			scopesSupported: []string{"openid", "profile", "email", "groups"},
			want:            "openid profile email groups",
		},
		{
			name:            "groups not advertised",
			scopesSupported: []string{"openid", "profile", "email"},
			want:            "openid profile email",
		},
		{
			name:            "configuration wins",
			scopesSupported: []string{"openid", "profile", "email", "groups"},
			configured:      []string{"openid", "email"},
			want:            "openid email",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			idp := newFakeIDP(t)
			idp.scopesSupported = tc.scopesSupported
			flow, err := auth.NewFlow(context.Background(), auth.FlowConfig{
				IssuerURL: idp.Issuer(),
				ClientID:  fakeClientID,
				Scopes:    tc.configured,
			})
			if err != nil {
				t.Fatalf("NewFlow: %v", err)
			}
			if _, err := flow.AuthCodePKCE(context.Background(), browse(t)); err != nil {
				t.Fatalf("AuthCodePKCE: %v", err)
			}
			if got, _ := idp.lastAuthScope.Load().(string); got != tc.want {
				t.Errorf("authorize scope = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestNewFlowDiscoveryError(t *testing.T) {
	_, err := auth.NewFlow(context.Background(), auth.FlowConfig{IssuerURL: "http://127.0.0.1:1/realms/nix"})
	if err == nil {
		t.Fatal("expected discovery error")
	}
}
