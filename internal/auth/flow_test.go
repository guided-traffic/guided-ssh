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

// browse simuliert den Browser: folgt der Authorize-URL inkl. Redirect zum
// lokalen Callback.
func browse(t *testing.T) func(string) error {
	t.Helper()
	return func(authURL string) error {
		resp, err := http.Get(authURL) //nolint:gosec // Test-URL vom Fake-IdP
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("callback-status %d", resp.StatusCode)
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
		t.Fatal("leeres id_token")
	}
	// PKCE-Verifier muss beim Code-Exchange mitgeschickt worden sein.
	if v, _ := idp.lastCodeVerifier.Load().(string); v == "" {
		t.Error("kein code_verifier beim token-endpoint angekommen")
	}
}

func TestAuthCodePKCEIdPFehler(t *testing.T) {
	idp := newFakeIDP(t)
	flow := newFlow(t, idp)

	// "Browser" ruft den Callback direkt mit einer IdP-Fehlermeldung auf
	// (State stimmt, damit der Fehlerpfad des IdP getestet wird).
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
		resp, err := http.Get(callback.String()) //nolint:gosec // lokale Test-URL
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		return nil
	}
	if _, err := flow.AuthCodePKCE(context.Background(), openURL); err == nil {
		t.Fatal("erwartete idp-fehler")
	}
}

func TestAuthCodePKCEAbbruch(t *testing.T) {
	idp := newFakeIDP(t)
	flow := newFlow(t, idp)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	// openURL öffnet nichts ⇒ es kommt nie ein Callback.
	if _, err := flow.AuthCodePKCE(ctx, func(string) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("erwartete context.Canceled, bekam %v", err)
	}
}

func TestDeviceFlow(t *testing.T) {
	idp := newFakeIDP(t)
	idp.deviceStillPending.Store(1) // erster Poll: authorization_pending
	flow := newFlow(t, idp)

	var gotURI, gotCode string
	raw, err := flow.DeviceFlow(context.Background(), func(uri, code string) {
		gotURI, gotCode = uri, code
	})
	if err != nil {
		t.Fatalf("DeviceFlow: %v", err)
	}
	if raw == "" {
		t.Fatal("leeres id_token")
	}
	if gotCode != fakeUserCode || gotURI == "" {
		t.Errorf("prompt bekam uri=%q code=%q", gotURI, gotCode)
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
		t.Fatal("leeres id_token")
	}
}

func TestClientCredentialsFalschesSecret(t *testing.T) {
	idp := newFakeIDP(t)
	flow := newFlow(t, idp)

	if _, err := flow.ClientCredentials(context.Background(), "falsch"); err == nil {
		t.Fatal("erwartete fehler bei falschem client-secret")
	}
}

func TestNewFlowDiscoveryFehler(t *testing.T) {
	_, err := auth.NewFlow(context.Background(), auth.FlowConfig{IssuerURL: "http://127.0.0.1:1/realms/nix"})
	if err == nil {
		t.Fatal("erwartete discovery-fehler")
	}
}
