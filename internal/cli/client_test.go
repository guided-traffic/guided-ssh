package cli

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/guided-traffic/guided-ssh/internal/pintls"
)

// spkiPin returns the base64 SPKI SHA-256 of the httptest TLS certificate.
func spkiPin(t *testing.T, server *httptest.Server) string {
	t.Helper()
	return pintls.FromCertificate(server.Certificate())
}

func marshalPub(pub ssh.PublicKey) string {
	return string(ssh.MarshalAuthorizedKey(pub))
}

func TestSignUserWithPin(t *testing.T) {
	sign := newFakeSign(t, "tok", time.Hour, true)
	client, err := newAPIClient(&Config{APIURL: sign.server.URL, PinSHA256: spkiPin(t, sign.server)})
	if err != nil {
		t.Fatalf("newAPIClient: %v", err)
	}
	_, pub := testKeyPair(t)
	cert, err := client.signUser(context.Background(), "tok", marshalPub(pub), 2*time.Hour)
	if err != nil {
		t.Fatalf("signUser: %v", err)
	}
	if cert.KeyId != "user:alice@fake-idp" {
		t.Errorf("keyid = %q", cert.KeyId)
	}
	if got := sign.lastValidity.Load(); got != int64((2 * time.Hour).Seconds()) {
		t.Errorf("validity_seconds = %d, expected 7200", got)
	}
}

func TestSignUserWrongPin(t *testing.T) {
	sign := newFakeSign(t, "tok", time.Hour, true)
	wrongPin := base64.StdEncoding.EncodeToString(make([]byte, sha256.Size))
	client, err := newAPIClient(&Config{APIURL: sign.server.URL, PinSHA256: wrongPin})
	if err != nil {
		t.Fatalf("newAPIClient: %v", err)
	}
	_, pub := testKeyPair(t)
	_, err = client.signUser(context.Background(), "tok", marshalPub(pub), 0)
	if err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("expected pin error, got %v", err)
	}
}

func TestSignUserWithoutPinSelfSigned(t *testing.T) {
	// Without a pin, the system CAs apply — the self-signed test certificate
	// must be rejected.
	sign := newFakeSign(t, "tok", time.Hour, true)
	client, err := newAPIClient(&Config{APIURL: sign.server.URL})
	if err != nil {
		t.Fatalf("newAPIClient: %v", err)
	}
	_, pub := testKeyPair(t)
	if _, err := client.signUser(context.Background(), "tok", marshalPub(pub), 0); err == nil {
		t.Fatal("expected tls error (unknown ca)")
	}
}

func TestSignUserHTTPError(t *testing.T) {
	sign := newFakeSign(t, "richtig", time.Hour, false)
	client, err := newAPIClient(&Config{APIURL: sign.server.URL})
	if err != nil {
		t.Fatalf("newAPIClient: %v", err)
	}
	_, pub := testKeyPair(t)
	_, err = client.signUser(context.Background(), "falsch", marshalPub(pub), 0)
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("expected 401, got %v", err)
	}
}

func TestSignUserBrokenResponses(t *testing.T) {
	_, pub := testKeyPair(t)
	for name, response := range map[string]string{
		"no json":         "broken",
		"no certificate":  `{"certificate":"no-cert"}`,
		"public key only": `{"certificate":"` + strings.TrimSpace(marshalPub(pub)) + `"}`,
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(response))
		}))
		client, err := newAPIClient(&Config{APIURL: server.URL})
		if err != nil {
			t.Fatalf("newAPIClient: %v", err)
		}
		if _, err := client.signUser(context.Background(), "tok", marshalPub(pub), 0); err == nil {
			t.Errorf("%s: error expected", name)
		}
		server.Close()
	}
}

func TestSignUserServerUnreachable(t *testing.T) {
	client, err := newAPIClient(&Config{APIURL: "http://127.0.0.1:1"})
	if err != nil {
		t.Fatalf("newAPIClient: %v", err)
	}
	_, pub := testKeyPair(t)
	if _, err := client.signUser(context.Background(), "tok", marshalPub(pub), 0); err == nil {
		t.Fatal("expected connection error")
	}
}
