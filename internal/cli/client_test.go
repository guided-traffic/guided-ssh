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
)

// spkiPin liefert den Base64-SPKI-SHA-256 des httptest-TLS-Zertifikats.
func spkiPin(t *testing.T, server *httptest.Server) string {
	t.Helper()
	sum := sha256.Sum256(server.Certificate().RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}

func marshalPub(pub ssh.PublicKey) string {
	return string(ssh.MarshalAuthorizedKey(pub))
}

func TestSignUserMitPin(t *testing.T) {
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
		t.Errorf("validity_seconds = %d, erwartet 7200", got)
	}
}

func TestSignUserFalscherPin(t *testing.T) {
	sign := newFakeSign(t, "tok", time.Hour, true)
	wrongPin := base64.StdEncoding.EncodeToString(make([]byte, sha256.Size))
	client, err := newAPIClient(&Config{APIURL: sign.server.URL, PinSHA256: wrongPin})
	if err != nil {
		t.Fatalf("newAPIClient: %v", err)
	}
	_, pub := testKeyPair(t)
	_, err = client.signUser(context.Background(), "tok", marshalPub(pub), 0)
	if err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("erwartete pin-fehler, bekam %v", err)
	}
}

func TestSignUserOhnePinSelbstsigniert(t *testing.T) {
	// Ohne Pin gelten die System-CAs — das selbstsignierte Test-Zertifikat
	// muss abgelehnt werden.
	sign := newFakeSign(t, "tok", time.Hour, true)
	client, err := newAPIClient(&Config{APIURL: sign.server.URL})
	if err != nil {
		t.Fatalf("newAPIClient: %v", err)
	}
	_, pub := testKeyPair(t)
	if _, err := client.signUser(context.Background(), "tok", marshalPub(pub), 0); err == nil {
		t.Fatal("erwartete tls-fehler (unbekannte ca)")
	}
}

func TestSignUserHTTPFehler(t *testing.T) {
	sign := newFakeSign(t, "richtig", time.Hour, false)
	client, err := newAPIClient(&Config{APIURL: sign.server.URL})
	if err != nil {
		t.Fatalf("newAPIClient: %v", err)
	}
	_, pub := testKeyPair(t)
	_, err = client.signUser(context.Background(), "falsch", marshalPub(pub), 0)
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("erwartete 401, bekam %v", err)
	}
}

func TestSignUserKaputteAntworten(t *testing.T) {
	_, pub := testKeyPair(t)
	for name, response := range map[string]string{
		"kein json":       "kaputt",
		"kein zertifikat": `{"certificate":"kein-cert"}`,
		"nur public key":  `{"certificate":"` + strings.TrimSpace(marshalPub(pub)) + `"}`,
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(response))
		}))
		client, err := newAPIClient(&Config{APIURL: server.URL})
		if err != nil {
			t.Fatalf("newAPIClient: %v", err)
		}
		if _, err := client.signUser(context.Background(), "tok", marshalPub(pub), 0); err == nil {
			t.Errorf("%s: fehler erwartet", name)
		}
		server.Close()
	}
}

func TestSignUserServerNichtErreichbar(t *testing.T) {
	client, err := newAPIClient(&Config{APIURL: "http://127.0.0.1:1"})
	if err != nil {
		t.Fatalf("newAPIClient: %v", err)
	}
	_, pub := testKeyPair(t)
	if _, err := client.signUser(context.Background(), "tok", marshalPub(pub), 0); err == nil {
		t.Fatal("erwartete verbindungsfehler")
	}
}
