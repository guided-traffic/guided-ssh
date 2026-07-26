package cli

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"
)

func TestLoginPKCE(t *testing.T) {
	keyring := startAgent(t)
	idp := newFakeIDP(t)
	sign := newFakeSign(t, idp.idToken, time.Hour, false)
	stubBrowser(t)

	var stdout, stderr bytes.Buffer
	if got := Run(&stdout, &stderr, []string{"login", "--config", minimalConfig(t, idp, sign)}); got != 0 {
		t.Fatalf("login = %d (stderr: %s)", got, stderr.String())
	}
	if !strings.Contains(stdout.String(), "signed in: user:alice@fake-idp") {
		t.Errorf("stdout: %q", stdout.String())
	}

	certs, err := gsshCerts(keyring)
	if err != nil || len(certs) != 1 {
		t.Fatalf("agent: %d certificates, %v — expected 1", len(certs), err)
	}
	if got := certs[0].ValidPrincipals; len(got) != 2 || got[0] != "alice" {
		t.Errorf("principals: %v", got)
	}
	if idp.tokenCalls.Load() != 1 {
		t.Errorf("tokenCalls = %d, expected 1", idp.tokenCalls.Load())
	}
}

func TestLoginReplacesOldEntry(t *testing.T) {
	keyring := startAgent(t)
	idp := newFakeIDP(t)
	sign := newFakeSign(t, idp.idToken, time.Hour, false)
	stubBrowser(t)
	config := minimalConfig(t, idp, sign)

	var out bytes.Buffer
	for i := 0; i < 2; i++ {
		if got := Run(&out, &out, []string{"login", "--config", config}); got != 0 {
			t.Fatalf("login %d = %d (%s)", i, got, out.String())
		}
	}
	certs, _ := gsshCerts(keyring)
	if len(certs) != 1 {
		t.Errorf("agent has %d guided-ssh certificates, expected 1", len(certs))
	}
	if idp.tokenCalls.Load() != 2 {
		t.Errorf("tokenCalls = %d, expected 2", idp.tokenCalls.Load())
	}
}

func TestLoginIfNeededSkips(t *testing.T) {
	startAgent(t)
	idp := newFakeIDP(t)
	sign := newFakeSign(t, idp.idToken, time.Hour, false)
	stubBrowser(t)
	config := minimalConfig(t, idp, sign)

	var out bytes.Buffer
	if got := Run(&out, &out, []string{"login", "--config", config}); got != 0 {
		t.Fatalf("first login = %d (%s)", got, out.String())
	}
	if got := Run(&out, &out, []string{"login", "--if-needed", "--config", config}); got != 0 {
		t.Fatalf("if-needed = %d (%s)", got, out.String())
	}
	if idp.tokenCalls.Load() != 1 {
		t.Errorf("if-needed signed in again: tokenCalls = %d", idp.tokenCalls.Load())
	}
}

func TestLoginDeviceFlow(t *testing.T) {
	keyring := startAgent(t)
	idp := newFakeIDP(t)
	sign := newFakeSign(t, idp.idToken, time.Hour, false)

	var stdout, stderr bytes.Buffer
	got := Run(&stdout, &stderr, []string{"login", "--device", "--config", minimalConfig(t, idp, sign)})
	if got != 0 {
		t.Fatalf("login --device = %d (stderr: %s)", got, stderr.String())
	}
	if !strings.Contains(stderr.String(), "AB-CD") {
		t.Errorf("user code missing from stderr: %q", stderr.String())
	}
	if certs, _ := gsshCerts(keyring); len(certs) != 1 {
		t.Errorf("agent has %d certificates, expected 1", len(certs))
	}
}

func TestLoginValidityFlag(t *testing.T) {
	startAgent(t)
	idp := newFakeIDP(t)
	sign := newFakeSign(t, idp.idToken, time.Hour, false)
	stubBrowser(t)

	var out bytes.Buffer
	got := Run(&out, &out, []string{"login", "--validity", "2h", "--config", minimalConfig(t, idp, sign)})
	if got != 0 {
		t.Fatalf("login = %d (%s)", got, out.String())
	}
	if sign.lastValidity.Load() != 7200 {
		t.Errorf("validity_seconds = %d, expected 7200", sign.lastValidity.Load())
	}
}

func TestLoginValidityFromConfig(t *testing.T) {
	startAgent(t)
	idp := newFakeIDP(t)
	sign := newFakeSign(t, idp.idToken, time.Hour, false)
	stubBrowser(t)
	config := writeConfig(t, "api_url: "+sign.server.URL+"\nissuer: "+idp.server.URL+"\nclient_id: gssh-cli\nvalidity: 1h30m\n")

	var out bytes.Buffer
	if got := Run(&out, &out, []string{"login", "--config", config}); got != 0 {
		t.Fatalf("login = %d (%s)", got, out.String())
	}
	if sign.lastValidity.Load() != 5400 {
		t.Errorf("validity_seconds = %d, expected 5400 (from config)", sign.lastValidity.Load())
	}
}

func TestLoginSignRejected(t *testing.T) {
	keyring := startAgent(t)
	idp := newFakeIDP(t)
	sign := newFakeSign(t, "different-token", time.Hour, false)
	stubBrowser(t)

	var stdout, stderr bytes.Buffer
	got := Run(&stdout, &stderr, []string{"login", "--config", minimalConfig(t, idp, sign)})
	if got != 1 {
		t.Fatalf("login = %d, expected 1", got)
	}
	if !strings.Contains(stderr.String(), "401") {
		t.Errorf("stderr without 401: %q", stderr.String())
	}
	if certs, _ := gsshCerts(keyring); len(certs) != 0 {
		t.Errorf("agent must be empty after failure, has %d", len(certs))
	}
}

func TestLoginExpiredCertificateFromServer(t *testing.T) {
	startAgent(t)
	idp := newFakeIDP(t)
	sign := newFakeSign(t, idp.idToken, -time.Hour, false) // server returns an expired certificate
	stubBrowser(t)

	var stdout, stderr bytes.Buffer
	if got := Run(&stdout, &stderr, []string{"login", "--config", minimalConfig(t, idp, sign)}); got != 1 {
		t.Fatalf("login = %d, expected 1 (stderr: %s)", got, stderr.String())
	}
	if !strings.Contains(stderr.String(), "expired") {
		t.Errorf("stderr: %q", stderr.String())
	}
}

func TestLoginWithoutAgent(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	idp := newFakeIDP(t)
	sign := newFakeSign(t, idp.idToken, time.Hour, false)

	var stdout, stderr bytes.Buffer
	if got := Run(&stdout, &stderr, []string{"login", "--config", minimalConfig(t, idp, sign)}); got != 1 {
		t.Fatalf("login = %d, expected 1", got)
	}
	if !strings.Contains(stderr.String(), "SSH_AUTH_SOCK") {
		t.Errorf("stderr: %q", stderr.String())
	}
}

func TestLoginIssuerUnreachable(t *testing.T) {
	startAgent(t)
	config := writeConfig(t, "api_url: http://127.0.0.1:1\nissuer: http://127.0.0.1:1\nclient_id: c\n")
	var stdout, stderr bytes.Buffer
	if got := Run(&stdout, &stderr, []string{"login", "--config", config}); got != 1 {
		t.Fatalf("login = %d, expected 1", got)
	}
}

// deadConfig points api_url at a closed port: only an override can make the
// login work.
func deadConfig(t *testing.T, idp *fakeIDP) string {
	t.Helper()
	return writeConfig(t, "api_url: http://127.0.0.1:1\nissuer: "+idp.server.URL+"\nclient_id: gssh-cli\n")
}

func TestLoginAPIURLOverride(t *testing.T) {
	startAgent(t)
	idp := newFakeIDP(t)
	sign := newFakeSign(t, idp.idToken, time.Hour, false)
	stubBrowser(t)
	config := deadConfig(t, idp)
	before, err := os.ReadFile(config)
	if err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if got := Run(&stdout, &stderr, []string{"login", "--config", config, "--api-url", sign.server.URL}); got != 0 {
		t.Fatalf("login = %d (stderr: %s)", got, stderr.String())
	}
	if !strings.Contains(stdout.String(), "signed in:") {
		t.Errorf("stdout: %q", stdout.String())
	}
	// The override is ephemeral: the configuration file stays untouched.
	after, err := os.ReadFile(config)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Errorf("config file changed:\n%s\n---\n%s", before, after)
	}
}

func TestLoginPinOverride(t *testing.T) {
	startAgent(t)
	idp := newFakeIDP(t)
	sign := newFakeSign(t, idp.idToken, time.Hour, true) // https with a self-signed certificate
	stubBrowser(t)
	config := deadConfig(t, idp)

	// Without a pin the untrusted certificate is rejected — the hint is shown.
	var stdout, stderr bytes.Buffer
	if got := Run(&stdout, &stderr, []string{"login", "--config", config, "--api-url", sign.server.URL}); got != 1 {
		t.Fatalf("login without pin = %d, expected 1", got)
	}
	if !strings.Contains(stderr.String(), "--pin-sha256") {
		t.Errorf("hint missing: %q", stderr.String())
	}

	// With the pin the same connection verifies.
	stdout.Reset()
	stderr.Reset()
	got := Run(&stdout, &stderr, []string{
		"login", "--config", config,
		"--api-url", sign.server.URL, "--pin-sha256", spkiPin(t, sign.server),
	})
	if got != 0 {
		t.Fatalf("login with pin = %d (stderr: %s)", got, stderr.String())
	}
	if !strings.Contains(stdout.String(), "signed in:") {
		t.Errorf("stdout: %q", stdout.String())
	}
}

func TestLoginInvalidPinAbortsBeforeNetwork(t *testing.T) {
	startAgent(t)
	idp := newFakeIDP(t)
	sign := newFakeSign(t, idp.idToken, time.Hour, false)
	stubBrowser(t)

	var stdout, stderr bytes.Buffer
	code := Run(&stdout, &stderr, []string{
		"login", "--config", minimalConfig(t, idp, sign),
		"--pin-sha256", "not-base64!!",
	})
	if code != 1 {
		t.Fatalf("login = %d, expected 1", code)
	}
	if !strings.Contains(stderr.String(), "--pin-sha256") {
		t.Errorf("stderr: %q", stderr.String())
	}
	if idp.tokenCalls.Load() != 0 {
		t.Errorf("oidc flow started despite an invalid pin: tokenCalls = %d", idp.tokenCalls.Load())
	}
}

func TestLoginWithoutConfig(t *testing.T) {
	var stdout, stderr bytes.Buffer
	missing := t.TempDir() + "/missing.yaml"
	if got := Run(&stdout, &stderr, []string{"login", "--config", missing}); got != 1 {
		t.Fatalf("login = %d, expected 1", got)
	}
	if !strings.Contains(stderr.String(), "create configuration file") {
		t.Errorf("hint missing: %q", stderr.String())
	}
}
