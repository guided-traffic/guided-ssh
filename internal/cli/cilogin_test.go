package cli

import (
	"bytes"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

const ciTestToken = "test-ci-job-token" //#nosec G101 -- Testwert, kein Credential

// runCILogin führt gssh ci-login mit Argumenten aus.
func runCILogin(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Run(&stdout, &stderr, append([]string{"ci-login"}, args...))
	return code, stdout.String(), stderr.String()
}

func TestCILoginErfolg(t *testing.T) {
	keyring := startAgent(t)
	sign := newFakeSign(t, ciTestToken, time.Hour, false)
	t.Setenv(envCIToken, ciTestToken)

	code, stdout, stderr := runCILogin(t, "--api-url", sign.server.URL)
	if code != 0 {
		t.Fatalf("code %d: %s", code, stderr)
	}
	if stdout == "" {
		t.Error("keine erfolgsmeldung")
	}
	// Schlüssel + Zertifikat liegen im Agenten (comment-präfix guided-ssh).
	keys, err := keyring.List()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, key := range keys {
		pub, err := ssh.ParsePublicKey(key.Blob)
		if err != nil {
			continue
		}
		if _, ok := pub.(*ssh.Certificate); ok {
			found = true
		}
	}
	if len(keys) == 0 || !found {
		t.Errorf("agent-einträge: %d, zertifikat gefunden: %t", len(keys), found)
	}
}

func TestCILoginTokenEnvUeberschreibbar(t *testing.T) {
	startAgent(t)
	sign := newFakeSign(t, ciTestToken, time.Hour, false)
	t.Setenv("MEIN_JOB_TOKEN", ciTestToken)

	code, _, stderr := runCILogin(t,
		"--api-url", sign.server.URL, "--token-env", "MEIN_JOB_TOKEN", "--validity", "30m")
	if code != 0 {
		t.Fatalf("code %d: %s", code, stderr)
	}
	if got := sign.lastValidity.Load(); got != 30*60 {
		t.Errorf("validity_seconds = %d, erwartet 1800", got)
	}
}

func TestCILoginAPIURLAusUmgebung(t *testing.T) {
	startAgent(t)
	sign := newFakeSign(t, ciTestToken, time.Hour, false)
	t.Setenv(envCIToken, ciTestToken)
	t.Setenv(envAPIURL, sign.server.URL)

	if code, _, stderr := runCILogin(t); code != 0 {
		t.Fatalf("code %d: %s", code, stderr)
	}
}

func TestCILoginFehlerfaelle(t *testing.T) {
	startAgent(t)
	sign := newFakeSign(t, ciTestToken, time.Hour, false)

	// Ohne API-URL.
	t.Setenv(envAPIURL, "")
	t.Setenv(envCIToken, ciTestToken)
	if code, _, stderr := runCILogin(t); code != 1 || stderr == "" {
		t.Errorf("ohne api-url: code %d, stderr %q", code, stderr)
	}

	// Ohne Token in der Env-Variable.
	t.Setenv(envCIToken, "")
	if code, _, stderr := runCILogin(t, "--api-url", sign.server.URL); code != 1 || stderr == "" {
		t.Errorf("ohne token: code %d, stderr %q", code, stderr)
	}

	// Server lehnt das Token ab.
	t.Setenv(envCIToken, "falsches-token")
	if code, _, _ := runCILogin(t, "--api-url", sign.server.URL); code != 1 {
		t.Errorf("abgelehntes token: code %d, erwartet 1", code)
	}

	// Kaputtes Flag.
	if code, _, _ := runCILogin(t, "--gibtsnicht"); code != 2 {
		t.Errorf("kaputtes flag: code %d, erwartet 2", code)
	}
}
