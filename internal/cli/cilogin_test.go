package cli

import (
	"bytes"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

const ciTestToken = "test-ci-job-token" //#nosec G101 -- test value, not a credential

// runCILogin runs gssh ci-login with arguments.
func runCILogin(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Run(&stdout, &stderr, append([]string{"ci-login"}, args...))
	return code, stdout.String(), stderr.String()
}

func TestCILoginSuccess(t *testing.T) {
	keyring := startAgent(t)
	sign := newFakeSign(t, ciTestToken, time.Hour, false)
	t.Setenv(envCIToken, ciTestToken)

	code, stdout, stderr := runCILogin(t, "--api-url", sign.server.URL)
	if code != 0 {
		t.Fatalf("code %d: %s", code, stderr)
	}
	if stdout == "" {
		t.Error("no success message")
	}
	// Key + certificate are in the agent (comment prefix guided-ssh).
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
		t.Errorf("agent entries: %d, certificate found: %t", len(keys), found)
	}
}

func TestCILoginTokenEnvOverridable(t *testing.T) {
	startAgent(t)
	sign := newFakeSign(t, ciTestToken, time.Hour, false)
	t.Setenv("MY_JOB_TOKEN", ciTestToken)

	code, _, stderr := runCILogin(t,
		"--api-url", sign.server.URL, "--token-env", "MY_JOB_TOKEN", "--validity", "30m")
	if code != 0 {
		t.Fatalf("code %d: %s", code, stderr)
	}
	if got := sign.lastValidity.Load(); got != 30*60 {
		t.Errorf("validity_seconds = %d, expected 1800", got)
	}
}

func TestCILoginAPIURLFromEnvironment(t *testing.T) {
	startAgent(t)
	sign := newFakeSign(t, ciTestToken, time.Hour, false)
	t.Setenv(envCIToken, ciTestToken)
	t.Setenv(envAPIURL, sign.server.URL)

	if code, _, stderr := runCILogin(t); code != 0 {
		t.Fatalf("code %d: %s", code, stderr)
	}
}

func TestCILoginErrorCases(t *testing.T) {
	startAgent(t)
	sign := newFakeSign(t, ciTestToken, time.Hour, false)

	// Without API URL.
	t.Setenv(envAPIURL, "")
	t.Setenv(envCIToken, ciTestToken)
	if code, _, stderr := runCILogin(t); code != 1 || stderr == "" {
		t.Errorf("without api-url: code %d, stderr %q", code, stderr)
	}

	// Without token in the env variable.
	t.Setenv(envCIToken, "")
	if code, _, stderr := runCILogin(t, "--api-url", sign.server.URL); code != 1 || stderr == "" {
		t.Errorf("without token: code %d, stderr %q", code, stderr)
	}

	// Server rejects the token.
	t.Setenv(envCIToken, "wrong-token")
	if code, _, _ := runCILogin(t, "--api-url", sign.server.URL); code != 1 {
		t.Errorf("rejected token: code %d, expected 1", code)
	}

	// Broken flag.
	if code, _, _ := runCILogin(t, "--doesnotexist"); code != 2 {
		t.Errorf("broken flag: code %d, expected 2", code)
	}
}
