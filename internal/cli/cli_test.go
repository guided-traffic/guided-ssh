package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh/agent"
)

func TestRunWithoutArguments(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := Run(&stdout, &stderr, nil); got != 2 {
		t.Fatalf("Run() = %d, expected 2", got)
	}
	if !strings.Contains(stderr.String(), "commands") {
		t.Errorf("usage missing: %q", stderr.String())
	}
}

func TestRunUnknownCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := Run(&stdout, &stderr, []string{"doesnotexist"}); got != 2 {
		t.Fatalf("Run(doesnotexist) = %d, expected 2", got)
	}
	if !strings.Contains(stderr.String(), "doesnotexist") {
		t.Errorf("stderr: %q", stderr.String())
	}
}

func TestRunHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := Run(&stdout, &stderr, []string{"help"}); got != 0 {
		t.Fatalf("Run(help) = %d", got)
	}
	if !strings.Contains(stdout.String(), "commands") {
		t.Errorf("stdout: %q", stdout.String())
	}
}

func TestRunVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := Run(&stdout, &stderr, []string{"version"}); got != 0 {
		t.Fatalf("Run(version) = %d", got)
	}
	if !strings.Contains(stdout.String(), "guided-ssh") {
		t.Errorf("stdout: %q", stdout.String())
	}
}

func TestRunLoginFlagError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := Run(&stdout, &stderr, []string{"login", "--doesnotexist"}); got != 2 {
		t.Fatalf("Run(login --doesnotexist) = %d, expected 2", got)
	}
}

func TestRunIntegrate(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := Run(&stdout, &stderr, []string{"integrate", "--hosts", "*.corp.example.com"}); got != 0 {
		t.Fatalf("Run(integrate) = %d", got)
	}
	want := `Match host "*.corp.example.com" exec "gssh login --if-needed"`
	if !strings.Contains(stdout.String(), want) {
		t.Errorf("snippet missing:\n%s", stdout.String())
	}
}

func TestRunIntegrateFlagError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := Run(&stdout, &stderr, []string{"integrate", "--broken"}); got != 2 {
		t.Fatalf("Run(integrate --broken) = %d, expected 2", got)
	}
}

func TestRunLogout(t *testing.T) {
	keyring := startAgent(t)
	priv, pub := testKeyPair(t)
	if err := loadIntoAgent(keyring, priv, testSignCert(t, newTestSigner(t), pub, time.Hour)); err != nil {
		t.Fatalf("setup: %v", err)
	}

	var stdout, stderr bytes.Buffer
	if got := Run(&stdout, &stderr, []string{"logout"}); got != 0 {
		t.Fatalf("logout = %d (stderr: %s)", got, stderr.String())
	}
	if !strings.Contains(stdout.String(), "1 agent entries removed") {
		t.Errorf("stdout: %q", stdout.String())
	}
	if keys, _ := keyring.List(); len(keys) != 0 {
		t.Errorf("agent not empty: %d entries", len(keys))
	}
}

func TestRunLogoutWithoutAgent(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	var stdout, stderr bytes.Buffer
	if got := Run(&stdout, &stderr, []string{"logout"}); got != 1 {
		t.Fatalf("logout = %d, expected 1", got)
	}
}

func TestRunStatusWithoutCertificate(t *testing.T) {
	startAgent(t)
	t.Setenv(envConfig, t.TempDir()+"/missing.yaml")
	var stdout, stderr bytes.Buffer
	if got := Run(&stdout, &stderr, []string{"status"}); got != 1 {
		t.Fatalf("status = %d, expected 1", got)
	}
	if !strings.Contains(stdout.String(), "no guided-ssh certificate") {
		t.Errorf("stdout: %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "error:") {
		t.Errorf("config error missing from output: %q", stdout.String())
	}
}

func TestRunStatusWithCertificate(t *testing.T) {
	keyring := startAgent(t)
	idp := newFakeIDP(t)
	sign := newFakeSign(t, idp.idToken, time.Hour, false)
	config := minimalConfig(t, idp, sign)
	priv, pub := testKeyPair(t)
	if err := loadIntoAgent(keyring, priv, testSignCert(t, newTestSigner(t), pub, time.Hour)); err != nil {
		t.Fatalf("setup: %v", err)
	}

	var stdout, stderr bytes.Buffer
	if got := Run(&stdout, &stderr, []string{"status", "--config", config}); got != 0 {
		t.Fatalf("status = %d (stderr: %s)", got, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{"configuration:", "user:alice@fake-idp", "alice, alice@example.com", "valid until"} {
		if !strings.Contains(out, want) {
			t.Errorf("status output missing %q:\n%s", want, out)
		}
	}
}

func TestRunStatusExpired(t *testing.T) {
	keyring := startAgent(t)
	t.Setenv(envConfig, t.TempDir()+"/missing.yaml")
	// Put an expired certificate directly into the keyring (without a
	// lifetime, so it isn't removed immediately).
	priv, pub := testKeyPair(t)
	cert := testSignCert(t, newTestSigner(t), pub, -time.Hour)
	err := keyring.Add(agent.AddedKey{PrivateKey: priv, Certificate: cert, Comment: agentCommentPrefix + " " + cert.KeyId})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	var stdout, stderr bytes.Buffer
	if got := Run(&stdout, &stderr, []string{"status"}); got != 1 {
		t.Fatalf("status = %d, expected 1 (expired)", got)
	}
	if !strings.Contains(stdout.String(), "expired") {
		t.Errorf("stdout: %q", stdout.String())
	}
}

func TestRunStatusWithoutAgent(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	t.Setenv(envConfig, t.TempDir()+"/missing.yaml")
	var stdout, stderr bytes.Buffer
	if got := Run(&stdout, &stderr, []string{"status"}); got != 1 {
		t.Fatalf("status = %d, expected 1", got)
	}
}

func TestRunStatusFlagError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := Run(&stdout, &stderr, []string{"status", "--broken"}); got != 2 {
		t.Fatalf("status --broken = %d, expected 2", got)
	}
}
