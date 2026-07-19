package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh/agent"
)

func TestRunOhneArgumente(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := Run(&stdout, &stderr, nil); got != 2 {
		t.Fatalf("Run() = %d, erwartet 2", got)
	}
	if !strings.Contains(stderr.String(), "kommandos") {
		t.Errorf("usage fehlt: %q", stderr.String())
	}
}

func TestRunUnbekanntesKommando(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := Run(&stdout, &stderr, []string{"gibtsnicht"}); got != 2 {
		t.Fatalf("Run(gibtsnicht) = %d, erwartet 2", got)
	}
	if !strings.Contains(stderr.String(), "gibtsnicht") {
		t.Errorf("stderr: %q", stderr.String())
	}
}

func TestRunHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := Run(&stdout, &stderr, []string{"help"}); got != 0 {
		t.Fatalf("Run(help) = %d", got)
	}
	if !strings.Contains(stdout.String(), "kommandos") {
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

func TestRunLoginFlagFehler(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := Run(&stdout, &stderr, []string{"login", "--gibtsnicht"}); got != 2 {
		t.Fatalf("Run(login --gibtsnicht) = %d, erwartet 2", got)
	}
}

func TestRunIntegrate(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := Run(&stdout, &stderr, []string{"integrate", "--hosts", "*.corp.example.com"}); got != 0 {
		t.Fatalf("Run(integrate) = %d", got)
	}
	want := `Match host "*.corp.example.com" exec "gssh login --if-needed"`
	if !strings.Contains(stdout.String(), want) {
		t.Errorf("schnipsel fehlt:\n%s", stdout.String())
	}
}

func TestRunIntegrateFlagFehler(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := Run(&stdout, &stderr, []string{"integrate", "--kaputt"}); got != 2 {
		t.Fatalf("Run(integrate --kaputt) = %d, erwartet 2", got)
	}
}

func TestRunLogout(t *testing.T) {
	keyring := startAgent(t)
	priv, pub := testKeyPair(t)
	if err := loadIntoAgent(keyring, priv, testSignCert(t, newTestSigner(t), pub, time.Hour)); err != nil {
		t.Fatalf("vorbereiten: %v", err)
	}

	var stdout, stderr bytes.Buffer
	if got := Run(&stdout, &stderr, []string{"logout"}); got != 0 {
		t.Fatalf("logout = %d (stderr: %s)", got, stderr.String())
	}
	if !strings.Contains(stdout.String(), "1 agent-einträge entfernt") {
		t.Errorf("stdout: %q", stdout.String())
	}
	if keys, _ := keyring.List(); len(keys) != 0 {
		t.Errorf("agent nicht leer: %d einträge", len(keys))
	}
}

func TestRunLogoutOhneAgent(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	var stdout, stderr bytes.Buffer
	if got := Run(&stdout, &stderr, []string{"logout"}); got != 1 {
		t.Fatalf("logout = %d, erwartet 1", got)
	}
}

func TestRunStatusOhneZertifikat(t *testing.T) {
	startAgent(t)
	t.Setenv(envConfig, t.TempDir()+"/fehlt.yaml")
	var stdout, stderr bytes.Buffer
	if got := Run(&stdout, &stderr, []string{"status"}); got != 1 {
		t.Fatalf("status = %d, erwartet 1", got)
	}
	if !strings.Contains(stdout.String(), "kein guided-ssh-zertifikat") {
		t.Errorf("stdout: %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "fehler:") {
		t.Errorf("config-fehler fehlt in ausgabe: %q", stdout.String())
	}
}

func TestRunStatusMitZertifikat(t *testing.T) {
	keyring := startAgent(t)
	idp := newFakeIDP(t)
	sign := newFakeSign(t, idp.idToken, time.Hour, false)
	config := minimalConfig(t, idp, sign)
	priv, pub := testKeyPair(t)
	if err := loadIntoAgent(keyring, priv, testSignCert(t, newTestSigner(t), pub, time.Hour)); err != nil {
		t.Fatalf("vorbereiten: %v", err)
	}

	var stdout, stderr bytes.Buffer
	if got := Run(&stdout, &stderr, []string{"status", "--config", config}); got != 0 {
		t.Fatalf("status = %d (stderr: %s)", got, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{"konfiguration:", "user:alice@fake-idp", "alice, alice@example.com", "gültig bis"} {
		if !strings.Contains(out, want) {
			t.Errorf("status-ausgabe ohne %q:\n%s", want, out)
		}
	}
}

func TestRunStatusAbgelaufen(t *testing.T) {
	keyring := startAgent(t)
	t.Setenv(envConfig, t.TempDir()+"/fehlt.yaml")
	// Abgelaufenes Zertifikat direkt in den Keyring legen (ohne Lifetime,
	// damit es nicht sofort entfernt wird).
	priv, pub := testKeyPair(t)
	cert := testSignCert(t, newTestSigner(t), pub, -time.Hour)
	err := keyring.Add(agent.AddedKey{PrivateKey: priv, Certificate: cert, Comment: agentCommentPrefix + " " + cert.KeyId})
	if err != nil {
		t.Fatalf("vorbereiten: %v", err)
	}

	var stdout, stderr bytes.Buffer
	if got := Run(&stdout, &stderr, []string{"status"}); got != 1 {
		t.Fatalf("status = %d, erwartet 1 (abgelaufen)", got)
	}
	if !strings.Contains(stdout.String(), "abgelaufen") {
		t.Errorf("stdout: %q", stdout.String())
	}
}

func TestRunStatusOhneAgent(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	t.Setenv(envConfig, t.TempDir()+"/fehlt.yaml")
	var stdout, stderr bytes.Buffer
	if got := Run(&stdout, &stderr, []string{"status"}); got != 1 {
		t.Fatalf("status = %d, erwartet 1", got)
	}
}

func TestRunStatusFlagFehler(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := Run(&stdout, &stderr, []string{"status", "--kaputt"}); got != 2 {
		t.Fatalf("status --kaputt = %d, erwartet 2", got)
	}
}
