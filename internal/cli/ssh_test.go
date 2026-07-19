package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestRunSSHMitGueltigemZertifikat(t *testing.T) {
	startAgent(t)
	idp := newFakeIDP(t)
	sign := newFakeSign(t, idp.idToken, time.Hour, false)
	stubBrowser(t)
	config := minimalConfig(t, idp, sign)
	t.Setenv(envConfig, config)

	var out bytes.Buffer
	if got := Run(&out, &out, []string{"login", "--config", config}); got != 0 {
		t.Fatalf("login = %d (%s)", got, out.String())
	}

	argv := stubExecSSH(t, nil)
	var stdout, stderr bytes.Buffer
	if got := Run(&stdout, &stderr, []string{"ssh", "host1", "-l", "root"}); got != 0 {
		t.Fatalf("ssh = %d (stderr: %s)", got, stderr.String())
	}
	if want := []string{"host1", "-l", "root"}; strings.Join(*argv, " ") != strings.Join(want, " ") {
		t.Errorf("ssh-argumente = %v, erwartet %v", *argv, want)
	}
	if idp.tokenCalls.Load() != 1 {
		t.Errorf("gültiges zertifikat, trotzdem neuer login: tokenCalls = %d", idp.tokenCalls.Load())
	}
}

func TestRunSSHAutoLogin(t *testing.T) {
	keyring := startAgent(t)
	idp := newFakeIDP(t)
	sign := newFakeSign(t, idp.idToken, time.Hour, false)
	stubBrowser(t)
	t.Setenv(envConfig, minimalConfig(t, idp, sign))

	argv := stubExecSSH(t, nil)
	var stdout, stderr bytes.Buffer
	if got := Run(&stdout, &stderr, []string{"ssh", "host1"}); got != 0 {
		t.Fatalf("ssh = %d (stderr: %s)", got, stderr.String())
	}
	if idp.tokenCalls.Load() != 1 {
		t.Errorf("auto-login fehlte: tokenCalls = %d", idp.tokenCalls.Load())
	}
	if certs, _ := gsshCerts(keyring); len(certs) != 1 {
		t.Errorf("agent hat %d zertifikate, erwartet 1", len(certs))
	}
	if len(*argv) != 1 || (*argv)[0] != "host1" {
		t.Errorf("ssh-argumente = %v", *argv)
	}
}

func TestRunSSHExecFehler(t *testing.T) {
	startAgent(t)
	idp := newFakeIDP(t)
	sign := newFakeSign(t, idp.idToken, time.Hour, false)
	stubBrowser(t)
	t.Setenv(envConfig, minimalConfig(t, idp, sign))

	stubExecSSH(t, errors.New("exec kaputt"))
	var stdout, stderr bytes.Buffer
	if got := Run(&stdout, &stderr, []string{"ssh", "host1"}); got != 1 {
		t.Fatalf("ssh = %d, erwartet 1", got)
	}
	if !strings.Contains(stderr.String(), "exec kaputt") {
		t.Errorf("stderr: %q", stderr.String())
	}
}

func TestRunSSHOhneArgumente(t *testing.T) {
	startAgent(t)
	idp := newFakeIDP(t)
	sign := newFakeSign(t, idp.idToken, time.Hour, false)
	t.Setenv(envConfig, minimalConfig(t, idp, sign))

	var stdout, stderr bytes.Buffer
	if got := Run(&stdout, &stderr, []string{"ssh"}); got != 1 {
		t.Fatalf("ssh ohne args = %d, erwartet 1", got)
	}
	if !strings.Contains(stderr.String(), "aufruf") {
		t.Errorf("stderr: %q", stderr.String())
	}
}

func TestRunSSHOhneConfig(t *testing.T) {
	t.Setenv(envConfig, t.TempDir()+"/fehlt.yaml")
	var stdout, stderr bytes.Buffer
	if got := Run(&stdout, &stderr, []string{"ssh", "host1"}); got != 1 {
		t.Fatalf("ssh = %d, erwartet 1", got)
	}
	if !strings.Contains(stderr.String(), "konfigurationsdatei anlegen") {
		t.Errorf("hinweis fehlt: %q", stderr.String())
	}
}
