package cli

import (
	"bytes"
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
	if !strings.Contains(stdout.String(), "angemeldet: user:alice@fake-idp") {
		t.Errorf("stdout: %q", stdout.String())
	}

	certs, err := gsshCerts(keyring)
	if err != nil || len(certs) != 1 {
		t.Fatalf("agent: %d zertifikate, %v — erwartet 1", len(certs), err)
	}
	if got := certs[0].ValidPrincipals; len(got) != 2 || got[0] != "alice" {
		t.Errorf("principals: %v", got)
	}
	if idp.tokenCalls.Load() != 1 {
		t.Errorf("tokenCalls = %d, erwartet 1", idp.tokenCalls.Load())
	}
}

func TestLoginErsetztAltenEintrag(t *testing.T) {
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
		t.Errorf("agent hat %d guided-ssh-zertifikate, erwartet 1", len(certs))
	}
	if idp.tokenCalls.Load() != 2 {
		t.Errorf("tokenCalls = %d, erwartet 2", idp.tokenCalls.Load())
	}
}

func TestLoginIfNeededUeberspringt(t *testing.T) {
	startAgent(t)
	idp := newFakeIDP(t)
	sign := newFakeSign(t, idp.idToken, time.Hour, false)
	stubBrowser(t)
	config := minimalConfig(t, idp, sign)

	var out bytes.Buffer
	if got := Run(&out, &out, []string{"login", "--config", config}); got != 0 {
		t.Fatalf("erster login = %d (%s)", got, out.String())
	}
	if got := Run(&out, &out, []string{"login", "--if-needed", "--config", config}); got != 0 {
		t.Fatalf("if-needed = %d (%s)", got, out.String())
	}
	if idp.tokenCalls.Load() != 1 {
		t.Errorf("if-needed hat neu angemeldet: tokenCalls = %d", idp.tokenCalls.Load())
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
		t.Errorf("user-code fehlt in stderr: %q", stderr.String())
	}
	if certs, _ := gsshCerts(keyring); len(certs) != 1 {
		t.Errorf("agent hat %d zertifikate, erwartet 1", len(certs))
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
		t.Errorf("validity_seconds = %d, erwartet 7200", sign.lastValidity.Load())
	}
}

func TestLoginValidityAusConfig(t *testing.T) {
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
		t.Errorf("validity_seconds = %d, erwartet 5400 (aus config)", sign.lastValidity.Load())
	}
}

func TestLoginSignAbgelehnt(t *testing.T) {
	keyring := startAgent(t)
	idp := newFakeIDP(t)
	sign := newFakeSign(t, "anderes-token", time.Hour, false)
	stubBrowser(t)

	var stdout, stderr bytes.Buffer
	got := Run(&stdout, &stderr, []string{"login", "--config", minimalConfig(t, idp, sign)})
	if got != 1 {
		t.Fatalf("login = %d, erwartet 1", got)
	}
	if !strings.Contains(stderr.String(), "401") {
		t.Errorf("stderr ohne 401: %q", stderr.String())
	}
	if certs, _ := gsshCerts(keyring); len(certs) != 0 {
		t.Errorf("agent darf nach fehlschlag leer sein, hat %d", len(certs))
	}
}

func TestLoginAbgelaufenesZertifikatVomServer(t *testing.T) {
	startAgent(t)
	idp := newFakeIDP(t)
	sign := newFakeSign(t, idp.idToken, -time.Hour, false) // Server liefert abgelaufenes Zertifikat
	stubBrowser(t)

	var stdout, stderr bytes.Buffer
	if got := Run(&stdout, &stderr, []string{"login", "--config", minimalConfig(t, idp, sign)}); got != 1 {
		t.Fatalf("login = %d, erwartet 1 (stderr: %s)", got, stderr.String())
	}
	if !strings.Contains(stderr.String(), "abgelaufen") {
		t.Errorf("stderr: %q", stderr.String())
	}
}

func TestLoginOhneAgent(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	idp := newFakeIDP(t)
	sign := newFakeSign(t, idp.idToken, time.Hour, false)

	var stdout, stderr bytes.Buffer
	if got := Run(&stdout, &stderr, []string{"login", "--config", minimalConfig(t, idp, sign)}); got != 1 {
		t.Fatalf("login = %d, erwartet 1", got)
	}
	if !strings.Contains(stderr.String(), "SSH_AUTH_SOCK") {
		t.Errorf("stderr: %q", stderr.String())
	}
}

func TestLoginIssuerNichtErreichbar(t *testing.T) {
	startAgent(t)
	config := writeConfig(t, "api_url: http://127.0.0.1:1\nissuer: http://127.0.0.1:1\nclient_id: c\n")
	var stdout, stderr bytes.Buffer
	if got := Run(&stdout, &stderr, []string{"login", "--config", config}); got != 1 {
		t.Fatalf("login = %d, erwartet 1", got)
	}
}

func TestLoginOhneConfig(t *testing.T) {
	var stdout, stderr bytes.Buffer
	missing := t.TempDir() + "/fehlt.yaml"
	if got := Run(&stdout, &stderr, []string{"login", "--config", missing}); got != 1 {
		t.Fatalf("login = %d, erwartet 1", got)
	}
	if !strings.Contains(stderr.String(), "konfigurationsdatei anlegen") {
		t.Errorf("hinweis fehlt: %q", stderr.String())
	}
}
