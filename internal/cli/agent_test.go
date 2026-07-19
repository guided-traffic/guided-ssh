package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// newTestSigner liefert eine Wegwerf-CA für Agent-Tests.
func newTestSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ca-key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return signer
}

// addForeignKey legt einen fremden (nicht guided-ssh) Eintrag in den Agenten.
func addForeignKey(t *testing.T, ag agent.Agent) {
	t.Helper()
	priv, _ := testKeyPair(t)
	if err := ag.Add(agent.AddedKey{PrivateKey: priv, Comment: "fremder schlüssel"}); err != nil {
		t.Fatalf("fremden key laden: %v", err)
	}
}

func TestConnectAgentOhneSocket(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	if _, _, err := connectAgent(); err == nil || !strings.Contains(err.Error(), "SSH_AUTH_SOCK") {
		t.Fatalf("erwartete SSH_AUTH_SOCK-fehler, bekam %v", err)
	}
}

func TestConnectAgentSocketKaputt(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "/nicht/vorhanden.sock")
	if _, _, err := connectAgent(); err == nil {
		t.Fatal("erwartete verbindungsfehler")
	}
}

func TestLoadIntoAgentUndGsshCerts(t *testing.T) {
	keyring := agent.NewKeyring()
	signer := newTestSigner(t)
	addForeignKey(t, keyring)

	priv, pub := testKeyPair(t)
	cert := testSignCert(t, signer, pub, time.Hour)
	if err := loadIntoAgent(keyring, priv, cert); err != nil {
		t.Fatalf("loadIntoAgent: %v", err)
	}

	certs, err := gsshCerts(keyring)
	if err != nil {
		t.Fatalf("gsshCerts: %v", err)
	}
	if len(certs) != 1 || certs[0].KeyId != cert.KeyId {
		t.Fatalf("erwartete genau unser zertifikat, bekam %d", len(certs))
	}

	// Zweiter Login ersetzt den Eintrag, der fremde Schlüssel bleibt.
	priv2, pub2 := testKeyPair(t)
	cert2 := testSignCert(t, signer, pub2, 2*time.Hour)
	if err := loadIntoAgent(keyring, priv2, cert2); err != nil {
		t.Fatalf("zweites loadIntoAgent: %v", err)
	}
	keys, err := keyring.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 2 { // fremder Schlüssel + genau ein guided-ssh-Eintrag
		t.Errorf("agent hat %d einträge, erwartet 2", len(keys))
	}
}

func TestLoadIntoAgentAbgelaufen(t *testing.T) {
	keyring := agent.NewKeyring()
	priv, pub := testKeyPair(t)
	cert := testSignCert(t, newTestSigner(t), pub, -time.Hour)
	if err := loadIntoAgent(keyring, priv, cert); err == nil {
		t.Fatal("fehler erwartet (abgelaufen)")
	}
}

func TestRemoveGsshKeysLaesstFremdeStehen(t *testing.T) {
	keyring := agent.NewKeyring()
	addForeignKey(t, keyring)
	priv, pub := testKeyPair(t)
	if err := loadIntoAgent(keyring, priv, testSignCert(t, newTestSigner(t), pub, time.Hour)); err != nil {
		t.Fatalf("loadIntoAgent: %v", err)
	}

	removed, err := removeGsshKeys(keyring)
	if err != nil || removed != 1 {
		t.Fatalf("removeGsshKeys = %d, %v — erwartet 1, nil", removed, err)
	}
	keys, _ := keyring.List()
	if len(keys) != 1 || keys[0].Comment != "fremder schlüssel" {
		t.Errorf("fremder schlüssel muss übrig bleiben: %+v", keys)
	}
}

func TestCertValid(t *testing.T) {
	signer := newTestSigner(t)
	_, pub := testKeyPair(t)

	valid := testSignCert(t, signer, pub, time.Hour)
	if !certValid(valid, 0) {
		t.Error("frisches zertifikat muss gültig sein")
	}
	if certValid(valid, 2*time.Hour) {
		t.Error("margin größer als restlaufzeit ⇒ ungültig")
	}

	expired := testSignCert(t, signer, pub, -time.Minute)
	if certValid(expired, 0) {
		t.Error("abgelaufenes zertifikat darf nicht gültig sein")
	}

	notYet := testSignCert(t, signer, pub, time.Hour)
	notYet.ValidAfter = uint64(time.Now().Add(30 * time.Minute).Unix()) //nolint:gosec // Unix-Zeit nach 1970
	if certValid(notYet, 0) {
		t.Error("noch nicht gültiges zertifikat darf nicht gültig sein")
	}

	if anyValidCert([]*ssh.Certificate{expired, valid}, 0) != true {
		t.Error("anyValidCert muss das gültige finden")
	}
	if anyValidCert([]*ssh.Certificate{expired}, 0) {
		t.Error("anyValidCert ohne gültige ⇒ false")
	}
}

func TestCertTimeClamp(t *testing.T) {
	// ssh.CertTimeInfinity (max uint64) darf nicht überlaufen.
	if certTime(^uint64(0)).Before(time.Now()) {
		t.Error("certTime(max) muss in der zukunft liegen")
	}
}
