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

// newTestSigner returns a throwaway CA for agent tests.
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

// addForeignKey adds a foreign (non-guided-ssh) entry to the agent.
func addForeignKey(t *testing.T, ag agent.Agent) {
	t.Helper()
	priv, _ := testKeyPair(t)
	if err := ag.Add(agent.AddedKey{PrivateKey: priv, Comment: "foreign key"}); err != nil {
		t.Fatalf("loading foreign key: %v", err)
	}
}

func TestConnectAgentWithoutSocket(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	if _, _, err := connectAgent(); err == nil || !strings.Contains(err.Error(), "SSH_AUTH_SOCK") {
		t.Fatalf("expected SSH_AUTH_SOCK error, got %v", err)
	}
}

func TestConnectAgentSocketBroken(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "/does/not/exist.sock")
	if _, _, err := connectAgent(); err == nil {
		t.Fatal("expected connection error")
	}
}

func TestLoadIntoAgentAndGsshCerts(t *testing.T) {
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
		t.Fatalf("expected exactly our certificate, got %d", len(certs))
	}

	// Second login replaces the entry; the foreign key remains.
	priv2, pub2 := testKeyPair(t)
	cert2 := testSignCert(t, signer, pub2, 2*time.Hour)
	if err := loadIntoAgent(keyring, priv2, cert2); err != nil {
		t.Fatalf("second loadIntoAgent: %v", err)
	}
	keys, err := keyring.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 2 { // foreign key + exactly one guided-ssh entry
		t.Errorf("agent has %d entries, expected 2", len(keys))
	}
}

func TestLoadIntoAgentExpired(t *testing.T) {
	keyring := agent.NewKeyring()
	priv, pub := testKeyPair(t)
	cert := testSignCert(t, newTestSigner(t), pub, -time.Hour)
	if err := loadIntoAgent(keyring, priv, cert); err == nil {
		t.Fatal("expected error (expired)")
	}
}

func TestRemoveGsshKeysKeepsForeignKey(t *testing.T) {
	keyring := agent.NewKeyring()
	addForeignKey(t, keyring)
	priv, pub := testKeyPair(t)
	if err := loadIntoAgent(keyring, priv, testSignCert(t, newTestSigner(t), pub, time.Hour)); err != nil {
		t.Fatalf("loadIntoAgent: %v", err)
	}

	removed, err := removeGsshKeys(keyring)
	if err != nil || removed != 1 {
		t.Fatalf("removeGsshKeys = %d, %v — expected 1, nil", removed, err)
	}
	keys, _ := keyring.List()
	if len(keys) != 1 || keys[0].Comment != "foreign key" {
		t.Errorf("foreign key must remain: %+v", keys)
	}
}

func TestCertValid(t *testing.T) {
	signer := newTestSigner(t)
	_, pub := testKeyPair(t)

	valid := testSignCert(t, signer, pub, time.Hour)
	if !certValid(valid, 0) {
		t.Error("fresh certificate must be valid")
	}
	if certValid(valid, 2*time.Hour) {
		t.Error("margin larger than remaining validity ⇒ invalid")
	}

	expired := testSignCert(t, signer, pub, -time.Minute)
	if certValid(expired, 0) {
		t.Error("expired certificate must not be valid")
	}

	notYet := testSignCert(t, signer, pub, time.Hour)
	notYet.ValidAfter = uint64(time.Now().Add(30 * time.Minute).Unix()) //nolint:gosec // Unix time after 1970
	if certValid(notYet, 0) {
		t.Error("not-yet-valid certificate must not be valid")
	}

	if anyValidCert([]*ssh.Certificate{expired, valid}, 0) != true {
		t.Error("anyValidCert must find the valid one")
	}
	if anyValidCert([]*ssh.Certificate{expired}, 0) {
		t.Error("anyValidCert with none valid ⇒ false")
	}
}

func TestCertTimeClamp(t *testing.T) {
	// ssh.CertTimeInfinity (max uint64) must not overflow.
	if certTime(^uint64(0)).Before(time.Now()) {
		t.Error("certTime(max) must be in the future")
	}
}
