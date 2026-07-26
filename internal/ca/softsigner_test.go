package ca

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/guided-traffic/guided-ssh/internal/store"
)

func TestNewCAKey(t *testing.T) {
	key, err := NewCAKey(store.CertTypeUser, testMasterKey())
	if err != nil {
		t.Fatalf("NewCAKey: %v", err)
	}
	if key.Purpose != store.CertTypeUser || key.Algorithm != "ed25519" || key.State != store.CAKeyStateActive {
		t.Fatalf("unexpected fields: %+v", key)
	}
	if !strings.HasPrefix(key.PublicKey, "ssh-ed25519 ") {
		t.Fatalf("public key not in authorized_keys format: %q", key.PublicKey)
	}
	if len(key.EncryptedPrivateKey) == 0 {
		t.Fatal("EncryptedPrivateKey empty")
	}
	// Private key must not be present in plaintext.
	if bytes.Contains(key.EncryptedPrivateKey, []byte("OPENSSH PRIVATE KEY")) {
		t.Fatal("private key stored unencrypted")
	}
}

func TestNewCAKeyUnknownPurpose(t *testing.T) {
	if _, err := NewCAKey("robot", testMasterKey()); err == nil {
		t.Fatal("expected an error")
	}
}

func TestNewSoftwareSignerWrongMasterKey(t *testing.T) {
	key, err := NewCAKey(store.CertTypeUser, testMasterKey())
	if err != nil {
		t.Fatalf("NewCAKey: %v", err)
	}
	wrongKey := testMasterKey()
	wrongKey[0] ^= 0xff
	if _, err := NewSoftwareSigner(key, wrongKey); !errors.Is(err, ErrInvalidMasterKey) {
		t.Fatalf("expected ErrInvalidMasterKey, got: %v", err)
	}
}

func TestNewSoftwareSignerWithoutPrivateKey(t *testing.T) {
	key := &store.CAKey{PublicKey: "ssh-ed25519 AAAA"}
	if _, err := NewSoftwareSigner(key, testMasterKey()); err == nil {
		t.Fatal("expected an error (KMS key without a private key)")
	}
}

func TestSoftwareSignerSign(t *testing.T) {
	caKey, err := NewCAKey(store.CertTypeUser, testMasterKey())
	if err != nil {
		t.Fatalf("NewCAKey: %v", err)
	}
	signer, err := NewSoftwareSigner(caKey, testMasterKey())
	if err != nil {
		t.Fatalf("NewSoftwareSigner: %v", err)
	}
	if strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))) != caKey.PublicKey {
		t.Fatal("signer public key does not match the persisted ca key")
	}

	now := time.Now()
	req := CertRequest{
		CertType:        store.CertTypeUser,
		PublicKey:       testPublicKey(t),
		KeyID:           UserKeyID("sub-1", "https://idp.example"),
		Principals:      []string{"alice"},
		ValidAfter:      now.Add(-time.Minute),
		ValidBefore:     now.Add(time.Hour),
		Extensions:      map[string]string{"permit-pty": ""},
		CriticalOptions: map[string]string{"source-address": "10.0.0.0/8"},
		Serial:          42,
	}
	cert, err := signer.Sign(context.Background(), req)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if cert.Serial != 42 || cert.KeyId != req.KeyID || cert.CertType != ssh.UserCert {
		t.Fatalf("unexpected certificate fields: serial=%d keyid=%q type=%d", cert.Serial, cert.KeyId, cert.CertType)
	}
	if len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != "alice" {
		t.Fatalf("principals: %v", cert.ValidPrincipals)
	}
	if cert.ValidAfter != uint64(req.ValidAfter.Unix()) || cert.ValidBefore != uint64(req.ValidBefore.Unix()) { //nolint:gosec // times after 1970
		t.Fatalf("validity window: %d-%d", cert.ValidAfter, cert.ValidBefore)
	}
	if _, ok := cert.Extensions["permit-pty"]; !ok {
		t.Fatalf("extension permit-pty missing: %v", cert.Extensions)
	}
	if cert.CriticalOptions["source-address"] != "10.0.0.0/8" {
		t.Fatalf("critical options: %v", cert.CriticalOptions)
	}

	// Verify the signature with CertChecker (principal + time window + signature).
	checker := ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return bytes.Equal(auth.Marshal(), signer.PublicKey().Marshal())
		},
	}
	if _, err := checker.Authenticate(fakeConnMetadata{user: "alice"}, cert); err != nil {
		t.Fatalf("certificate check failed: %v", err)
	}
}

func TestSoftwareSignerSignHostCertificate(t *testing.T) {
	caKey, err := NewCAKey(store.CertTypeHost, testMasterKey())
	if err != nil {
		t.Fatalf("NewCAKey: %v", err)
	}
	signer, err := NewSoftwareSigner(caKey, testMasterKey())
	if err != nil {
		t.Fatalf("NewSoftwareSigner: %v", err)
	}
	now := time.Now()
	cert, err := signer.Sign(context.Background(), CertRequest{
		CertType:    store.CertTypeHost,
		PublicKey:   testPublicKey(t),
		KeyID:       HostKeyID("web-1.example"),
		Principals:  []string{"web-1.example"},
		ValidAfter:  now,
		ValidBefore: now.Add(24 * time.Hour),
		Serial:      7,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if cert.CertType != ssh.HostCert {
		t.Fatalf("CertType = %d, expected HostCert", cert.CertType)
	}
}

func TestSoftwareSignerSignError(t *testing.T) {
	caKey, err := NewCAKey(store.CertTypeUser, testMasterKey())
	if err != nil {
		t.Fatalf("NewCAKey: %v", err)
	}
	signer, err := NewSoftwareSigner(caKey, testMasterKey())
	if err != nil {
		t.Fatalf("NewSoftwareSigner: %v", err)
	}
	if _, err := signer.Sign(context.Background(), CertRequest{CertType: "robot"}); err == nil {
		t.Fatal("expected an error (unknown type)")
	}
	if _, err := signer.Sign(context.Background(), CertRequest{CertType: store.CertTypeUser}); err == nil {
		t.Fatal("expected an error (no public key)")
	}
}

// fakeConnMetadata gives the CertChecker the target username.
type fakeConnMetadata struct{ user string }

func (m fakeConnMetadata) User() string          { return m.user }
func (m fakeConnMetadata) SessionID() []byte     { return nil }
func (m fakeConnMetadata) ClientVersion() []byte { return nil }
func (m fakeConnMetadata) ServerVersion() []byte { return nil }
func (m fakeConnMetadata) RemoteAddr() net.Addr  { return nil }
func (m fakeConnMetadata) LocalAddr() net.Addr   { return nil }
