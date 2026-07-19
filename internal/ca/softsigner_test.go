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
		t.Fatalf("unerwartete Felder: %+v", key)
	}
	if !strings.HasPrefix(key.PublicKey, "ssh-ed25519 ") {
		t.Fatalf("Public Key nicht im authorized_keys-Format: %q", key.PublicKey)
	}
	if len(key.EncryptedPrivateKey) == 0 {
		t.Fatal("EncryptedPrivateKey leer")
	}
	// Private Key darf nicht im Klartext vorliegen.
	if bytes.Contains(key.EncryptedPrivateKey, []byte("OPENSSH PRIVATE KEY")) {
		t.Fatal("Private Key unverschlüsselt gespeichert")
	}
}

func TestNewCAKeyUnbekannterZweck(t *testing.T) {
	if _, err := NewCAKey("robot", testMasterKey()); err == nil {
		t.Fatal("Fehler erwartet")
	}
}

func TestNewSoftwareSignerFalscherMasterKey(t *testing.T) {
	key, err := NewCAKey(store.CertTypeUser, testMasterKey())
	if err != nil {
		t.Fatalf("NewCAKey: %v", err)
	}
	wrongKey := testMasterKey()
	wrongKey[0] ^= 0xff
	if _, err := NewSoftwareSigner(key, wrongKey); !errors.Is(err, ErrInvalidMasterKey) {
		t.Fatalf("ErrInvalidMasterKey erwartet, bekommen: %v", err)
	}
}

func TestNewSoftwareSignerOhnePrivateKey(t *testing.T) {
	key := &store.CAKey{PublicKey: "ssh-ed25519 AAAA"}
	if _, err := NewSoftwareSigner(key, testMasterKey()); err == nil {
		t.Fatal("Fehler erwartet (KMS-Key ohne Private Key)")
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
		t.Fatal("Signer-PublicKey stimmt nicht mit persistiertem CA-Key überein")
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
		t.Fatalf("unerwartete Zertifikatsfelder: serial=%d keyid=%q type=%d", cert.Serial, cert.KeyId, cert.CertType)
	}
	if len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != "alice" {
		t.Fatalf("Principals: %v", cert.ValidPrincipals)
	}
	if cert.ValidAfter != uint64(req.ValidAfter.Unix()) || cert.ValidBefore != uint64(req.ValidBefore.Unix()) { //nolint:gosec // Zeiten nach 1970
		t.Fatalf("Gültigkeitsfenster: %d–%d", cert.ValidAfter, cert.ValidBefore)
	}
	if _, ok := cert.Extensions["permit-pty"]; !ok {
		t.Fatalf("Extension permit-pty fehlt: %v", cert.Extensions)
	}
	if cert.CriticalOptions["source-address"] != "10.0.0.0/8" {
		t.Fatalf("Critical Options: %v", cert.CriticalOptions)
	}

	// Signatur mit CertChecker verifizieren (Principal + Zeitfenster + Signatur).
	checker := ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return bytes.Equal(auth.Marshal(), signer.PublicKey().Marshal())
		},
	}
	if _, err := checker.Authenticate(fakeConnMetadata{user: "alice"}, cert); err != nil {
		t.Fatalf("Zertifikatsprüfung fehlgeschlagen: %v", err)
	}
}

func TestSoftwareSignerSignHostZertifikat(t *testing.T) {
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
		t.Fatalf("CertType = %d, erwartet HostCert", cert.CertType)
	}
}

func TestSoftwareSignerSignFehler(t *testing.T) {
	caKey, err := NewCAKey(store.CertTypeUser, testMasterKey())
	if err != nil {
		t.Fatalf("NewCAKey: %v", err)
	}
	signer, err := NewSoftwareSigner(caKey, testMasterKey())
	if err != nil {
		t.Fatalf("NewSoftwareSigner: %v", err)
	}
	if _, err := signer.Sign(context.Background(), CertRequest{CertType: "robot"}); err == nil {
		t.Fatal("Fehler erwartet (unbekannter Typ)")
	}
	if _, err := signer.Sign(context.Background(), CertRequest{CertType: store.CertTypeUser}); err == nil {
		t.Fatal("Fehler erwartet (kein Public Key)")
	}
}

// fakeConnMetadata liefert dem CertChecker den Ziel-Usernamen.
type fakeConnMetadata struct{ user string }

func (m fakeConnMetadata) User() string          { return m.user }
func (m fakeConnMetadata) SessionID() []byte     { return nil }
func (m fakeConnMetadata) ClientVersion() []byte { return nil }
func (m fakeConnMetadata) ServerVersion() []byte { return nil }
func (m fakeConnMetadata) RemoteAddr() net.Addr  { return nil }
func (m fakeConnMetadata) LocalAddr() net.Addr   { return nil }
