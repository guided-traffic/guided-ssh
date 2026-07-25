package pintls_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/guided-traffic/guided-ssh/internal/pintls"
)

// testCert baut ein selbstsigniertes Zertifikat für die Pin-Berechnung.
func testCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "pin-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// TestFromCertificate belegt, dass der Helper den Base64-SHA-256 des
// SubjectPublicKeyInfo liefert und sein Ergebnis von DecodePin/Verifier
// akzeptiert wird (eine Quelle für alle drei Wege).
func TestFromCertificate(t *testing.T) {
	cert := testCert(t)

	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	want := base64.StdEncoding.EncodeToString(sum[:])

	got := pintls.FromCertificate(cert)
	if got != want {
		t.Fatalf("pin = %q, erwartet %q", got, want)
	}

	pin, err := pintls.DecodePin(got)
	if err != nil {
		t.Fatalf("DecodePin: %v", err)
	}
	if len(pin) != sha256.Size {
		t.Fatalf("dekodierte länge = %d, erwartet %d", len(pin), sha256.Size)
	}

	// Ein anderes Zertifikat muss einen anderen Pin liefern.
	if other := pintls.FromCertificate(testCert(t)); other == got {
		t.Error("zwei zertifikate liefern denselben pin")
	}
}
