package agentd

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"testing"
	"time"
)

// RenewMTLS signiert den eingereichten CSR mit einer Wegwerf-CA (die Rotation
// prüft nur Schlüssel-Zertifikat-Paarung, keine Kette).
func (f *fakeAPI) RenewMTLS(_ context.Context, csrPEM string) (string, error) {
	f.mtlsCalls.Add(1)
	if f.mtlsErr != nil {
		return "", f.mtlsErr
	}
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return "", errors.New("kein pem-csr")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return "", err
	}
	return testClientCertPEM(csr.PublicKey, 0)
}

// clientCertValidity ist die Laufzeit der Test-Client-Zertifikate (wie
// ca.AgentCertValidity: 1 Jahr).
const clientCertValidity = 365 * 24 * time.Hour

// testClientCertPEM stellt ein Client-Zertifikat für pub aus, dessen Laufzeit
// bereits um elapsed fortgeschritten ist.
func testClientCertPEM(pub crypto.PublicKey, elapsed time.Duration) (string, error) {
	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "00000000-0000-0000-0000-000000000000"},
		NotBefore:    time.Now().Add(-elapsed),
		NotAfter:     time.Now().Add(clientCertValidity - elapsed),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, caPriv)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), nil
}

// writeAgentCert legt ein Client-Zertifikat mit fortgeschrittener Laufzeit
// in das State-Verzeichnis des Daemons.
func writeAgentCert(t *testing.T, d *Daemon, elapsed time.Duration) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, err := testClientCertPEM(pub, elapsed)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(d.paths.AgentCertFile(), []byte(certPEM), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestMTLSNeedsRotation(t *testing.T) {
	api := &fakeAPI{}
	d := newTestDaemon(t, api)

	// Keine Datei ⇒ Rotation versuchen (Selbstheilung über das geladene Paar).
	if !mtlsNeedsRotation(d.paths.AgentCertFile(), time.Now()) {
		t.Error("fehlende zertifikatsdatei muss rotation auslösen")
	}
	// Frisch (10 % verstrichen) ⇒ keine Rotation.
	writeAgentCert(t, d, clientCertValidity/10)
	if mtlsNeedsRotation(d.paths.AgentCertFile(), time.Now()) {
		t.Error("frisches zertifikat darf nicht rotiert werden")
	}
	// 80 % verstrichen ⇒ Rotation.
	writeAgentCert(t, d, clientCertValidity*8/10)
	if !mtlsNeedsRotation(d.paths.AgentCertFile(), time.Now()) {
		t.Error("2/3 laufzeit überschritten muss rotation auslösen")
	}
}

func TestRotateMTLSIfNeeded(t *testing.T) {
	api := &fakeAPI{}
	d := newTestDaemon(t, api)
	writeAgentCert(t, d, clientCertValidity*8/10)

	d.rotateMTLSIfNeeded(context.Background())
	if api.mtlsCalls.Load() != 1 {
		t.Fatalf("mtlsCalls = %d", api.mtlsCalls.Load())
	}
	// Neues Paar liegt auf Platte und ist konsistent (Schlüssel passt zum
	// Zertifikat) — und das neue Zertifikat ist frisch.
	if _, err := os.Stat(d.paths.AgentKeyFile()); err != nil {
		t.Fatalf("agent.key fehlt: %v", err)
	}
	if mtlsNeedsRotation(d.paths.AgentCertFile(), time.Now()) {
		t.Error("nach rotation muss das zertifikat frisch sein")
	}

	// Zweiter Lauf: frisch ⇒ kein weiterer API-Call.
	d.rotateMTLSIfNeeded(context.Background())
	if api.mtlsCalls.Load() != 1 {
		t.Errorf("frisches zertifikat erneut rotiert (calls=%d)", api.mtlsCalls.Load())
	}
}

func TestRotateMTLSFehlerLaesstAltesPaarStehen(t *testing.T) {
	api := &fakeAPI{mtlsErr: errors.New("server nicht erreichbar")}
	d := newTestDaemon(t, api)
	writeAgentCert(t, d, clientCertValidity*8/10)
	before, err := os.ReadFile(d.paths.AgentCertFile())
	if err != nil {
		t.Fatal(err)
	}

	d.rotateMTLSIfNeeded(context.Background())
	after, err := os.ReadFile(d.paths.AgentCertFile())
	if err != nil || string(after) != string(before) {
		t.Fatalf("fehlgeschlagene rotation darf das zertifikat nicht anfassen: %v", err)
	}
}
