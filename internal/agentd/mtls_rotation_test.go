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

// RenewMTLS signs the submitted CSR with a throwaway CA (the rotation only
// checks key-certificate pairing, no chain).
func (f *fakeAPI) RenewMTLS(_ context.Context, csrPEM string) (string, error) {
	f.mtlsCalls.Add(1)
	if f.mtlsErr != nil {
		return "", f.mtlsErr
	}
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return "", errors.New("not a pem csr")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return "", err
	}
	return testClientCertPEM(csr.PublicKey, 0)
}

// clientCertValidity is the validity period of test client certificates
// (like ca.AgentCertValidity: 1 year).
const clientCertValidity = 365 * 24 * time.Hour

// testClientCertPEM issues a client certificate for pub whose validity has
// already advanced by elapsed.
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

// writeAgentCert places a client certificate with advanced validity into
// the daemon's state directory.
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

	// No file ⇒ attempt rotation (self-heal via the loaded pair).
	if !mtlsNeedsRotation(d.paths.AgentCertFile(), time.Now()) {
		t.Error("missing certificate file must trigger rotation")
	}
	// Fresh (10% elapsed) ⇒ no rotation.
	writeAgentCert(t, d, clientCertValidity/10)
	if mtlsNeedsRotation(d.paths.AgentCertFile(), time.Now()) {
		t.Error("fresh certificate must not be rotated")
	}
	// 80% elapsed ⇒ rotation.
	writeAgentCert(t, d, clientCertValidity*8/10)
	if !mtlsNeedsRotation(d.paths.AgentCertFile(), time.Now()) {
		t.Error("2/3 of validity exceeded must trigger rotation")
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
	// The new pair is on disk and consistent (key matches the certificate)
	// — and the new certificate is fresh.
	if _, err := os.Stat(d.paths.AgentKeyFile()); err != nil {
		t.Fatalf("agent.key missing: %v", err)
	}
	if mtlsNeedsRotation(d.paths.AgentCertFile(), time.Now()) {
		t.Error("certificate must be fresh after rotation")
	}

	// Second run: fresh ⇒ no further API call.
	d.rotateMTLSIfNeeded(context.Background())
	if api.mtlsCalls.Load() != 1 {
		t.Errorf("fresh certificate rotated again (calls=%d)", api.mtlsCalls.Load())
	}
}

func TestRotateMTLSErrorKeepsOldPair(t *testing.T) {
	api := &fakeAPI{mtlsErr: errors.New("server unreachable")}
	d := newTestDaemon(t, api)
	writeAgentCert(t, d, clientCertValidity*8/10)
	before, err := os.ReadFile(d.paths.AgentCertFile())
	if err != nil {
		t.Fatal(err)
	}

	d.rotateMTLSIfNeeded(context.Background())
	after, err := os.ReadFile(d.paths.AgentCertFile())
	if err != nil || string(after) != string(before) {
		t.Fatalf("a failed rotation must not touch the certificate: %v", err)
	}
}
