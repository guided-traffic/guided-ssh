package ca

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/guided-traffic/guided-ssh/internal/store"
)

// testCSR generates a valid agent CSR along with its private key.
func testCSR(t *testing.T) ([]byte, ed25519.PrivateKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, priv)
	if err != nil {
		t.Fatalf("csr: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), priv
}

func TestEnsureMTLSCAIdempotent(t *testing.T) {
	c, fs := newTestCA(t)
	ctx := context.Background()
	if err := c.EnsureMTLSCA(ctx); err != nil {
		t.Fatalf("EnsureMTLSCA: %v", err)
	}
	if err := c.EnsureMTLSCA(ctx); err != nil {
		t.Fatalf("second EnsureMTLSCA: %v", err)
	}
	count := 0
	for _, k := range fs.keys {
		if k.Purpose == store.CAPurposeMTLS {
			count++
		}
	}
	if count != 1 {
		t.Errorf("mtls keys = %d, expected 1", count)
	}
	if !slices.Contains(fs.eventTypes(), EventKeyCreated) {
		t.Errorf("key-created event missing: %v", fs.eventTypes())
	}
}

func TestIssueAgentCert(t *testing.T) {
	c, fs := newTestCA(t)
	ctx := context.Background()
	if err := c.EnsureMTLSCA(ctx); err != nil {
		t.Fatalf("EnsureMTLSCA: %v", err)
	}
	hostID := uuid.New()
	csrPEM, _ := testCSR(t)

	certPEM, err := c.IssueAgentCert(ctx, hostID, csrPEM)
	if err != nil {
		t.Fatalf("IssueAgentCert: %v", err)
	}
	block, _ := pem.Decode([]byte(certPEM))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	if cert.Subject.CommonName != hostID.String() {
		t.Errorf("cn = %q, expected host id", cert.Subject.CommonName)
	}
	if !slices.Contains(cert.ExtKeyUsage, x509.ExtKeyUsageClientAuth) {
		t.Error("clientAuth missing")
	}
	// Chain must verify against the CA.
	pool, err := c.MTLSCAPool(ctx)
	if err != nil {
		t.Fatalf("MTLSCAPool: %v", err)
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Errorf("chain check: %v", err)
	}
	if !slices.Contains(fs.eventTypes(), EventAgentCertIssued) {
		t.Errorf("audit event missing: %v", fs.eventTypes())
	}
}

func TestIssueAgentCertBrokenCSR(t *testing.T) {
	c, _ := newTestCA(t)
	ctx := context.Background()
	if err := c.EnsureMTLSCA(ctx); err != nil {
		t.Fatalf("EnsureMTLSCA: %v", err)
	}
	if _, err := c.IssueAgentCert(ctx, uuid.New(), []byte("not pem")); err == nil {
		t.Fatal("expected an error (not pem)")
	}
}

func TestIssueAgentCertWithoutCA(t *testing.T) {
	c, _ := newTestCA(t)
	csrPEM, _ := testCSR(t)
	if _, err := c.IssueAgentCert(context.Background(), uuid.New(), csrPEM); err == nil {
		t.Fatal("expected an error (no mtls ca)")
	}
}

func TestIssueServerCert(t *testing.T) {
	c, _ := newTestCA(t)
	ctx := context.Background()
	if err := c.EnsureMTLSCA(ctx); err != nil {
		t.Fatalf("EnsureMTLSCA: %v", err)
	}
	serverCert, err := c.IssueServerCert(ctx, []string{"localhost", "127.0.0.1", "gssh.example.com"})
	if err != nil {
		t.Fatalf("IssueServerCert: %v", err)
	}
	leaf, err := x509.ParseCertificate(serverCert.Certificate[0])
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !slices.Contains(leaf.DNSNames, "gssh.example.com") || len(leaf.IPAddresses) != 1 {
		t.Errorf("sans wrong: dns=%v ips=%v", leaf.DNSNames, leaf.IPAddresses)
	}
	if leaf.NotAfter.Before(time.Now().Add(24 * time.Hour)) {
		t.Error("server certificate expires too soon")
	}
	if _, ok := serverCert.PrivateKey.(ed25519.PrivateKey); !ok {
		t.Errorf("private key type %T", serverCert.PrivateKey)
	}
}

// TestMTLSHandshake: full TLS handshake with a client certificate against the
// mini PKI — the server requires and verifies the agent certificate.
func TestMTLSHandshake(t *testing.T) {
	c, _ := newTestCA(t)
	ctx := context.Background()
	if err := c.EnsureMTLSCA(ctx); err != nil {
		t.Fatalf("EnsureMTLSCA: %v", err)
	}
	hostID := uuid.New()
	csrPEM, agentPriv := testCSR(t)
	agentCertPEM, err := c.IssueAgentCert(ctx, hostID, csrPEM)
	if err != nil {
		t.Fatalf("IssueAgentCert: %v", err)
	}
	agentBlock, _ := pem.Decode([]byte(agentCertPEM))
	clientCert := tls.Certificate{Certificate: [][]byte{agentBlock.Bytes}, PrivateKey: agentPriv}

	serverCert, err := c.IssueServerCert(ctx, []string{"127.0.0.1"})
	if err != nil {
		t.Fatalf("IssueServerCert: %v", err)
	}
	pool, err := c.MTLSCAPool(ctx)
	if err != nil {
		t.Fatalf("MTLSCAPool: %v", err)
	}

	serverCfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	clientCfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		RootCAs:      pool,
		Certificates: []tls.Certificate{clientCert},
		ServerName:   "127.0.0.1",
	}

	serverConn, clientConn := tlsPipe(t, serverCfg, clientCfg)
	state := serverConn.ConnectionState()
	if len(state.PeerCertificates) == 0 || state.PeerCertificates[0].Subject.CommonName != hostID.String() {
		t.Errorf("server sees the wrong client certificate: %+v", state.PeerCertificates)
	}
	_ = serverConn.Close()
	_ = clientConn.Close()
}

// TestSelfManagedMTLSCA: in self-managed mode the agent PKI runs entirely on the
// mounted files — the ca_keys row is derived state without any private key, and
// issued agent certificates chain to the mounted CA certificate.
func TestSelfManagedMTLSCA(t *testing.T) {
	fs := &fakeStore{}
	keys := mountedKeys(t, t.TempDir())
	c := newSelfManagedCA(t, fs, keys)
	ctx := context.Background()
	if err := c.AdoptExternalKeys(ctx); err != nil {
		t.Fatalf("AdoptExternalKeys: %v", err)
	}

	pemStr, err := c.MTLSCAPEM(ctx)
	if err != nil {
		t.Fatalf("MTLSCAPEM: %v", err)
	}
	if pemStr != keys.MTLS.CertPEM {
		t.Errorf("MTLSCAPEM does not return the mounted certificate:\n%s", pemStr)
	}
	if row := caKeyFor(fs, store.CAPurposeMTLS, ""); row.EncryptedPrivateKey != nil {
		t.Error("mtls ca row must not carry private key material")
	}

	hostID := uuid.New()
	csrPEM, _ := testCSR(t)
	agentCertPEM, err := c.IssueAgentCert(ctx, hostID, csrPEM)
	if err != nil {
		t.Fatalf("IssueAgentCert: %v", err)
	}
	block, _ := pem.Decode([]byte(agentCertPEM))
	if block == nil {
		t.Fatalf("agent certificate is not pem: %s", agentCertPEM)
	}
	agentCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse agent certificate: %v", err)
	}
	if agentCert.Subject.CommonName != hostID.String() {
		t.Errorf("cn = %q, want the host id", agentCert.Subject.CommonName)
	}
	if err := agentCert.CheckSignatureFrom(keys.MTLS.Certificate); err != nil {
		t.Errorf("agent certificate was not signed by the mounted ca: %v", err)
	}
	pool, err := c.MTLSCAPool(ctx)
	if err != nil {
		t.Fatalf("MTLSCAPool: %v", err)
	}
	if _, err := agentCert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Errorf("chain check against the mounted ca: %v", err)
	}
}

// tlsPipe connects client and server over net.Pipe and performs the handshake.
func tlsPipe(t *testing.T, serverCfg, clientCfg *tls.Config) (*tls.Conn, *tls.Conn) {
	t.Helper()
	rawServer, rawClient := net.Pipe()
	server := tls.Server(rawServer, serverCfg)
	client := tls.Client(rawClient, clientCfg)
	errCh := make(chan error, 1)
	go func() { errCh <- server.Handshake() }()
	if err := client.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
	return server, client
}
