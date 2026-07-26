package ca

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/google/uuid"

	"github.com/guided-traffic/guided-ssh/internal/store"
)

// EventAgentCertIssued is the audit event of an mTLS client certificate issuance.
const EventAgentCertIssued = "ca.agent_cert_issued"

// Lifetimes of the mTLS PKI: the CA is long-lived, client certificates last
// until rotation (Phase 10), the server certificate is reissued on every start.
const (
	mtlsCAValidity     = 10 * 365 * 24 * time.Hour
	AgentCertValidity  = 365 * 24 * time.Hour
	ServerCertValidity = 90 * 24 * time.Hour
)

// EnsureMTLSCA creates the X.509 CA for agent mTLS if none exists yet
// (bootstrap, analogous to EnsureCAKeys). The CA key is stored AES-GCM
// encrypted in ca_keys (purpose "mtls"), public_key holds the CA certificate as PEM.
// In self-managed mode this bootstrap is refused; use AdoptExternalKeys.
func (ca *CA) EnsureMTLSCA(ctx context.Context) error {
	if ca.selfManaged() {
		return fmt.Errorf("%w: call AdoptExternalKeys instead of EnsureMTLSCA", ErrSelfManaged)
	}
	keys, err := ca.store.ListActiveCAKeys(ctx, store.CAPurposeMTLS)
	if err != nil {
		return err
	}
	if len(keys) > 0 {
		return nil
	}

	certPEM, keyPEM, err := GenerateMTLSCA()
	if err != nil {
		return err
	}
	encrypted, err := encryptPrivateKey(ca.masterKey, keyPEM)
	if err != nil {
		return err
	}
	key := &store.CAKey{
		Purpose:             store.CAPurposeMTLS,
		Algorithm:           "ed25519",
		PublicKey:           string(certPEM),
		EncryptedPrivateKey: encrypted,
		State:               store.CAKeyStateActive,
	}
	if err := ca.store.CreateCAKey(ctx, key); err != nil {
		return fmt.Errorf("ca: persist mtls ca: %w", err)
	}
	payload, err := json.Marshal(map[string]any{"ca_key_id": key.ID, "purpose": store.CAPurposeMTLS})
	if err != nil {
		return err
	}
	return ca.store.AppendAuditEvent(ctx, &store.AuditEvent{EventType: EventKeyCreated, Payload: payload})
}

// GenerateMTLSCA creates a fresh agent mTLS CA: an Ed25519 key pair and the
// self-signed CA certificate for it, returned as PEM (PKCS#8 for the key).
// EnsureMTLSCA and the `gssh-server gen-mtls-ca` helper share this function, so
// a self-managed CA has exactly the same shape as a generated one.
func GenerateMTLSCA() (certPEM, keyPEM []byte, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("ca: generate mtls key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "guided-ssh agent mTLS CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(mtlsCAValidity),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("ca: create mtls ca certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("ca: marshal mtls key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}

// mtlsCA loads the CA certificate and private key of the active mTLS CA.
// In self-managed mode the material comes straight from the mounted files; the
// ca_keys row is derived state and carries no private key to decrypt.
func (ca *CA) mtlsCA(ctx context.Context) (*x509.Certificate, ed25519.PrivateKey, string, error) {
	if ca.selfManaged() {
		return ca.external.MTLS.Certificate, ca.external.MTLS.PrivateKey, ca.external.MTLS.CertPEM, nil
	}
	keys, err := ca.store.ListActiveCAKeys(ctx, store.CAPurposeMTLS)
	if err != nil {
		return nil, nil, "", err
	}
	for i := range keys {
		if keys[i].State != store.CAKeyStateActive {
			continue
		}
		block, _ := pem.Decode([]byte(keys[i].PublicKey))
		if block == nil {
			return nil, nil, "", fmt.Errorf("ca: mtls ca %s: no pem certificate", keys[i].ID)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, "", fmt.Errorf("ca: parse mtls ca %s: %w", keys[i].ID, err)
		}
		keyPEM, err := decryptPrivateKey(ca.masterKey, keys[i].EncryptedPrivateKey)
		if err != nil {
			return nil, nil, "", fmt.Errorf("ca: mtls ca %s: %w", keys[i].ID, err)
		}
		keyBlock, _ := pem.Decode(keyPEM)
		if keyBlock == nil {
			return nil, nil, "", fmt.Errorf("ca: mtls ca %s: no pem key", keys[i].ID)
		}
		parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, nil, "", fmt.Errorf("ca: parse mtls key %s: %w", keys[i].ID, err)
		}
		priv, ok := parsed.(ed25519.PrivateKey)
		if !ok {
			return nil, nil, "", fmt.Errorf("ca: mtls key %s: unexpected type %T", keys[i].ID, parsed)
		}
		return cert, priv, keys[i].PublicKey, nil
	}
	return nil, nil, "", fmt.Errorf("ca: no active mtls ca (EnsureMTLSCA missing?)")
}

// MTLSCAPEM returns the CA certificate as PEM (trust anchor for agents
// and the server's ClientCAs).
func (ca *CA) MTLSCAPEM(ctx context.Context) (string, error) {
	_, _, pemStr, err := ca.mtlsCA(ctx)
	return pemStr, err
}

// MTLSCAPool returns the mTLS CA as a CertPool (for tls.Config.ClientCAs).
func (ca *CA) MTLSCAPool(ctx context.Context) (*x509.CertPool, error) {
	cert, _, _, err := ca.mtlsCA(ctx)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pool, nil
}

// IssueAgentCert signs a host agent's CSR as an mTLS client certificate.
// The CommonName is set server-side to the host ID — the identity comes
// from the enrollment, never from the CSR.
func (ca *CA) IssueAgentCert(ctx context.Context, hostID uuid.UUID, csrPEM []byte) (string, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return "", fmt.Errorf("ca: not a pem csr")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("ca: parse csr: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return "", fmt.Errorf("ca: invalid csr signature: %w", err)
	}
	caCert, caPriv, _, err := ca.mtlsCA(ctx)
	if err != nil {
		return "", err
	}
	serial, err := randomSerial()
	if err != nil {
		return "", err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hostID.String()},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(AgentCertValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, csr.PublicKey, caPriv)
	if err != nil {
		return "", fmt.Errorf("ca: create agent certificate: %w", err)
	}
	payload, err := json.Marshal(map[string]any{
		"host_id": hostID, "serial": serial.String(), "not_after": template.NotAfter,
	})
	if err != nil {
		return "", err
	}
	event := &store.AuditEvent{EventType: EventAgentCertIssued, Actor: "host:" + hostID.String(), Payload: payload}
	if err := ca.store.AppendAuditEvent(ctx, event); err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), nil
}

// IssueServerCert issues the TLS server certificate of the agent listener
// (freshly on every start, in memory only). Names may be DNS names or
// IP addresses.
func (ca *CA) IssueServerCert(ctx context.Context, names []string) (tls.Certificate, error) {
	caCert, caPriv, _, err := ca.mtlsCA(ctx)
	if err != nil {
		return tls.Certificate{}, err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := randomSerial()
	if err != nil {
		return tls.Certificate{}, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "guided-ssh agent api"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(ServerCertValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, name := range names {
		if ip := net.ParseIP(name); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else if name != "" {
			template.DNSNames = append(template.DNSNames, name)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, pub, caPriv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("ca: create server certificate: %w", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, nil
}

// randomSerial generates a random X.509 serial number (collision- and
// prediction-resistant; SSH serials still come from the DB sequence).
func randomSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("ca: generate serial number: %w", err)
	}
	return serial, nil
}
