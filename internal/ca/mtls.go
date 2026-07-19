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

// EventAgentCertIssued ist das Audit-Event einer mTLS-Client-Zertifikat-Ausstellung.
const EventAgentCertIssued = "ca.agent_cert_issued"

// Laufzeiten der mTLS-PKI: CA langlebig, Client-Zertifikate bis zur Rotation
// (Phase 10), Server-Zertifikat wird bei jedem Start neu ausgestellt.
const (
	mtlsCAValidity     = 10 * 365 * 24 * time.Hour
	AgentCertValidity  = 365 * 24 * time.Hour
	ServerCertValidity = 90 * 24 * time.Hour
)

// EnsureMTLSCA legt die X.509-CA für Agent-mTLS an, falls noch keine existiert
// (Bootstrap, analog EnsureCAKeys). Der CA-Key liegt AES-GCM-verschlüsselt in
// ca_keys (purpose "mtls"), public_key enthält das CA-Zertifikat als PEM.
func (ca *CA) EnsureMTLSCA(ctx context.Context) error {
	keys, err := ca.store.ListActiveCAKeys(ctx, store.CAPurposeMTLS)
	if err != nil {
		return err
	}
	if len(keys) > 0 {
		return nil
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("ca: mtls-key erzeugen: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return err
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
		return fmt.Errorf("ca: mtls-ca-zertifikat erstellen: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("ca: mtls-key serialisieren: %w", err)
	}
	encrypted, err := encryptPrivateKey(ca.masterKey,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		return err
	}
	key := &store.CAKey{
		Purpose:             store.CAPurposeMTLS,
		Algorithm:           "ed25519",
		PublicKey:           string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		EncryptedPrivateKey: encrypted,
		State:               store.CAKeyStateActive,
	}
	if err := ca.store.CreateCAKey(ctx, key); err != nil {
		return fmt.Errorf("ca: mtls-ca persistieren: %w", err)
	}
	payload, err := json.Marshal(map[string]any{"ca_key_id": key.ID, "purpose": store.CAPurposeMTLS})
	if err != nil {
		return err
	}
	return ca.store.AppendAuditEvent(ctx, &store.AuditEvent{EventType: EventKeyCreated, Payload: payload})
}

// mtlsCA lädt CA-Zertifikat und Private Key der aktiven mTLS-CA.
func (ca *CA) mtlsCA(ctx context.Context) (*x509.Certificate, ed25519.PrivateKey, string, error) {
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
			return nil, nil, "", fmt.Errorf("ca: mtls-ca %s: kein pem-zertifikat", keys[i].ID)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, "", fmt.Errorf("ca: mtls-ca %s parsen: %w", keys[i].ID, err)
		}
		keyPEM, err := decryptPrivateKey(ca.masterKey, keys[i].EncryptedPrivateKey)
		if err != nil {
			return nil, nil, "", fmt.Errorf("ca: mtls-ca %s: %w", keys[i].ID, err)
		}
		keyBlock, _ := pem.Decode(keyPEM)
		if keyBlock == nil {
			return nil, nil, "", fmt.Errorf("ca: mtls-ca %s: kein pem-key", keys[i].ID)
		}
		parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, nil, "", fmt.Errorf("ca: mtls-key %s parsen: %w", keys[i].ID, err)
		}
		priv, ok := parsed.(ed25519.PrivateKey)
		if !ok {
			return nil, nil, "", fmt.Errorf("ca: mtls-key %s: unerwarteter typ %T", keys[i].ID, parsed)
		}
		return cert, priv, keys[i].PublicKey, nil
	}
	return nil, nil, "", fmt.Errorf("ca: keine aktive mtls-ca (EnsureMTLSCA fehlt?)")
}

// MTLSCAPEM liefert das CA-Zertifikat als PEM (Vertrauensanker für Agenten
// und ClientCAs des Servers).
func (ca *CA) MTLSCAPEM(ctx context.Context) (string, error) {
	_, _, pemStr, err := ca.mtlsCA(ctx)
	return pemStr, err
}

// MTLSCAPool liefert die mTLS-CA als CertPool (für tls.Config.ClientCAs).
func (ca *CA) MTLSCAPool(ctx context.Context) (*x509.CertPool, error) {
	cert, _, _, err := ca.mtlsCA(ctx)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pool, nil
}

// IssueAgentCert signiert den CSR eines Host-Agenten als mTLS-Client-Zertifikat.
// Der CommonName wird serverseitig auf die Host-ID gesetzt — die Identität
// kommt aus dem Enrollment, nie aus dem CSR.
func (ca *CA) IssueAgentCert(ctx context.Context, hostID uuid.UUID, csrPEM []byte) (string, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return "", fmt.Errorf("ca: kein pem-csr")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("ca: csr parsen: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return "", fmt.Errorf("ca: csr-signatur ungültig: %w", err)
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
		return "", fmt.Errorf("ca: agent-zertifikat erstellen: %w", err)
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

// IssueServerCert stellt das TLS-Server-Zertifikat des Agent-Listeners aus
// (bei jedem Start neu, nur im Speicher). Namen dürfen DNS-Namen oder
// IP-Adressen sein.
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
		return tls.Certificate{}, fmt.Errorf("ca: server-zertifikat erstellen: %w", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, nil
}

// randomSerial erzeugt eine zufällige X.509-Seriennummer (Kollisions- und
// Vorhersagefreiheit; SSH-Serials kommen weiterhin aus der DB-Sequence).
func randomSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("ca: seriennummer erzeugen: %w", err)
	}
	return serial, nil
}
