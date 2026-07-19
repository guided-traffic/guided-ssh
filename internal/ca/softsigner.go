package ca

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/guided-traffic/guided-ssh/internal/store"
)

// NewCAKey erzeugt einen Ed25519-CA-Key für den gegebenen Zweck ("user" oder
// "host"), verschlüsselt den Private Key mit dem Master-Key und liefert den
// persistierbaren Datensatz (State active, noch ohne ID — die vergibt der Store).
func NewCAKey(purpose string, masterKey []byte) (*store.CAKey, error) {
	if purpose != store.CertTypeUser && purpose != store.CertTypeHost {
		return nil, fmt.Errorf("ca: unbekannter key-zweck %q", purpose)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ca: schlüssel erzeugen: %w", err)
	}
	pemBlock, err := ssh.MarshalPrivateKey(priv, "guided-ssh "+purpose+" ca")
	if err != nil {
		return nil, fmt.Errorf("ca: private key serialisieren: %w", err)
	}
	encrypted, err := encryptPrivateKey(masterKey, pem.EncodeToMemory(pemBlock))
	if err != nil {
		return nil, err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("ca: public key konvertieren: %w", err)
	}
	return &store.CAKey{
		Purpose:             purpose,
		Algorithm:           "ed25519",
		PublicKey:           strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))),
		EncryptedPrivateKey: encrypted,
		State:               store.CAKeyStateActive,
	}, nil
}

// SoftwareSigner signiert mit einem in der Datenbank abgelegten,
// AES-GCM-verschlüsselten Ed25519-CA-Key.
type SoftwareSigner struct {
	caKeyID uuid.UUID
	signer  ssh.Signer
}

// NewSoftwareSigner entschlüsselt den Private Key des CA-Keys mit dem
// Master-Key und liefert einen einsatzbereiten Signer.
func NewSoftwareSigner(k *store.CAKey, masterKey []byte) (*SoftwareSigner, error) {
	if len(k.EncryptedPrivateKey) == 0 {
		return nil, fmt.Errorf("ca: ca-key %s hat keinen private key (KMS/HSM-Key?)", k.ID)
	}
	pemBytes, err := decryptPrivateKey(masterKey, k.EncryptedPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("ca: ca-key %s: %w", k.ID, err)
	}
	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("ca: ca-key %s parsen: %w", k.ID, err)
	}
	return &SoftwareSigner{caKeyID: k.ID, signer: signer}, nil
}

// Sign baut das SSH-Zertifikat aus dem Request und signiert es.
func (s *SoftwareSigner) Sign(_ context.Context, req CertRequest) (*ssh.Certificate, error) {
	var certType uint32
	switch req.CertType {
	case store.CertTypeUser:
		certType = ssh.UserCert
	case store.CertTypeHost:
		certType = ssh.HostCert
	default:
		return nil, fmt.Errorf("ca: unbekannter zertifikatstyp %q", req.CertType)
	}
	if req.PublicKey == nil {
		return nil, fmt.Errorf("ca: request ohne public key")
	}
	cert := &ssh.Certificate{
		Key:             req.PublicKey,
		Serial:          req.Serial,
		CertType:        certType,
		KeyId:           req.KeyID,
		ValidPrincipals: req.Principals,
		ValidAfter:      uint64(req.ValidAfter.Unix()),  //nolint:gosec // Unix-Zeit nach 1970, nie negativ
		ValidBefore:     uint64(req.ValidBefore.Unix()), //nolint:gosec // dito
		Permissions: ssh.Permissions{
			CriticalOptions: req.CriticalOptions,
			Extensions:      req.Extensions,
		},
	}
	if err := cert.SignCert(rand.Reader, s.signer); err != nil {
		return nil, fmt.Errorf("ca: signieren: %w", err)
	}
	return cert, nil
}

// CAKeyID ist die Datenbank-ID des verwendeten CA-Keys.
func (s *SoftwareSigner) CAKeyID() uuid.UUID { return s.caKeyID }

// PublicKey ist der öffentliche Schlüssel des CA-Keys.
func (s *SoftwareSigner) PublicKey() ssh.PublicKey { return s.signer.PublicKey() }
