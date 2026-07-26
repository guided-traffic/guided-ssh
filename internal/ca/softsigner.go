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

// NewCAKey generates an Ed25519 CA key for the given purpose ("user" or
// "host"), encrypts the private key with the master key, and returns the
// persistable record (state active, still without an ID — the store assigns that).
func NewCAKey(purpose string, masterKey []byte) (*store.CAKey, error) {
	if purpose != store.CertTypeUser && purpose != store.CertTypeHost {
		return nil, fmt.Errorf("ca: unknown key purpose %q", purpose)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ca: generate key: %w", err)
	}
	pemBlock, err := ssh.MarshalPrivateKey(priv, "guided-ssh "+purpose+" ca")
	if err != nil {
		return nil, fmt.Errorf("ca: marshal private key: %w", err)
	}
	encrypted, err := encryptPrivateKey(masterKey, pem.EncodeToMemory(pemBlock))
	if err != nil {
		return nil, err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("ca: convert public key: %w", err)
	}
	return &store.CAKey{
		Purpose:             purpose,
		Algorithm:           "ed25519",
		PublicKey:           strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))),
		EncryptedPrivateKey: encrypted,
		State:               store.CAKeyStateActive,
	}, nil
}

// SoftwareSigner signs with an Ed25519 CA key that is stored AES-GCM
// encrypted in the database.
type SoftwareSigner struct {
	caKeyID uuid.UUID
	signer  ssh.Signer
}

// NewSoftwareSigner decrypts the CA key's private key with the master key
// and returns a ready-to-use signer.
func NewSoftwareSigner(k *store.CAKey, masterKey []byte) (*SoftwareSigner, error) {
	if len(k.EncryptedPrivateKey) == 0 {
		return nil, fmt.Errorf("ca: ca key %s has no private key (KMS/HSM key?)", k.ID)
	}
	pemBytes, err := decryptPrivateKey(masterKey, k.EncryptedPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("ca: ca key %s: %w", k.ID, err)
	}
	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("ca: parse ca key %s: %w", k.ID, err)
	}
	return &SoftwareSigner{caKeyID: k.ID, signer: signer}, nil
}

// Sign builds the SSH certificate from the request and signs it.
func (s *SoftwareSigner) Sign(_ context.Context, req CertRequest) (*ssh.Certificate, error) {
	cert, err := buildCert(req)
	if err != nil {
		return nil, err
	}
	if err := cert.SignCert(rand.Reader, s.signer); err != nil {
		return nil, fmt.Errorf("ca: sign: %w", err)
	}
	return cert, nil
}

// CAKeyID is the database ID of the CA key used.
func (s *SoftwareSigner) CAKeyID() uuid.UUID { return s.caKeyID }

// PublicKey is the public key of the CA key.
func (s *SoftwareSigner) PublicKey() ssh.PublicKey { return s.signer.PublicKey() }
