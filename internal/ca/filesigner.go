package ca

import (
	"context"
	"crypto/rand"
	"fmt"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
)

// FileSigner signs with an externally managed CA key that was loaded from a
// mounted key file (self-managed mode). Unlike SoftwareSigner it never touches
// encrypted_private_key: the ca_keys row only carries the public key and the
// ID this signer stamps onto issued certificates.
type FileSigner struct {
	caKeyID uuid.UUID
	signer  ssh.Signer
}

// NewFileSigner binds a key loaded by LoadExternalKeys to the ca_keys row that
// AdoptCAKey selected or created for it.
func NewFileSigner(caKeyID uuid.UUID, signer ssh.Signer) *FileSigner {
	return &FileSigner{caKeyID: caKeyID, signer: signer}
}

// Sign builds the SSH certificate from the request and signs it.
func (s *FileSigner) Sign(_ context.Context, req CertRequest) (*ssh.Certificate, error) {
	cert, err := buildCert(req)
	if err != nil {
		return nil, err
	}
	if err := cert.SignCert(rand.Reader, s.signer); err != nil {
		return nil, fmt.Errorf("ca: signieren: %w", err)
	}
	return cert, nil
}

// CAKeyID is the database ID of the adopted CA key.
func (s *FileSigner) CAKeyID() uuid.UUID { return s.caKeyID }

// PublicKey is the public key of the CA key.
func (s *FileSigner) PublicKey() ssh.PublicKey { return s.signer.PublicKey() }
