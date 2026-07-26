// Package ca implements the certification authority: the signer interface,
// the software signer (Ed25519, private key AES-GCM encrypted at rest),
// the policy engine, issuance with transactional audit, and key rotation
// with a CA bundle (Phase 2 of the project plan).
package ca

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/guided-traffic/guided-ssh/internal/store"
)

// CertRequest describes an SSH certificate to be signed.
type CertRequest struct {
	CertType        string // store.CertTypeUser or store.CertTypeHost
	PublicKey       ssh.PublicKey
	KeyID           string
	Principals      []string
	ValidAfter      time.Time
	ValidBefore     time.Time
	Extensions      map[string]string
	CriticalOptions map[string]string
	Serial          uint64
}

// Signer signs certificate requests with a CA key. Implementations:
// SoftwareSigner and FileSigner (Phase 2); KMS/HSM signers follow in Phase 10
// over the same interface.
type Signer interface {
	// Sign builds an SSH certificate from the request and signs it.
	Sign(ctx context.Context, req CertRequest) (*ssh.Certificate, error)
	// CAKeyID is the database ID of the CA key used.
	CAKeyID() uuid.UUID
	// PublicKey is the public key of the CA key.
	PublicKey() ssh.PublicKey
}

// buildCert turns a request into an unsigned SSH certificate. Shared by every
// Signer implementation so that the certificate contents do not depend on
// where the CA key material lives.
func buildCert(req CertRequest) (*ssh.Certificate, error) {
	var certType uint32
	switch req.CertType {
	case store.CertTypeUser:
		certType = ssh.UserCert
	case store.CertTypeHost:
		certType = ssh.HostCert
	default:
		return nil, fmt.Errorf("ca: unknown certificate type %q", req.CertType)
	}
	if req.PublicKey == nil {
		return nil, fmt.Errorf("ca: request without public key")
	}
	return &ssh.Certificate{
		Key:             req.PublicKey,
		Serial:          req.Serial,
		CertType:        certType,
		KeyId:           req.KeyID,
		ValidPrincipals: req.Principals,
		ValidAfter:      uint64(req.ValidAfter.Unix()),  //nolint:gosec // unix time after 1970, never negative
		ValidBefore:     uint64(req.ValidBefore.Unix()), //nolint:gosec // ditto
		Permissions: ssh.Permissions{
			CriticalOptions: req.CriticalOptions,
			Extensions:      req.Extensions,
		},
	}, nil
}
