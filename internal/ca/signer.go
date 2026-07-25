// Package ca implementiert die Zertifizierungsstelle: Signer-Interface,
// Software-Signer (Ed25519, Private Key AES-GCM-verschlüsselt at rest),
// Policy-Engine, Ausstellung mit transaktionalem Audit sowie Key-Rotation
// mit CA-Bundle (Phase 2 des Projektplans).
package ca

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/guided-traffic/guided-ssh/internal/store"
)

// CertRequest beschreibt ein zu signierendes SSH-Zertifikat.
type CertRequest struct {
	CertType        string // store.CertTypeUser oder store.CertTypeHost
	PublicKey       ssh.PublicKey
	KeyID           string
	Principals      []string
	ValidAfter      time.Time
	ValidBefore     time.Time
	Extensions      map[string]string
	CriticalOptions map[string]string
	Serial          uint64
}

// Signer signiert Zertifikats-Requests mit einem CA-Key. Implementierungen:
// SoftwareSigner und FileSigner (Phase 2); KMS/HSM-Signer folgen in Phase 10
// über dasselbe Interface.
type Signer interface {
	// Sign baut aus dem Request ein SSH-Zertifikat und signiert es.
	Sign(ctx context.Context, req CertRequest) (*ssh.Certificate, error)
	// CAKeyID ist die Datenbank-ID des verwendeten CA-Keys.
	CAKeyID() uuid.UUID
	// PublicKey ist der öffentliche Schlüssel des CA-Keys.
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
		return nil, fmt.Errorf("ca: unbekannter zertifikatstyp %q", req.CertType)
	}
	if req.PublicKey == nil {
		return nil, fmt.Errorf("ca: request ohne public key")
	}
	return &ssh.Certificate{
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
	}, nil
}
