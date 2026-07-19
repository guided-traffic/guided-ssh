// Package ca implementiert die Zertifizierungsstelle: Signer-Interface,
// Software-Signer (Ed25519, Private Key AES-GCM-verschlüsselt at rest),
// Policy-Engine, Ausstellung mit transaktionalem Audit sowie Key-Rotation
// mit CA-Bundle (Phase 2 des Projektplans).
package ca

import (
	"context"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
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
// SoftwareSigner (Phase 2); KMS/HSM-Signer folgen in Phase 10 über dasselbe
// Interface.
type Signer interface {
	// Sign baut aus dem Request ein SSH-Zertifikat und signiert es.
	Sign(ctx context.Context, req CertRequest) (*ssh.Certificate, error)
	// CAKeyID ist die Datenbank-ID des verwendeten CA-Keys.
	CAKeyID() uuid.UUID
	// PublicKey ist der öffentliche Schlüssel des CA-Keys.
	PublicKey() ssh.PublicKey
}
