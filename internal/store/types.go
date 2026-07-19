package store

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// User ist ein aus dem IdP synchronisierter Benutzer.
type User struct {
	ID        uuid.UUID `db:"id"`
	Issuer    string    `db:"issuer"`
	Subject   string    `db:"subject"`
	Username  string    `db:"username"`
	Email     string    `db:"email"`
	UID       *int32    `db:"uid"`
	GID       *int32    `db:"gid"`
	Active    bool      `db:"active"`
	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`
}

// Group ist eine IdP-Gruppe.
type Group struct {
	ID         uuid.UUID `db:"id"`
	Issuer     string    `db:"issuer"`
	Name       string    `db:"name"`
	ExternalID *string   `db:"external_id"`
	CreatedAt  time.Time `db:"created_at"`
}

// Host ist ein verwalteter SSH-Host.
type Host struct {
	ID         uuid.UUID  `db:"id"`
	Name       string     `db:"name"`
	PublicKey  *string    `db:"public_key"`
	EnrolledAt *time.Time `db:"enrolled_at"`
	LastSeenAt *time.Time `db:"last_seen_at"`
	CreatedAt  time.Time  `db:"created_at"`
	UpdatedAt  time.Time  `db:"updated_at"`
}

// AccessGrant verknüpft eine IdP-Gruppe über einen Tag-Selektor mit
// Ziel-Principals, sudo-Flag und maximaler Zertifikatslaufzeit.
type AccessGrant struct {
	ID                 uuid.UUID         `db:"id"`
	GroupID            uuid.UUID         `db:"group_id"`
	TagSelector        map[string]string `db:"tag_selector"`
	Principals         []string          `db:"principals"`
	Sudo               bool              `db:"sudo"`
	MaxValiditySeconds int64             `db:"max_validity_seconds"`
	CreatedAt          time.Time         `db:"created_at"`
	UpdatedAt          time.Time         `db:"updated_at"`
}

// MaxValidity ist die maximale Zertifikatslaufzeit als Duration.
func (g *AccessGrant) MaxValidity() time.Duration {
	return time.Duration(g.MaxValiditySeconds) * time.Second
}

// Zustände eines CA-Keys.
const (
	CAKeyStateActive   = "active"
	CAKeyStateRetiring = "retiring"
	CAKeyStateRetired  = "retired"
)

// Zertifikatstypen bzw. CA-Key-Zwecke.
const (
	CertTypeUser = "user"
	CertTypeHost = "host"
	// CAPurposeMTLS ist die X.509-CA für mTLS-Client-Zertifikate der
	// Host-Agenten (Phase 5); kein SSH-Zertifikatstyp.
	CAPurposeMTLS = "mtls"
)

// CAKey ist ein Signierschlüssel der CA.
type CAKey struct {
	ID                  uuid.UUID  `db:"id"`
	Purpose             string     `db:"purpose"`
	Algorithm           string     `db:"algorithm"`
	PublicKey           string     `db:"public_key"`
	EncryptedPrivateKey []byte     `db:"encrypted_private_key"`
	State               string     `db:"state"`
	CreatedAt           time.Time  `db:"created_at"`
	RetiredAt           *time.Time `db:"retired_at"`
}

// ServiceAccount ist eine maschinelle Identität (z. B. GitLab-CI-Projekt).
type ServiceAccount struct {
	ID           uuid.UUID         `db:"id"`
	Name         string            `db:"name"`
	Kind         string            `db:"kind"`
	Issuer       string            `db:"issuer"`
	ClaimMatcher map[string]string `db:"claim_matcher"`
	Active       bool              `db:"active"`
	CreatedAt    time.Time         `db:"created_at"`
	UpdatedAt    time.Time         `db:"updated_at"`
}

// Certificate ist ein ausgestelltes SSH-Zertifikat (Metadaten, nie der Private Key).
type Certificate struct {
	ID               uuid.UUID       `db:"id"`
	Serial           int64           `db:"serial"`
	KeyID            string          `db:"key_id"`
	CertType         string          `db:"cert_type"`
	PublicKey        string          `db:"public_key"`
	Principals       []string        `db:"principals"`
	ValidAfter       time.Time       `db:"valid_after"`
	ValidBefore      time.Time       `db:"valid_before"`
	CAKeyID          uuid.UUID       `db:"ca_key_id"`
	UserID           *uuid.UUID      `db:"user_id"`
	ServiceAccountID *uuid.UUID      `db:"service_account_id"`
	HostID           *uuid.UUID      `db:"host_id"`
	IssuerContext    json.RawMessage `db:"issuer_context"`
	CreatedAt        time.Time       `db:"created_at"`
}

// AuditEvent ist ein Eintrag im Append-only-Audit-Log.
type AuditEvent struct {
	ID         int64           `db:"id"`
	OccurredAt time.Time       `db:"occurred_at"`
	EventType  string          `db:"event_type"`
	Actor      string          `db:"actor"`
	Payload    json.RawMessage `db:"payload"`
}
