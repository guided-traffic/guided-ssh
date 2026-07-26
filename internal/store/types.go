package store

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// User is a user synchronized from the IdP.
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

// Group is an IdP group.
type Group struct {
	ID         uuid.UUID `db:"id"`
	Issuer     string    `db:"issuer"`
	Name       string    `db:"name"`
	ExternalID *string   `db:"external_id"`
	CreatedAt  time.Time `db:"created_at"`
}

// Host is a managed SSH host.
type Host struct {
	ID         uuid.UUID  `db:"id"`
	Name       string     `db:"name"`
	PublicKey  *string    `db:"public_key"`
	EnrolledAt *time.Time `db:"enrolled_at"`
	LastSeenAt *time.Time `db:"last_seen_at"`
	CreatedAt  time.Time  `db:"created_at"`
	UpdatedAt  time.Time  `db:"updated_at"`
}

// AccessGrant links an IdP group, via a tag selector, to target principals,
// a sudo flag, and a maximum certificate validity.
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

// MaxValidity is the maximum certificate validity as a Duration.
func (g *AccessGrant) MaxValidity() time.Duration {
	return time.Duration(g.MaxValiditySeconds) * time.Second
}

// States of a CA key.
const (
	CAKeyStateActive   = "active"
	CAKeyStateRetiring = "retiring"
	CAKeyStateRetired  = "retired"
)

// Certificate types / CA key purposes.
const (
	CertTypeUser = "user"
	CertTypeHost = "host"
	// CAPurposeMTLS is the X.509 CA for mTLS client certificates of the
	// host agents (phase 5); not an SSH certificate type.
	CAPurposeMTLS = "mtls"
)

// CAKey is a signing key of the CA.
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

// ServiceAccount is a machine identity (e.g. a GitLab CI project).
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

// Certificate is an issued SSH certificate (metadata only, never the private key).
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

// HostSession is an SSH session observed on the host (phase 9). The host
// agent reports its start and end; cert_serial correlates it with the
// issued certificate (and thereby with user_id). ended_at NULL = active.
type HostSession struct {
	ID         uuid.UUID  `db:"id"`
	HostID     uuid.UUID  `db:"host_id"`
	LocalUser  string     `db:"local_user"`
	RemoteUser string     `db:"remote_user"`
	RemoteAddr string     `db:"remote_addr"`
	TTY        string     `db:"tty"`
	CertSerial *int64     `db:"cert_serial"`
	KeyID      string     `db:"key_id"`
	UserID     *uuid.UUID `db:"user_id"`
	StartedAt  time.Time  `db:"started_at"`
	EndedAt    *time.Time `db:"ended_at"`
	CreatedAt  time.Time  `db:"created_at"`
}

// AuditEvent is an entry in the append-only audit log.
type AuditEvent struct {
	ID         int64           `db:"id"`
	OccurredAt time.Time       `db:"occurred_at"`
	EventType  string          `db:"event_type"`
	Actor      string          `db:"actor"`
	Payload    json.RawMessage `db:"payload"`
}
