package ca

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/guided-traffic/guided-ssh/internal/metrics"
	"github.com/guided-traffic/guided-ssh/internal/store"
)

// Audit-Event-Typen der CA.
const (
	EventCertIssued = "ca.cert_issued"
	EventKeyCreated = "ca.key_created"
	EventKeyRotated = "ca.key_rotated"
	EventKeyRetired = "ca.key_retired"
	EventKeyAdopted = "ca.key_adopted"
)

// Store ist die von der CA benötigte Persistenz-Schnittstelle
// (*store.Store erfüllt sie; Tests nutzen einen Fake).
type Store interface {
	NextCertificateSerial(ctx context.Context) (int64, error)
	CreateCertificateWithAudit(ctx context.Context, c *store.Certificate, e *store.AuditEvent) error
	CreateCAKey(ctx context.Context, k *store.CAKey) error
	ListActiveCAKeys(ctx context.Context, purpose string) ([]store.CAKey, error)
	UpdateCAKeyState(ctx context.Context, id uuid.UUID, state string) (*store.CAKey, error)
	AdoptCAKey(ctx context.Context, purpose, algorithm, publicKey string) (*store.CAKey, bool, error)
	AppendAuditEvent(ctx context.Context, e *store.AuditEvent) error
}

// IssueRef verknüpft eine Ausstellung mit ihrem Kontext: wer hat angefordert
// (Audit-Actor), welche Entität (User/Service-Account/Host) und beliebige
// Zusatzinfos (SSO-Session, Pipeline-Claims) für issuer_context und Audit-Payload.
type IssueRef struct {
	Actor            string
	UserID           *uuid.UUID
	ServiceAccountID *uuid.UUID
	HostID           *uuid.UUID
	Context          map[string]any
}

// CA orchestriert Policy-Prüfung, Signatur und transaktionale Persistenz.
// Pro Zweck (user/host) wird der Signer des neuesten aktiven CA-Keys gecacht;
// getrennte Keys für Benutzer- und Host-Zertifikate sind damit strukturell
// erzwungen.
type CA struct {
	store     Store
	masterKey []byte
	policies  *PolicyEngine

	// external ist im Self-Managed-Modus gesetzt (unveränderlich nach New) und
	// ersetzt jede Key-Erzeugung durch das gemountete Dateimaterial.
	external *ExternalKeys

	mu      sync.Mutex
	signers map[string]Signer // Zweck → Signer des neuesten aktiven Keys
}

// Option configures a CA at construction time.
type Option func(*CA)

// WithExternalKeys puts the CA into self-managed mode: all CA key material
// comes from the mounted files instead of the database, so no key is ever
// generated or decrypted in-process. Call AdoptExternalKeys once at startup to
// register the keys in the database and build the signers.
func WithExternalKeys(keys *ExternalKeys) Option {
	return func(c *CA) { c.external = keys }
}

// New baut eine CA. Der Master-Key muss MasterKeySize Bytes lang sein.
// Options select the key source; without any option the CA runs in managed
// mode and keeps its keys encrypted in the database.
func New(st Store, masterKey []byte, policies *PolicyEngine, opts ...Option) (*CA, error) {
	if len(masterKey) != MasterKeySize {
		return nil, fmt.Errorf("%w: %d Bytes statt %d", ErrInvalidMasterKey, len(masterKey), MasterKeySize)
	}
	c := &CA{
		store:     st,
		masterKey: masterKey,
		policies:  policies,
		signers:   make(map[string]Signer),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c, nil
}

// selfManaged reports whether the CA key material comes from mounted files.
func (ca *CA) selfManaged() bool { return ca.external != nil }

// SelfManaged reports whether the CA runs on mounted key files instead of
// database-managed keys. Callers use it to skip the managed-mode bootstrap
// paths (EnsureCAKeys, EnsureMTLSCA), which refuse to run in this mode.
func (ca *CA) SelfManaged() bool { return ca.selfManaged() }

// AdoptExternalKeys registers the mounted CA key material in the database and
// builds the signers; it is the self-managed replacement for EnsureCAKeys and
// EnsureMTLSCA and must be called once at startup (SELF_MANAGED_CA.md, D4).
//
// Per purpose the ca_keys row matching the mounted public key is selected or
// inserted without private key material; inserting demotes a previously active
// key of that purpose to "retiring" so its public key stays in the bundle
// during a file-based rotation. The first adoption of a key is audited as
// EventKeyAdopted.
func (ca *CA) AdoptExternalKeys(ctx context.Context) error {
	if !ca.selfManaged() {
		return fmt.Errorf("ca: AdoptExternalKeys requires self-managed mode (see WithExternalKeys)")
	}
	// The algorithm comes from the loaded material, never from an assumption:
	// a mounted ssh-rsa CA must not be recorded as ed25519.
	adoptions := []struct {
		purpose   string
		algorithm string
		publicKey string
		signer    ssh.Signer // nil for the mTLS CA: it is not an SSH signer
	}{
		{store.CertTypeUser, ca.external.User.Algorithm, ca.external.User.PublicKey, ca.external.User.Signer},
		{store.CertTypeHost, ca.external.Host.Algorithm, ca.external.Host.PublicKey, ca.external.Host.Signer},
		{store.CAPurposeMTLS, ca.external.MTLS.Algorithm, ca.external.MTLS.CertPEM, nil},
	}
	for _, a := range adoptions {
		key, created, err := ca.store.AdoptCAKey(ctx, a.purpose, a.algorithm, a.publicKey)
		if err != nil {
			if errors.Is(err, store.ErrCAKeyRetired) {
				return fmt.Errorf(
					"ca: the mounted %s ca key was retired and must not be used again — mount the current key or un-retire its ca_keys row: %w",
					a.purpose, err)
			}
			return fmt.Errorf("ca: adopt %s ca key: %w", a.purpose, err)
		}
		if a.signer != nil {
			ca.mu.Lock()
			ca.signers[a.purpose] = NewFileSigner(key.ID, a.signer)
			ca.mu.Unlock()
		}
		if !created {
			continue
		}
		payload, err := json.Marshal(map[string]any{
			"ca_key_id":  key.ID,
			"purpose":    a.purpose,
			"public_key": key.PublicKey,
		})
		if err != nil {
			return err
		}
		if err := ca.store.AppendAuditEvent(ctx, &store.AuditEvent{EventType: EventKeyAdopted, Payload: payload}); err != nil {
			return err
		}
	}
	return nil
}

// EnsureCAKeys legt für jeden Zweck (user, host) einen aktiven CA-Key an,
// falls noch keiner existiert (Bootstrap beim ersten Start).
// In self-managed mode this bootstrap is refused; use AdoptExternalKeys.
func (ca *CA) EnsureCAKeys(ctx context.Context) error {
	if ca.selfManaged() {
		return fmt.Errorf("%w: call AdoptExternalKeys instead of EnsureCAKeys", ErrSelfManaged)
	}
	for _, purpose := range []string{store.CertTypeUser, store.CertTypeHost} {
		keys, err := ca.store.ListActiveCAKeys(ctx, purpose)
		if err != nil {
			return err
		}
		if len(keys) > 0 {
			continue
		}
		if _, err := ca.createKey(ctx, purpose, EventKeyCreated); err != nil {
			return err
		}
	}
	return nil
}

// Issue prüft den Request gegen die Policy des Requester-Typs, signiert mit dem
// aktiven CA-Key des passenden Zwecks und persistiert Zertifikats-Metadaten und
// Audit-Event in einer Transaktion. Serial wird von der CA vergeben.
func (ca *CA) Issue(ctx context.Context, requesterType string, req CertRequest, ref IssueRef) (*ssh.Certificate, *store.Certificate, error) {
	if err := ca.policies.Validate(requesterType, req); err != nil {
		return nil, nil, err
	}
	signer, err := ca.activeSigner(ctx, req.CertType)
	if err != nil {
		return nil, nil, err
	}
	serial, err := ca.store.NextCertificateSerial(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("ca: serial vergeben: %w", err)
	}
	req.Serial = uint64(serial) //nolint:gosec // Sequence beginnt bei 1, nie negativ

	cert, err := signer.Sign(ctx, req)
	if err != nil {
		return nil, nil, err
	}

	issuerContext, err := json.Marshal(ref.Context)
	if err != nil {
		return nil, nil, fmt.Errorf("ca: issuer-kontext serialisieren: %w", err)
	}
	record := &store.Certificate{
		Serial:           serial,
		KeyID:            req.KeyID,
		CertType:         req.CertType,
		PublicKey:        strings.TrimSpace(string(ssh.MarshalAuthorizedKey(req.PublicKey))),
		Principals:       req.Principals,
		ValidAfter:       req.ValidAfter,
		ValidBefore:      req.ValidBefore,
		CAKeyID:          signer.CAKeyID(),
		UserID:           ref.UserID,
		ServiceAccountID: ref.ServiceAccountID,
		HostID:           ref.HostID,
		IssuerContext:    issuerContext,
	}
	payload, err := json.Marshal(map[string]any{
		"serial":         serial,
		"key_id":         req.KeyID,
		"cert_type":      req.CertType,
		"requester_type": requesterType,
		"principals":     req.Principals,
		"valid_after":    req.ValidAfter,
		"valid_before":   req.ValidBefore,
		"ca_key_id":      signer.CAKeyID(),
		"context":        ref.Context,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("ca: audit-payload serialisieren: %w", err)
	}
	event := &store.AuditEvent{EventType: EventCertIssued, Actor: ref.Actor, Payload: payload}
	if err := ca.store.CreateCertificateWithAudit(ctx, record, event); err != nil {
		return nil, nil, err
	}
	metrics.CertificatesIssued.WithLabelValues(requesterType, req.CertType).Inc()
	return cert, record, nil
}

// Rotate legt einen neuen aktiven CA-Key für den Zweck an und setzt bisherige
// aktive Keys auf "retiring" (Übergangsfenster: sie bleiben im Bundle, bis sie
// via RetireKey ausgemustert werden).
// In self-managed mode rotation is refused: it happens by committing a new key
// file to the SOPS-encrypted secret (SELF_MANAGED_CA.md, D6).
func (ca *CA) Rotate(ctx context.Context, purpose string) (*store.CAKey, error) {
	if ca.selfManaged() {
		return nil, fmt.Errorf(
			"%w: rotate the %q ca key by committing a new key file and restarting", ErrSelfManaged, purpose)
	}
	previous, err := ca.store.ListActiveCAKeys(ctx, purpose)
	if err != nil {
		return nil, err
	}
	newKey, err := ca.createKey(ctx, purpose, EventKeyRotated)
	if err != nil {
		return nil, err
	}
	for i := range previous {
		if previous[i].State != store.CAKeyStateActive {
			continue
		}
		if _, err := ca.store.UpdateCAKeyState(ctx, previous[i].ID, store.CAKeyStateRetiring); err != nil {
			return nil, fmt.Errorf("ca: key %s auf retiring setzen: %w", previous[i].ID, err)
		}
	}
	ca.invalidateSigner(purpose)
	return newKey, nil
}

// RetireKey mustert einen CA-Key endgültig aus (fliegt aus dem Bundle) und
// schreibt ein Audit-Event.
func (ca *CA) RetireKey(ctx context.Context, id uuid.UUID) error {
	key, err := ca.store.UpdateCAKeyState(ctx, id, store.CAKeyStateRetired)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(map[string]any{"ca_key_id": key.ID, "purpose": key.Purpose})
	if err != nil {
		return err
	}
	if err := ca.store.AppendAuditEvent(ctx, &store.AuditEvent{EventType: EventKeyRetired, Payload: payload}); err != nil {
		return err
	}
	ca.invalidateSigner(key.Purpose)
	return nil
}

// Bundle liefert die Public Keys aller nicht ausgemusterten CA-Keys eines
// Zwecks im authorized_keys-Format — der Inhalt für TrustedUserCAKeys auf
// Hosts (Zweck user) bzw. @cert-authority für Clients (Zweck host).
func (ca *CA) Bundle(ctx context.Context, purpose string) (string, error) {
	if purpose != store.CertTypeUser && purpose != store.CertTypeHost {
		return "", fmt.Errorf("ca: unbekannter key-zweck %q", purpose)
	}
	keys, err := ca.store.ListActiveCAKeys(ctx, purpose)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for i := range keys {
		b.WriteString(strings.TrimSpace(keys[i].PublicKey))
		b.WriteString("\n")
	}
	return b.String(), nil
}

// createKey erzeugt und persistiert einen neuen aktiven CA-Key inkl. Audit-Event.
// In self-managed mode no key material may be generated in-process.
func (ca *CA) createKey(ctx context.Context, purpose, eventType string) (*store.CAKey, error) {
	if ca.selfManaged() {
		return nil, fmt.Errorf("%w: cannot create a %q ca key", ErrSelfManaged, purpose)
	}
	key, err := NewCAKey(purpose, ca.masterKey)
	if err != nil {
		return nil, err
	}
	if err := ca.store.CreateCAKey(ctx, key); err != nil {
		return nil, fmt.Errorf("ca: key persistieren: %w", err)
	}
	payload, err := json.Marshal(map[string]any{
		"ca_key_id":  key.ID,
		"purpose":    purpose,
		"public_key": key.PublicKey,
	})
	if err != nil {
		return nil, err
	}
	if err := ca.store.AppendAuditEvent(ctx, &store.AuditEvent{EventType: eventType, Payload: payload}); err != nil {
		return nil, err
	}
	ca.invalidateSigner(purpose)
	return key, nil
}

// activeSigner liefert den (gecachten) Signer des neuesten aktiven CA-Keys
// für den Zweck.
// In self-managed mode only the signer adopted from the mounted key file is
// used: the adopted row may sit in state "retiring" after a rotation, so
// selecting by state would pick the wrong key — and the database holds no
// private key to fall back to.
func (ca *CA) activeSigner(ctx context.Context, purpose string) (Signer, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if s, ok := ca.signers[purpose]; ok {
		return s, nil
	}
	if ca.selfManaged() {
		return nil, fmt.Errorf("ca: no external ca key adopted for purpose %q (AdoptExternalKeys not called?)", purpose)
	}
	keys, err := ca.store.ListActiveCAKeys(ctx, purpose)
	if err != nil {
		return nil, err
	}
	for i := range keys {
		if keys[i].State == store.CAKeyStateActive {
			signer, err := NewSoftwareSigner(&keys[i], ca.masterKey)
			if err != nil {
				return nil, err
			}
			ca.signers[purpose] = signer
			return signer, nil
		}
	}
	return nil, fmt.Errorf("ca: kein aktiver ca-key für zweck %q", purpose)
}

// invalidateSigner wirft den gecachten Signer eines Zwecks weg (nach Rotation).
// In self-managed mode this is a no-op: the cached signers are built from the
// mounted key files by AdoptExternalKeys and are the source of truth there, so
// no ca_keys state change can invalidate them — and the database holds no
// private key to rebuild them from. Dropping one (RetireKey on the D6 rotation
// path) would leave the purpose unsignable until the process restarts.
func (ca *CA) invalidateSigner(purpose string) {
	if ca.selfManaged() {
		return
	}
	ca.mu.Lock()
	defer ca.mu.Unlock()
	delete(ca.signers, purpose)
}
