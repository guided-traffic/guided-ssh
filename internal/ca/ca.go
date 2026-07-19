package ca

import (
	"context"
	"encoding/json"
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
)

// Store ist die von der CA benötigte Persistenz-Schnittstelle
// (*store.Store erfüllt sie; Tests nutzen einen Fake).
type Store interface {
	NextCertificateSerial(ctx context.Context) (int64, error)
	CreateCertificateWithAudit(ctx context.Context, c *store.Certificate, e *store.AuditEvent) error
	CreateCAKey(ctx context.Context, k *store.CAKey) error
	ListActiveCAKeys(ctx context.Context, purpose string) ([]store.CAKey, error)
	UpdateCAKeyState(ctx context.Context, id uuid.UUID, state string) (*store.CAKey, error)
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

	mu      sync.Mutex
	signers map[string]Signer // Zweck → Signer des neuesten aktiven Keys
}

// New baut eine CA. Der Master-Key muss MasterKeySize Bytes lang sein.
func New(st Store, masterKey []byte, policies *PolicyEngine) (*CA, error) {
	if len(masterKey) != MasterKeySize {
		return nil, fmt.Errorf("%w: %d Bytes statt %d", ErrInvalidMasterKey, len(masterKey), MasterKeySize)
	}
	return &CA{
		store:     st,
		masterKey: masterKey,
		policies:  policies,
		signers:   make(map[string]Signer),
	}, nil
}

// EnsureCAKeys legt für jeden Zweck (user, host) einen aktiven CA-Key an,
// falls noch keiner existiert (Bootstrap beim ersten Start).
func (ca *CA) EnsureCAKeys(ctx context.Context) error {
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
func (ca *CA) Rotate(ctx context.Context, purpose string) (*store.CAKey, error) {
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
func (ca *CA) createKey(ctx context.Context, purpose, eventType string) (*store.CAKey, error) {
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
func (ca *CA) activeSigner(ctx context.Context, purpose string) (Signer, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if s, ok := ca.signers[purpose]; ok {
		return s, nil
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
func (ca *CA) invalidateSigner(purpose string) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	delete(ca.signers, purpose)
}
