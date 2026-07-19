package ca

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/guided-traffic/guided-ssh/internal/store"
)

// fakeStore implementiert das Store-Interface in-memory; Zertifikat und
// Audit-Event landen wie in der echten Transaktion nur gemeinsam.
type fakeStore struct {
	serial int64
	keys   []store.CAKey
	certs  []store.Certificate
	events []store.AuditEvent

	failCreateWithAudit error
}

func (f *fakeStore) NextCertificateSerial(context.Context) (int64, error) {
	f.serial++
	return f.serial, nil
}

func (f *fakeStore) CreateCertificateWithAudit(_ context.Context, c *store.Certificate, e *store.AuditEvent) error {
	if f.failCreateWithAudit != nil {
		return f.failCreateWithAudit
	}
	c.ID = uuid.New()
	c.CreatedAt = time.Now()
	f.certs = append(f.certs, *c)
	e.ID = int64(len(f.events) + 1)
	e.OccurredAt = time.Now()
	f.events = append(f.events, *e)
	return nil
}

func (f *fakeStore) CreateCAKey(_ context.Context, k *store.CAKey) error {
	k.ID = uuid.New()
	k.CreatedAt = time.Now()
	f.keys = append(f.keys, *k)
	return nil
}

func (f *fakeStore) ListActiveCAKeys(_ context.Context, purpose string) ([]store.CAKey, error) {
	var out []store.CAKey
	// Neueste zuerst, wie die SQL-Implementierung.
	for i := len(f.keys) - 1; i >= 0; i-- {
		k := f.keys[i]
		if k.Purpose == purpose && k.State != store.CAKeyStateRetired {
			out = append(out, k)
		}
	}
	return out, nil
}

func (f *fakeStore) UpdateCAKeyState(_ context.Context, id uuid.UUID, state string) (*store.CAKey, error) {
	for i := range f.keys {
		if f.keys[i].ID == id {
			f.keys[i].State = state
			k := f.keys[i]
			return &k, nil
		}
	}
	return nil, store.ErrNotFound
}

func (f *fakeStore) AppendAuditEvent(_ context.Context, e *store.AuditEvent) error {
	e.ID = int64(len(f.events) + 1)
	e.OccurredAt = time.Now()
	f.events = append(f.events, *e)
	return nil
}

func (f *fakeStore) eventTypes() []string {
	types := make([]string, len(f.events))
	for i := range f.events {
		types[i] = f.events[i].EventType
	}
	return types
}

func newTestCA(t *testing.T) (*CA, *fakeStore) {
	t.Helper()
	fs := &fakeStore{}
	c, err := New(fs, testMasterKey(), NewPolicyEngine(DefaultPolicies()))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c, fs
}

func userRequest(t *testing.T) CertRequest {
	t.Helper()
	now := time.Now()
	return CertRequest{
		CertType:    store.CertTypeUser,
		PublicKey:   testPublicKey(t),
		KeyID:       UserKeyID("sub-1", "https://idp.example"),
		Principals:  []string{"alice"},
		ValidAfter:  now,
		ValidBefore: now.Add(16 * time.Hour),
		Extensions:  map[string]string{"permit-pty": ""},
	}
}

func TestNewFalscherMasterKey(t *testing.T) {
	if _, err := New(&fakeStore{}, []byte("kurz"), NewPolicyEngine(DefaultPolicies())); !errors.Is(err, ErrInvalidMasterKey) {
		t.Fatalf("ErrInvalidMasterKey erwartet, bekommen: %v", err)
	}
}

func TestEnsureCAKeys(t *testing.T) {
	c, fs := newTestCA(t)
	ctx := context.Background()

	if err := c.EnsureCAKeys(ctx); err != nil {
		t.Fatalf("EnsureCAKeys: %v", err)
	}
	if len(fs.keys) != 2 {
		t.Fatalf("2 CA-Keys erwartet (user, host), bekommen: %d", len(fs.keys))
	}
	if fs.keys[0].Purpose == fs.keys[1].Purpose {
		t.Fatal("getrennte Keys für user und host erwartet")
	}
	// Idempotent: zweiter Lauf legt nichts Neues an.
	if err := c.EnsureCAKeys(ctx); err != nil {
		t.Fatalf("EnsureCAKeys (2. Lauf): %v", err)
	}
	if len(fs.keys) != 2 {
		t.Fatalf("EnsureCAKeys nicht idempotent: %d Keys", len(fs.keys))
	}
	for _, et := range fs.eventTypes() {
		if et != EventKeyCreated {
			t.Fatalf("unerwartetes Event %q", et)
		}
	}
}

func TestIssueUserZertifikat(t *testing.T) {
	c, fs := newTestCA(t)
	ctx := context.Background()
	if err := c.EnsureCAKeys(ctx); err != nil {
		t.Fatalf("EnsureCAKeys: %v", err)
	}

	userID := uuid.New()
	req := userRequest(t)
	cert, record, err := c.Issue(ctx, RequesterUser, req, IssueRef{
		Actor:   "user:sub-1@https://idp.example",
		UserID:  &userID,
		Context: map[string]any{"session": "sso-abc"},
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	if cert.Serial == 0 || int64(cert.Serial) != record.Serial { //nolint:gosec // Test-Serial klein
		t.Fatalf("Serial passt nicht zusammen: cert=%d record=%d", cert.Serial, record.Serial)
	}
	if record.KeyID != req.KeyID || record.CertType != store.CertTypeUser {
		t.Fatalf("Record-Felder: %+v", record)
	}
	if record.UserID == nil || *record.UserID != userID {
		t.Fatal("UserID nicht übernommen")
	}
	if !strings.Contains(string(record.IssuerContext), "sso-abc") {
		t.Fatalf("IssuerContext: %s", record.IssuerContext)
	}
	if len(fs.certs) != 1 || len(fs.events) != 3 { // 2× key_created + 1× cert_issued
		t.Fatalf("Persistenz: %d Zertifikate, %d Events", len(fs.certs), len(fs.events))
	}
	last := fs.events[len(fs.events)-1]
	if last.EventType != EventCertIssued || last.Actor != "user:sub-1@https://idp.example" {
		t.Fatalf("Audit-Event: %+v", last)
	}

	// Signiert vom user-CA-Key, nicht vom host-Key.
	var userCAKey store.CAKey
	for _, k := range fs.keys {
		if k.Purpose == store.CertTypeUser {
			userCAKey = k
		}
	}
	if record.CAKeyID != userCAKey.ID {
		t.Fatal("Zertifikat nicht dem user-CA-Key zugeordnet")
	}
	caPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(userCAKey.PublicKey))
	if err != nil {
		t.Fatalf("CA-Public-Key parsen: %v", err)
	}
	if !bytes.Equal(cert.SignatureKey.Marshal(), caPub.Marshal()) {
		t.Fatal("Zertifikat nicht vom user-CA-Key signiert")
	}
}

func TestIssuePolicyVerstoss(t *testing.T) {
	c, fs := newTestCA(t)
	ctx := context.Background()
	if err := c.EnsureCAKeys(ctx); err != nil {
		t.Fatalf("EnsureCAKeys: %v", err)
	}

	req := userRequest(t)
	req.ValidBefore = req.ValidAfter.Add(48 * time.Hour)
	_, _, err := c.Issue(ctx, RequesterUser, req, IssueRef{Actor: "test"})
	var pv *PolicyViolationError
	if !errors.As(err, &pv) {
		t.Fatalf("PolicyViolationError erwartet, bekommen: %v", err)
	}
	if len(fs.certs) != 0 {
		t.Fatal("bei Policy-Verstoß darf kein Zertifikat persistiert werden")
	}
}

func TestIssueOhneAktivenKey(t *testing.T) {
	c, _ := newTestCA(t)
	if _, _, err := c.Issue(context.Background(), RequesterUser, userRequest(t), IssueRef{}); err == nil {
		t.Fatal("Fehler erwartet (kein aktiver CA-Key)")
	}
}

func TestIssuePersistenzFehlerPropagiert(t *testing.T) {
	c, fs := newTestCA(t)
	ctx := context.Background()
	if err := c.EnsureCAKeys(ctx); err != nil {
		t.Fatalf("EnsureCAKeys: %v", err)
	}
	fs.failCreateWithAudit = errors.New("db kaputt")
	if _, _, err := c.Issue(ctx, RequesterUser, userRequest(t), IssueRef{}); err == nil {
		t.Fatal("Persistenzfehler muss propagieren")
	}
}

func TestRotateUndBundle(t *testing.T) {
	c, fs := newTestCA(t)
	ctx := context.Background()
	if err := c.EnsureCAKeys(ctx); err != nil {
		t.Fatalf("EnsureCAKeys: %v", err)
	}
	oldKeyID := fs.keys[0].ID // user-Key aus EnsureCAKeys

	newKey, err := c.Rotate(ctx, store.CertTypeUser)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if newKey.State != store.CAKeyStateActive {
		t.Fatalf("neuer Key nicht aktiv: %s", newKey.State)
	}
	if state := fs.keys[0].State; state != store.CAKeyStateRetiring {
		t.Fatalf("alter Key nicht retiring: %s", state)
	}

	// Übergangsfenster: Bundle enthält alten und neuen Key.
	bundle, err := c.Bundle(ctx, store.CertTypeUser)
	if err != nil {
		t.Fatalf("Bundle: %v", err)
	}
	if lines := strings.Split(strings.TrimSpace(bundle), "\n"); len(lines) != 2 {
		t.Fatalf("Bundle mit 2 Keys erwartet, bekommen %d:\n%s", len(lines), bundle)
	}
	if !strings.Contains(bundle, newKey.PublicKey) {
		t.Fatal("neuer Key fehlt im Bundle")
	}

	// Neue Zertifikate müssen vom neuen Key kommen.
	_, record, err := c.Issue(ctx, RequesterUser, userRequest(t), IssueRef{Actor: "test"})
	if err != nil {
		t.Fatalf("Issue nach Rotation: %v", err)
	}
	if record.CAKeyID != newKey.ID {
		t.Fatal("Zertifikat nach Rotation nicht vom neuen Key signiert")
	}

	// Ausmustern: alter Key fliegt aus dem Bundle.
	if err := c.RetireKey(ctx, oldKeyID); err != nil {
		t.Fatalf("RetireKey: %v", err)
	}
	bundle, err = c.Bundle(ctx, store.CertTypeUser)
	if err != nil {
		t.Fatalf("Bundle: %v", err)
	}
	if lines := strings.Split(strings.TrimSpace(bundle), "\n"); len(lines) != 1 {
		t.Fatalf("Bundle mit 1 Key erwartet:\n%s", bundle)
	}

	types := fs.eventTypes()
	if !slices.Contains(types, EventKeyRotated) || !slices.Contains(types, EventKeyRetired) {
		t.Fatalf("Rotations-/Retire-Events fehlen: %v", types)
	}
}

func TestBundleUnbekannterZweck(t *testing.T) {
	c, _ := newTestCA(t)
	if _, err := c.Bundle(context.Background(), "robot"); err == nil {
		t.Fatal("Fehler erwartet")
	}
}

func TestRetireKeyNichtGefunden(t *testing.T) {
	c, _ := newTestCA(t)
	if err := c.RetireKey(context.Background(), uuid.New()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("ErrNotFound erwartet, bekommen: %v", err)
	}
}
