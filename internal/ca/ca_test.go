package ca

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

// AdoptCAKey bildet die Select-or-Insert-Semantik des echten Stores nach
// (siehe store.AdoptCAKey): vorhandene Zeile unverändert zurück, sonst neu
// anlegen und bisherige aktive Keys desselben Zwecks auf "retiring" setzen.
func (f *fakeStore) AdoptCAKey(_ context.Context, purpose, algorithm, publicKey string) (*store.CAKey, bool, error) {
	for i := range f.keys {
		if f.keys[i].Purpose != purpose || f.keys[i].PublicKey != publicKey {
			continue
		}
		if f.keys[i].State == store.CAKeyStateRetired {
			return nil, false, fmt.Errorf("%w: purpose %q", store.ErrCAKeyRetired, purpose)
		}
		k := f.keys[i]
		return &k, false, nil
	}
	for i := range f.keys {
		if f.keys[i].Purpose == purpose && f.keys[i].State == store.CAKeyStateActive {
			f.keys[i].State = store.CAKeyStateRetiring
		}
	}
	k := store.CAKey{
		ID:        uuid.New(),
		Purpose:   purpose,
		Algorithm: algorithm,
		PublicKey: publicKey,
		State:     store.CAKeyStateActive,
		CreatedAt: time.Now(),
	}
	f.keys = append(f.keys, k)
	return &k, true, nil
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

// --- self-managed mode (SELF_MANAGED_CA.md) ---------------------------------
//
// The tests below always take the production path: fresh key files on disk,
// loaded through LoadExternalKeys, so an ExternalKeys value that the loader
// could never produce cannot slip through.

// mustLoadExternalKeys loads a mounted key set and fails the test if it does not
// load — the fixtures are generated, so this is a test bug, not a case under test.
func mustLoadExternalKeys(t *testing.T, paths ExternalKeyPaths) *ExternalKeys {
	t.Helper()
	keys, err := LoadExternalKeys(paths)
	if err != nil {
		t.Fatalf("LoadExternalKeys: %v", err)
	}
	return keys
}

// mountedKeys generates a complete set of CA key files in dir and loads it.
func mountedKeys(t *testing.T, dir string) *ExternalKeys {
	t.Helper()
	return mustLoadExternalKeys(t, newExternalKeyFixtures(t, dir))
}

// newSelfManagedCA builds a CA that runs on mounted key material.
func newSelfManagedCA(t *testing.T, st Store, keys *ExternalKeys) *CA {
	t.Helper()
	c, err := New(st, testMasterKey(), NewPolicyEngine(DefaultPolicies()), WithExternalKeys(keys))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !c.SelfManaged() {
		t.Fatal("WithExternalKeys did not put the CA into self-managed mode")
	}
	return c
}

// caKeyFor returns the fake store's ca_keys row of a purpose with the given
// public key; the zero value means "not adopted".
func caKeyFor(fs *fakeStore, purpose, publicKey string) store.CAKey {
	for _, k := range fs.keys {
		if k.Purpose == purpose && (publicKey == "" || k.PublicKey == publicKey) {
			return k
		}
	}
	return store.CAKey{}
}

// adoptedPurposes returns the purpose of every ca.key_adopted audit event, in
// order — the audit trail of first adoptions.
func adoptedPurposes(t *testing.T, fs *fakeStore) []string {
	t.Helper()
	var purposes []string
	for _, e := range fs.events {
		if e.EventType != EventKeyAdopted {
			continue
		}
		var payload struct {
			CAKeyID string `json:"ca_key_id"`
			Purpose string `json:"purpose"`
		}
		if err := json.Unmarshal(e.Payload, &payload); err != nil {
			t.Fatalf("ca.key_adopted payload: %v", err)
		}
		if payload.CAKeyID == "" {
			t.Errorf("ca.key_adopted event without ca_key_id: %s", e.Payload)
		}
		purposes = append(purposes, payload.Purpose)
	}
	slices.Sort(purposes)
	return purposes
}

// selfManagedUserRequest is a user request that verifies cleanly against a
// CertChecker (valid_after slightly in the past, within the allowed backdate).
func selfManagedUserRequest(t *testing.T) CertRequest {
	t.Helper()
	req := userRequest(t)
	req.ValidAfter = time.Now().Add(-time.Minute)
	req.ValidBefore = req.ValidAfter.Add(time.Hour)
	return req
}

// TestSelfManagedRefusesInAppKeyCreation: in self-managed mode the key files are
// the source of truth, so every path that would create key material fails with
// ErrSelfManaged — and managed mode keeps working exactly as before.
func TestSelfManagedRefusesInAppKeyCreation(t *testing.T) {
	ctx := context.Background()
	operations := []struct {
		name string
		run  func(*CA) error
	}{
		{"EnsureCAKeys", func(c *CA) error { return c.EnsureCAKeys(ctx) }},
		{"EnsureMTLSCA", func(c *CA) error { return c.EnsureMTLSCA(ctx) }},
		{"Rotate", func(c *CA) error { _, err := c.Rotate(ctx, store.CertTypeUser); return err }},
	}
	for _, op := range operations {
		t.Run(op.name+"/self-managed", func(t *testing.T) {
			fs := &fakeStore{}
			c := newSelfManagedCA(t, fs, mountedKeys(t, t.TempDir()))
			if err := op.run(c); !errors.Is(err, ErrSelfManaged) {
				t.Fatalf("%s: got %v, want ErrSelfManaged", op.name, err)
			}
			if len(fs.keys) != 0 || len(fs.events) != 0 {
				t.Errorf("%s persisted state despite refusing: %d keys, %d events", op.name, len(fs.keys), len(fs.events))
			}
		})
		t.Run(op.name+"/managed", func(t *testing.T) {
			c, fs := newTestCA(t)
			if err := op.run(c); err != nil {
				t.Fatalf("%s in managed mode: %v", op.name, err)
			}
			if len(fs.keys) == 0 {
				t.Errorf("%s in managed mode created no key", op.name)
			}
		})
	}
}

// TestAdoptExternalKeysRequiresSelfManagedMode: adopting without mounted keys is
// a programming error, not a silent no-op.
func TestAdoptExternalKeysRequiresSelfManagedMode(t *testing.T) {
	c, _ := newTestCA(t)
	if err := c.AdoptExternalKeys(context.Background()); err == nil {
		t.Fatal("expected an error (managed mode has no external keys)")
	}
}

// TestAdoptExternalKeysOnEmptyStore: the first start in self-managed mode
// derives one ca_keys row per purpose from the mounted files — public metadata
// only, no private key in the database — and audits each adoption once.
func TestAdoptExternalKeysOnEmptyStore(t *testing.T) {
	fs := &fakeStore{}
	keys := mountedKeys(t, t.TempDir())
	c := newSelfManagedCA(t, fs, keys)
	ctx := context.Background()

	if err := c.AdoptExternalKeys(ctx); err != nil {
		t.Fatalf("AdoptExternalKeys: %v", err)
	}

	wantPublicKeys := map[string]string{
		store.CertTypeUser:  keys.User.PublicKey,
		store.CertTypeHost:  keys.Host.PublicKey,
		store.CAPurposeMTLS: keys.MTLS.CertPEM,
	}
	if len(fs.keys) != len(wantPublicKeys) {
		t.Fatalf("adopted %d ca_keys rows, want %d (user, host, mtls)", len(fs.keys), len(wantPublicKeys))
	}
	for purpose, wantPublicKey := range wantPublicKeys {
		key := caKeyFor(fs, purpose, "")
		switch {
		case key.ID == uuid.Nil:
			t.Errorf("%s: no ca_keys row adopted", purpose)
		case key.PublicKey != wantPublicKey:
			t.Errorf("%s: adopted public key does not match the mounted material", purpose)
		}
		if key.EncryptedPrivateKey != nil {
			t.Errorf("%s: private key material written to the database", purpose)
		}
		if key.State != store.CAKeyStateActive {
			t.Errorf("%s: state = %q, want %q", purpose, key.State, store.CAKeyStateActive)
		}
		if key.Algorithm != "ed25519" {
			t.Errorf("%s: algorithm = %q, want ed25519", purpose, key.Algorithm)
		}
	}

	want := []string{store.CertTypeHost, store.CAPurposeMTLS, store.CertTypeUser} // sorted
	if got := adoptedPurposes(t, fs); !slices.Equal(got, want) {
		t.Errorf("ca.key_adopted events = %v, want exactly %v", got, want)
	}
	if len(fs.events) != len(want) {
		t.Errorf("audit events = %v, want only the adoptions", fs.eventTypes())
	}
}

// TestAdoptExternalKeysRecordsMountedAlgorithm is the regression guard for
// ca_keys.algorithm: the column must describe the mounted material. The loader
// accepts every SSH key type, so an ssh-rsa user CA has to be recorded as "rsa"
// and not as the hardcoded "ed25519".
func TestAdoptExternalKeysRecordsMountedAlgorithm(t *testing.T) {
	dir := t.TempDir()
	paths := newExternalKeyFixtures(t, dir)
	paths.UserKeyFile = newRSASSHKeyFixture(t, dir, "user-ca-rsa")
	keys := mustLoadExternalKeys(t, paths)

	fs := &fakeStore{}
	if err := newSelfManagedCA(t, fs, keys).AdoptExternalKeys(context.Background()); err != nil {
		t.Fatalf("AdoptExternalKeys: %v", err)
	}
	want := map[string]string{
		store.CertTypeUser:  "rsa",
		store.CertTypeHost:  "ed25519",
		store.CAPurposeMTLS: "ed25519",
	}
	for purpose, wantAlgorithm := range want {
		if got := caKeyFor(fs, purpose, "").Algorithm; got != wantAlgorithm {
			t.Errorf("%s: algorithm = %q, want %q", purpose, got, wantAlgorithm)
		}
	}
}

// TestAdoptExternalKeysReAdoptsSameRows: a restart with unchanged key files
// re-uses the existing rows and audits nothing — the row is derived state.
func TestAdoptExternalKeysReAdoptsSameRows(t *testing.T) {
	fs := &fakeStore{}
	keys := mountedKeys(t, t.TempDir())
	ctx := context.Background()
	if err := newSelfManagedCA(t, fs, keys).AdoptExternalKeys(ctx); err != nil {
		t.Fatalf("AdoptExternalKeys: %v", err)
	}
	first := slices.Clone(fs.keys)

	// Same mounted secret, fresh process.
	restarted := newSelfManagedCA(t, fs, keys)
	if err := restarted.AdoptExternalKeys(ctx); err != nil {
		t.Fatalf("AdoptExternalKeys (restart): %v", err)
	}

	if len(fs.keys) != len(first) {
		t.Fatalf("ca_keys rows after restart = %d, want %d", len(fs.keys), len(first))
	}
	for i := range first {
		if fs.keys[i].ID != first[i].ID || fs.keys[i].State != first[i].State {
			t.Errorf("%s row changed on restart: %s/%s → %s/%s",
				first[i].Purpose, first[i].ID, first[i].State, fs.keys[i].ID, fs.keys[i].State)
		}
	}
	if got := adoptedPurposes(t, fs); len(got) != 3 {
		t.Errorf("ca.key_adopted events after restart = %v, want one per purpose from the first adoption", got)
	}
}

// TestAdoptExternalKeysRotationViaFileSwap: committing a new key file rotates
// the CA (D6) — the new key becomes active, the previous one is demoted to
// retiring and stays in the bundle so hosts keep trusting both.
func TestAdoptExternalKeysRotationViaFileSwap(t *testing.T) {
	dir := t.TempDir()
	paths := newExternalKeyFixtures(t, dir)
	keysA := mustLoadExternalKeys(t, paths)
	fs := &fakeStore{}
	ctx := context.Background()
	if err := newSelfManagedCA(t, fs, keysA).AdoptExternalKeys(ctx); err != nil {
		t.Fatalf("AdoptExternalKeys (key a): %v", err)
	}

	// The operator replaces the user CA key in the mounted secret.
	rotated := paths
	rotated.UserKeyFile, _ = newSSHKeyFixture(t, dir, "user-ca-next")
	keysB := mustLoadExternalKeys(t, rotated)
	c := newSelfManagedCA(t, fs, keysB)
	if err := c.AdoptExternalKeys(ctx); err != nil {
		t.Fatalf("AdoptExternalKeys (key b): %v", err)
	}

	newRow := caKeyFor(fs, store.CertTypeUser, keysB.User.PublicKey)
	oldRow := caKeyFor(fs, store.CertTypeUser, keysA.User.PublicKey)
	if newRow.State != store.CAKeyStateActive {
		t.Errorf("new user key state = %q, want %q", newRow.State, store.CAKeyStateActive)
	}
	if oldRow.State != store.CAKeyStateRetiring {
		t.Errorf("previous user key state = %q, want %q", oldRow.State, store.CAKeyStateRetiring)
	}

	bundle, err := c.Bundle(ctx, store.CertTypeUser)
	if err != nil {
		t.Fatalf("Bundle: %v", err)
	}
	if lines := strings.Split(strings.TrimSpace(bundle), "\n"); len(lines) != 2 {
		t.Fatalf("bundle with 2 keys expected, got %d:\n%s", len(lines), bundle)
	}
	if !strings.Contains(bundle, keysA.User.PublicKey) || !strings.Contains(bundle, keysB.User.PublicKey) {
		t.Error("bundle must contain the previous and the new user ca key")
	}

	// Only the new user key is a first adoption; host and mtls were re-adopted.
	want := []string{store.CertTypeHost, store.CAPurposeMTLS, store.CertTypeUser, store.CertTypeUser} // sorted
	if got := adoptedPurposes(t, fs); !slices.Equal(got, want) {
		t.Errorf("ca.key_adopted events = %v, want %v", got, want)
	}
}

// TestAdoptExternalKeysRetiredKeyRefused: re-mounting a key an operator retired
// on purpose must fail at startup with an actionable message.
func TestAdoptExternalKeysRetiredKeyRefused(t *testing.T) {
	fs := &fakeStore{}
	keys := mountedKeys(t, t.TempDir())
	ctx := context.Background()
	if err := newSelfManagedCA(t, fs, keys).AdoptExternalKeys(ctx); err != nil {
		t.Fatalf("AdoptExternalKeys: %v", err)
	}
	userKey := caKeyFor(fs, store.CertTypeUser, keys.User.PublicKey)
	if _, err := fs.UpdateCAKeyState(ctx, userKey.ID, store.CAKeyStateRetired); err != nil {
		t.Fatalf("retire key: %v", err)
	}

	err := newSelfManagedCA(t, fs, keys).AdoptExternalKeys(ctx)
	if !errors.Is(err, store.ErrCAKeyRetired) {
		t.Fatalf("got %v, want store.ErrCAKeyRetired", err)
	}
	for _, want := range []string{"retired", store.CertTypeUser} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error is not actionable, %q missing: %v", want, err)
		}
	}
}

// TestSelfManagedIssue: certificates are signed with the mounted key and carry
// the ID of the adopted row.
func TestSelfManagedIssue(t *testing.T) {
	fs := &fakeStore{}
	keys := mountedKeys(t, t.TempDir())
	c := newSelfManagedCA(t, fs, keys)
	ctx := context.Background()
	if err := c.AdoptExternalKeys(ctx); err != nil {
		t.Fatalf("AdoptExternalKeys: %v", err)
	}

	cert, record, err := c.Issue(ctx, RequesterUser, selfManagedUserRequest(t), IssueRef{Actor: "test"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	mountedPub := keys.User.Signer.PublicKey()
	if !bytes.Equal(cert.SignatureKey.Marshal(), mountedPub.Marshal()) {
		t.Fatal("certificate was not signed with the mounted user ca key")
	}
	checker := ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return bytes.Equal(auth.Marshal(), mountedPub.Marshal())
		},
	}
	if _, err := checker.Authenticate(fakeConnMetadata{user: "alice"}, cert); err != nil {
		t.Errorf("certificate does not verify against the mounted ca key: %v", err)
	}
	if want := caKeyFor(fs, store.CertTypeUser, keys.User.PublicKey); record.CAKeyID != want.ID {
		t.Errorf("ca_key_id = %s, want the adopted row %s", record.CAKeyID, want.ID)
	}
	if len(fs.certs) != 1 {
		t.Errorf("persisted certificates = %d, want 1", len(fs.certs))
	}
}

// TestSelfManagedIssueWithoutAdopt: without AdoptExternalKeys there is no signer
// — and no database key to silently fall back to.
func TestSelfManagedIssueWithoutAdopt(t *testing.T) {
	c := newSelfManagedCA(t, &fakeStore{}, mountedKeys(t, t.TempDir()))
	_, _, err := c.Issue(context.Background(), RequesterUser, selfManagedUserRequest(t), IssueRef{})
	if err == nil {
		t.Fatal("expected an error (AdoptExternalKeys was not called)")
	}
}

// TestSelfManagedRetiringKeyStillSigns is the regression guard for signer
// selection: a replica still running on the previous key file finds its row in
// state "retiring" after another replica adopted the new key. The signer is
// chosen by the adopted ID, not by state = active, so signing keeps working
// until that replica is rolled.
func TestSelfManagedRetiringKeyStillSigns(t *testing.T) {
	dir := t.TempDir()
	paths := newExternalKeyFixtures(t, dir)
	keysA := mustLoadExternalKeys(t, paths)
	fs := &fakeStore{}
	ctx := context.Background()
	if err := newSelfManagedCA(t, fs, keysA).AdoptExternalKeys(ctx); err != nil {
		t.Fatalf("AdoptExternalKeys (key a): %v", err)
	}
	rotated := paths
	rotated.UserKeyFile, _ = newSSHKeyFixture(t, dir, "user-ca-next")
	if err := newSelfManagedCA(t, fs, mustLoadExternalKeys(t, rotated)).AdoptExternalKeys(ctx); err != nil {
		t.Fatalf("AdoptExternalKeys (key b): %v", err)
	}

	old := newSelfManagedCA(t, fs, keysA)
	if err := old.AdoptExternalKeys(ctx); err != nil {
		t.Fatalf("re-adopting the demoted key: %v", err)
	}
	rowA := caKeyFor(fs, store.CertTypeUser, keysA.User.PublicKey)
	if rowA.State != store.CAKeyStateRetiring {
		t.Fatalf("precondition: previous key state = %q, want %q", rowA.State, store.CAKeyStateRetiring)
	}

	cert, record, err := old.Issue(ctx, RequesterUser, selfManagedUserRequest(t), IssueRef{Actor: "test"})
	if err != nil {
		t.Fatalf("issuing with an adopted key in state retiring: %v", err)
	}
	if record.CAKeyID != rowA.ID {
		t.Errorf("ca_key_id = %s, want the adopted (retiring) row %s", record.CAKeyID, rowA.ID)
	}
	if !bytes.Equal(cert.SignatureKey.Marshal(), keysA.User.Signer.PublicKey().Marshal()) {
		t.Error("certificate was not signed with the mounted key of this replica")
	}
}

// TestSelfManagedRetireKeyKeepsSigning is the regression guard for the signer
// cache: step 3 of the D6 rotation is the operator retiring the previous row
// after the transition window. That is a pure ca_keys state change and must not
// touch the running process — its signer comes from the mounted key file, so
// nothing in the database can invalidate it (and nothing could rebuild it).
func TestSelfManagedRetireKeyKeepsSigning(t *testing.T) {
	dir := t.TempDir()
	paths := newExternalKeyFixtures(t, dir)
	keysA := mustLoadExternalKeys(t, paths)
	fs := &fakeStore{}
	ctx := context.Background()
	if err := newSelfManagedCA(t, fs, keysA).AdoptExternalKeys(ctx); err != nil {
		t.Fatalf("AdoptExternalKeys (key a): %v", err)
	}

	// The operator commits the new key file; this process runs on it and
	// demoted the previous key to "retiring" on adoption.
	rotated := paths
	rotated.UserKeyFile, _ = newSSHKeyFixture(t, dir, "user-ca-next")
	keysB := mustLoadExternalKeys(t, rotated)
	c := newSelfManagedCA(t, fs, keysB)
	if err := c.AdoptExternalKeys(ctx); err != nil {
		t.Fatalf("AdoptExternalKeys (key b): %v", err)
	}
	oldRow := caKeyFor(fs, store.CertTypeUser, keysA.User.PublicKey)
	if oldRow.State != store.CAKeyStateRetiring {
		t.Fatalf("precondition: previous key state = %q, want %q", oldRow.State, store.CAKeyStateRetiring)
	}

	// D6 step 3: the transition window is over, the old row is retired.
	if err := c.RetireKey(ctx, oldRow.ID); err != nil {
		t.Fatalf("RetireKey: %v", err)
	}
	if got := caKeyFor(fs, store.CertTypeUser, keysA.User.PublicKey); got.State != store.CAKeyStateRetired {
		t.Fatalf("previous key state = %q, want %q", got.State, store.CAKeyStateRetired)
	}

	cert, record, err := c.Issue(ctx, RequesterUser, selfManagedUserRequest(t), IssueRef{Actor: "test"})
	if err != nil {
		t.Fatalf("issuing after retiring the previous ca key: %v", err)
	}
	newRow := caKeyFor(fs, store.CertTypeUser, keysB.User.PublicKey)
	if record.CAKeyID != newRow.ID {
		t.Errorf("ca_key_id = %s, want the adopted row %s", record.CAKeyID, newRow.ID)
	}
	if !bytes.Equal(cert.SignatureKey.Marshal(), keysB.User.Signer.PublicKey().Marshal()) {
		t.Error("certificate was not signed with the mounted user ca key")
	}
}
