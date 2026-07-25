//go:build integration

// Integration tests for the self-managed CA adoption path (SELF_MANAGED_CA.md,
// D4): AdoptCAKey against a real PostgreSQL, including the unique index from
// migration 0005 that makes concurrent adoptions by several replicas safe.
// They reuse the container harness of store_integration_test.go.

package store_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/guided-traffic/guided-ssh/internal/ca"
	"github.com/guided-traffic/guided-ssh/internal/store"
)

// newCertSubjectKey returns a fresh Ed25519 SSH public key.
func newCertSubjectKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("wrap ed25519 key as ssh public key: %v", err)
	}
	return sshPub
}

// authorizedKey renders a public key the way ca_keys.public_key and the CA
// bundle store it (single line, no trailing newline).
func authorizedKey(key ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}

// newSSHPublicKey returns a fresh Ed25519 public key in authorized_keys format
// — the representation ca_keys.public_key holds for the user/host purposes.
func newSSHPublicKey(t *testing.T) string {
	t.Helper()
	return authorizedKey(newCertSubjectKey(t))
}

// caKeyRow reads state and private-key presence of a ca_keys row straight from
// the database, past the repository API.
func caKeyRow(t *testing.T, id uuid.UUID) (state string, hasPrivateKey bool) {
	t.Helper()
	err := rawPool.QueryRow(context.Background(),
		`SELECT state, encrypted_private_key IS NOT NULL FROM ca_keys WHERE id = $1`, id).
		Scan(&state, &hasPrivateKey)
	if err != nil {
		t.Fatalf("read ca_keys row %s: %v", id, err)
	}
	return state, hasPrivateKey
}

// countCAKeys counts the ca_keys rows of a purpose.
func countCAKeys(t *testing.T, purpose string) int {
	t.Helper()
	var n int
	if err := rawPool.QueryRow(context.Background(),
		`SELECT count(*) FROM ca_keys WHERE purpose = $1`, purpose).Scan(&n); err != nil {
		t.Fatalf("count ca_keys of purpose %q: %v", purpose, err)
	}
	return n
}

func TestAdoptCAKeyFreshDatabase(t *testing.T) {
	cleanDB(t)
	ctx := context.Background()
	publicKey := newSSHPublicKey(t)

	key, created, err := testStore.AdoptCAKey(ctx, store.CertTypeUser, "ed25519", publicKey)
	mustNoErr(t, err)
	if !created {
		t.Fatal("first adoption must report created = true")
	}
	if key.State != store.CAKeyStateActive {
		t.Errorf("state = %q, want %q", key.State, store.CAKeyStateActive)
	}
	if key.EncryptedPrivateKey != nil {
		t.Errorf("adopted row carries private key material (%d bytes), want NULL", len(key.EncryptedPrivateKey))
	}
	if key.Purpose != store.CertTypeUser || key.Algorithm != "ed25519" || key.PublicKey != publicKey {
		t.Errorf("adopted row = %+v", key)
	}
	if key.ID == uuid.Nil || key.CreatedAt.IsZero() {
		t.Errorf("id/created_at not filled: %+v", key)
	}

	// The database really holds an active row without private key material.
	state, hasPrivateKey := caKeyRow(t, key.ID)
	if state != store.CAKeyStateActive || hasPrivateKey {
		t.Errorf("db row: state = %q, encrypted_private_key present = %v; want active/false", state, hasPrivateKey)
	}
}

func TestAdoptCAKeyReadoptIsIdempotent(t *testing.T) {
	cleanDB(t)
	ctx := context.Background()
	publicKey := newSSHPublicKey(t)

	first, created, err := testStore.AdoptCAKey(ctx, store.CertTypeUser, "ed25519", publicKey)
	mustNoErr(t, err)
	if !created {
		t.Fatal("first adoption must report created = true")
	}

	// A restart with an unchanged mounted key must not touch anything.
	second, created, err := testStore.AdoptCAKey(ctx, store.CertTypeUser, "ed25519", publicKey)
	mustNoErr(t, err)
	if created {
		t.Error("re-adopting the same key must report created = false")
	}
	if second.ID != first.ID {
		t.Errorf("re-adoption returned a different row: %s vs %s", second.ID, first.ID)
	}
	if second.State != store.CAKeyStateActive {
		t.Errorf("state after re-adoption = %q, want active", second.State)
	}
	if n := countCAKeys(t, store.CertTypeUser); n != 1 {
		t.Errorf("%d user ca_keys rows, want exactly 1", n)
	}
	if state, _ := caKeyRow(t, first.ID); state != store.CAKeyStateActive {
		t.Errorf("re-adoption demoted the only active key to %q", state)
	}
}

func TestAdoptCAKeyRotationDemotesPreviousKey(t *testing.T) {
	cleanDB(t)
	ctx := context.Background()

	oldKey := newSSHPublicKey(t)
	newKey := newSSHPublicKey(t)

	previous, _, err := testStore.AdoptCAKey(ctx, store.CertTypeUser, "ed25519", oldKey)
	mustNoErr(t, err)

	// File-based rotation (D6): a different mounted key becomes active and the
	// previous one moves to "retiring" so it stays in the CA bundle.
	current, created, err := testStore.AdoptCAKey(ctx, store.CertTypeUser, "ed25519", newKey)
	mustNoErr(t, err)
	if !created {
		t.Fatal("adopting a second key must report created = true")
	}
	if current.State != store.CAKeyStateActive {
		t.Errorf("new key state = %q, want active", current.State)
	}
	if state, _ := caKeyRow(t, previous.ID); state != store.CAKeyStateRetiring {
		t.Errorf("previous key state = %q, want retiring", state)
	}

	// Both keys stay in the bundle during the transition.
	active, err := testStore.ListActiveCAKeys(ctx, store.CertTypeUser)
	mustNoErr(t, err)
	if len(active) != 2 {
		t.Fatalf("ListActiveCAKeys = %d rows, want 2 (active + retiring)", len(active))
	}

	// Keys of another purpose are untouched by the rotation.
	hostKey, _, err := testStore.AdoptCAKey(ctx, store.CertTypeHost, "ed25519", newSSHPublicKey(t))
	mustNoErr(t, err)
	if state, _ := caKeyRow(t, current.ID); state != store.CAKeyStateActive {
		t.Errorf("adopting a host key demoted the active user key to %q", state)
	}
	if state, _ := caKeyRow(t, hostKey.ID); state != store.CAKeyStateActive {
		t.Errorf("host key state = %q, want active", state)
	}
}

func TestAdoptCAKeyDoesNotPromoteRetiringKey(t *testing.T) {
	cleanDB(t)
	ctx := context.Background()

	superseded := newSSHPublicKey(t)
	current := newSSHPublicKey(t)

	old, _, err := testStore.AdoptCAKey(ctx, store.CertTypeUser, "ed25519", superseded)
	mustNoErr(t, err)
	active, _, err := testStore.AdoptCAKey(ctx, store.CertTypeUser, "ed25519", current)
	mustNoErr(t, err)

	// Re-mounting the superseded key must not silently reverse the rotation.
	readopted, created, err := testStore.AdoptCAKey(ctx, store.CertTypeUser, "ed25519", superseded)
	mustNoErr(t, err)
	if created {
		t.Error("re-adopting an existing key must report created = false")
	}
	if readopted.ID != old.ID {
		t.Errorf("re-adoption returned %s, want the existing row %s", readopted.ID, old.ID)
	}
	if readopted.State != store.CAKeyStateRetiring {
		t.Errorf("retiring key was promoted to %q", readopted.State)
	}
	if state, _ := caKeyRow(t, old.ID); state != store.CAKeyStateRetiring {
		t.Errorf("db row of the retiring key = %q, want retiring", state)
	}
	if state, _ := caKeyRow(t, active.ID); state != store.CAKeyStateActive {
		t.Errorf("current active key was demoted to %q", state)
	}
	if n := countCAKeys(t, store.CertTypeUser); n != 2 {
		t.Errorf("%d user ca_keys rows, want 2", n)
	}
}

func TestAdoptCAKeyRetiredIsRefused(t *testing.T) {
	cleanDB(t)
	ctx := context.Background()
	publicKey := newSSHPublicKey(t)

	key, _, err := testStore.AdoptCAKey(ctx, store.CertTypeUser, "ed25519", publicKey)
	mustNoErr(t, err)
	if _, err := testStore.UpdateCAKeyState(ctx, key.ID, store.CAKeyStateRetired); err != nil {
		t.Fatalf("retire ca key: %v", err)
	}

	// Mounting a deliberately retired key is a startup error, not a resurrection.
	_, _, err = testStore.AdoptCAKey(ctx, store.CertTypeUser, "ed25519", publicKey)
	if !errors.Is(err, store.ErrCAKeyRetired) {
		t.Fatalf("err = %v, want ErrCAKeyRetired", err)
	}
	if n := countCAKeys(t, store.CertTypeUser); n != 1 {
		t.Errorf("%d user ca_keys rows, want 1 (the refused adoption must not insert)", n)
	}
	if state, _ := caKeyRow(t, key.ID); state != store.CAKeyStateRetired {
		t.Errorf("retired row changed to %q", state)
	}
}

// TestAdoptCAKeyConcurrent models several replicas starting at the same time
// against the same fresh database: the unique index of migration 0005 has to
// serialize them into exactly one row (SELF_MANAGED_CA.md, D4).
func TestAdoptCAKeyConcurrent(t *testing.T) {
	cleanDB(t)
	ctx := context.Background()
	publicKey := newSSHPublicKey(t)

	const replicas = 8
	type result struct {
		key     *store.CAKey
		created bool
		err     error
	}
	results := make([]result, replicas)

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range replicas {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			key, created, err := testStore.AdoptCAKey(ctx, store.CertTypeUser, "ed25519", publicKey)
			results[i] = result{key: key, created: created, err: err}
		}()
	}
	close(start)
	wg.Wait()

	var createdCount int
	var id uuid.UUID
	for i, r := range results {
		if r.err != nil {
			t.Fatalf("replica %d: %v", i, r.err)
		}
		if r.created {
			createdCount++
		}
		if id == uuid.Nil {
			id = r.key.ID
		}
		if r.key.ID != id {
			t.Errorf("replica %d adopted %s, replica 0 adopted %s — must be the same row", i, r.key.ID, id)
		}
		if r.key.State != store.CAKeyStateActive {
			t.Errorf("replica %d: state = %q, want active", i, r.key.State)
		}
	}
	if createdCount != 1 {
		t.Errorf("%d replicas reported created = true, want exactly 1", createdCount)
	}
	if n := countCAKeys(t, store.CertTypeUser); n != 1 {
		t.Errorf("%d user ca_keys rows after %d concurrent adoptions, want 1", n, replicas)
	}
	if _, hasPrivateKey := caKeyRow(t, id); hasPrivateKey {
		t.Error("concurrently adopted row carries private key material")
	}
}

// TestCAKeyUniqueIndexRejectsDuplicate pins the constraint the adoption logic
// relies on: the plain CreateCAKey path cannot create a second row for the same
// (purpose, public_key), while the same key under another purpose is fine.
func TestCAKeyUniqueIndexRejectsDuplicate(t *testing.T) {
	cleanDB(t)
	ctx := context.Background()
	publicKey := newSSHPublicKey(t)

	mustNoErr(t, testStore.CreateCAKey(ctx, &store.CAKey{
		Purpose: store.CertTypeUser, Algorithm: "ed25519", PublicKey: publicKey,
	}))

	err := testStore.CreateCAKey(ctx, &store.CAKey{
		Purpose: store.CertTypeUser, Algorithm: "ed25519", PublicKey: publicKey,
		State: store.CAKeyStateRetiring,
	})
	if err == nil {
		t.Fatal("duplicate (purpose, public_key) must be rejected")
	}
	if !strings.Contains(err.Error(), "ca_keys_purpose_public_key_idx") {
		t.Errorf("error does not name the unique index of migration 0005: %v", err)
	}

	// The index is composite: the same public key may exist for another purpose.
	mustNoErr(t, testStore.CreateCAKey(ctx, &store.CAKey{
		Purpose: store.CertTypeHost, Algorithm: "ed25519", PublicKey: publicKey,
	}))
	if n := countCAKeys(t, store.CertTypeUser); n != 1 {
		t.Errorf("%d user ca_keys rows, want 1", n)
	}
	if n := countCAKeys(t, store.CertTypeHost); n != 1 {
		t.Errorf("%d host ca_keys rows, want 1", n)
	}
}

// TestAdoptCAKeyMTLSCertificatePEM covers the largest value the index has to
// carry: for purpose "mtls" public_key holds the whole X.509 CA certificate
// PEM, not a one-line SSH key.
func TestAdoptCAKeyMTLSCertificatePEM(t *testing.T) {
	cleanDB(t)
	ctx := context.Background()

	certPEM, _, err := ca.GenerateMTLSCA()
	mustNoErr(t, err)
	t.Logf("mtls ca certificate pem: %d bytes", len(certPEM))

	key, created, err := testStore.AdoptCAKey(ctx, store.CAPurposeMTLS, "ed25519", string(certPEM))
	mustNoErr(t, err)
	if !created {
		t.Fatal("first adoption of the mtls ca must report created = true")
	}

	// Stored verbatim: adoption matches on the exact PEM, so any truncation or
	// normalization by the index would break every restart.
	stored, err := testStore.GetCAKey(ctx, key.ID)
	mustNoErr(t, err)
	if stored.PublicKey != string(certPEM) {
		t.Errorf("stored public_key differs from the certificate pem (%d vs %d bytes)",
			len(stored.PublicKey), len(certPEM))
	}
	if stored.EncryptedPrivateKey != nil {
		t.Error("adopted mtls row carries private key material")
	}

	// A restart re-adopts the very same row.
	again, created, err := testStore.AdoptCAKey(ctx, store.CAPurposeMTLS, "ed25519", string(certPEM))
	mustNoErr(t, err)
	if created || again.ID != key.ID {
		t.Errorf("re-adoption: created = %v, id = %s (want false / %s)", created, again.ID, key.ID)
	}

	// The unique index covers the full PEM as well.
	if err := testStore.CreateCAKey(ctx, &store.CAKey{
		Purpose: store.CAPurposeMTLS, Algorithm: "ed25519", PublicKey: string(certPEM),
	}); err == nil {
		t.Error("duplicate mtls certificate pem must be rejected by the unique index")
	}
	if n := countCAKeys(t, store.CAPurposeMTLS); n != 1 {
		t.Errorf("%d mtls ca_keys rows, want 1", n)
	}
}
