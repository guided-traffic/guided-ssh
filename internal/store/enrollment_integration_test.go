//go:build integration

package store_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/guided-traffic/guided-ssh/internal/store"
)

// newToken creates an enrollment token and returns the hash.
func newToken(t *testing.T, hostName *string, tags map[string]string, ttl time.Duration) []byte {
	t.Helper()
	hash := sha256.Sum256([]byte("token-" + uuid.NewString()))
	mustNoErr(t, testStore.CreateEnrollmentToken(context.Background(), &store.EnrollmentToken{
		TokenHash: hash[:],
		HostName:  hostName,
		Tags:      tags,
		ExpiresAt: time.Now().Add(ttl),
	}))
	return hash[:]
}

func TestEnrollHost(t *testing.T) {
	cleanDB(t)
	ctx := context.Background()
	hash := newToken(t, nil, map[string]string{"env": "prod"}, time.Hour)

	host, err := testStore.EnrollHost(ctx, store.EnrollHostParams{
		TokenHash: hash,
		Name:      "web1.example.com",
		PublicKey: "ssh-ed25519 AAAA-test",
		Tags:      map[string]string{"role": "web", "env": "should-lose"},
	})
	mustNoErr(t, err)
	if host.EnrolledAt == nil || host.PublicKey == nil {
		t.Fatalf("host incomplete: %+v", host)
	}

	// Token tags win on collision; request tags add to them.
	tags, err := testStore.GetHostTags(ctx, host.ID)
	mustNoErr(t, err)
	if tags["env"] != "prod" || tags["role"] != "web" {
		t.Errorf("tags = %v", tags)
	}

	// Token consumed ⇒ a second enrollment fails.
	_, err = testStore.EnrollHost(ctx, store.EnrollHostParams{
		TokenHash: hash, Name: "web2.example.com", PublicKey: "k",
	})
	wantNotFound(t, err)

	// Audit event written.
	events, err := testStore.ListAuditEvents(ctx, store.AuditFilter{EventType: store.EventHostEnrolled})
	mustNoErr(t, err)
	if len(events) != 1 {
		t.Errorf("audit events = %d, want 1", len(events))
	}

	// Re-enrolling the same host with a new token updates instead of duplicating.
	hash2 := newToken(t, nil, nil, time.Hour)
	again, err := testStore.EnrollHost(ctx, store.EnrollHostParams{
		TokenHash: hash2, Name: "web1.example.com", PublicKey: "ssh-ed25519 BBBB-new",
	})
	mustNoErr(t, err)
	if again.ID != host.ID {
		t.Errorf("re-enrollment created a new host: %s vs %s", again.ID, host.ID)
	}
}

func TestEnrollHostErrorCases(t *testing.T) {
	cleanDB(t)
	ctx := context.Background()

	// Expired token.
	expired := newToken(t, nil, nil, -time.Hour)
	_, err := testStore.EnrollHost(ctx, store.EnrollHostParams{TokenHash: expired, Name: "x", PublicKey: "k"})
	wantNotFound(t, err)

	// Unknown token.
	unknown := sha256.Sum256([]byte("does-not-exist"))
	_, err = testStore.EnrollHost(ctx, store.EnrollHostParams{TokenHash: unknown[:], Name: "x", PublicKey: "k"})
	wantNotFound(t, err)

	// Hostname binding violated — the token still ends up consumed (deliberate:
	// a token used with the wrong hostname is burned).
	bound := "correct.example.com"
	boundHash := newToken(t, &bound, nil, time.Hour)
	_, err = testStore.EnrollHost(ctx, store.EnrollHostParams{TokenHash: boundHash, Name: "wrong", PublicKey: "k"})
	if !errors.Is(err, store.ErrTokenHostMismatch) {
		t.Fatalf("expected ErrTokenHostMismatch, got: %v", err)
	}
}

func TestTouchHostLastSeen(t *testing.T) {
	cleanDB(t)
	ctx := context.Background()
	host := &store.Host{Name: "seen.example.com"}
	mustNoErr(t, testStore.CreateHost(ctx, host))
	mustNoErr(t, testStore.TouchHostLastSeen(ctx, host.ID))
	got, err := testStore.GetHost(ctx, host.ID)
	mustNoErr(t, err)
	if got.LastSeenAt == nil {
		t.Fatal("last_seen_at not set")
	}
	wantNotFound(t, testStore.TouchHostLastSeen(ctx, uuid.New()))
}

func TestListAuthorizedPrincipals(t *testing.T) {
	cleanDB(t)
	ctx := context.Background()

	// Users alice (active, group ops) and bob (inactive, group ops).
	alice := &store.User{Issuer: "idp", Subject: "s1", Username: "alice", Email: "alice@example.com", Active: true}
	mustNoErr(t, testStore.CreateUser(ctx, alice))
	bob := &store.User{Issuer: "idp", Subject: "s2", Username: "bob", Email: "bob@example.com", Active: false}
	mustNoErr(t, testStore.CreateUser(ctx, bob))
	ops := &store.Group{Issuer: "idp", Name: "ops"}
	mustNoErr(t, testStore.CreateGroup(ctx, ops))
	mustNoErr(t, testStore.SetUserGroups(ctx, alice.ID, []uuid.UUID{ops.ID}))
	mustNoErr(t, testStore.SetUserGroups(ctx, bob.ID, []uuid.UUID{ops.ID}))

	// Host with tags env=prod, role=web.
	host := &store.Host{Name: "web1.example.com"}
	mustNoErr(t, testStore.CreateHost(ctx, host))
	mustNoErr(t, testStore.SetHostTags(ctx, host.ID, map[string]string{"env": "prod", "role": "web"}))

	// Grant: group ops may log in as deploy on hosts with env=prod.
	grant := &store.AccessGrant{
		GroupID: ops.ID, TagSelector: map[string]string{"env": "prod"},
		Principals: []string{"deploy"}, MaxValiditySeconds: 3600,
	}
	mustNoErr(t, testStore.CreateGrant(ctx, "test", grant))

	// alice (active) is authorized, bob (inactive) is not.
	principals, err := testStore.ListAuthorizedPrincipals(ctx, host.ID, "deploy")
	mustNoErr(t, err)
	want := []string{"alice", "alice@example.com"}
	if len(principals) != 2 || principals[0] != want[0] || principals[1] != want[1] {
		t.Errorf("principals = %v, want %v", principals, want)
	}

	// Different local user ⇒ empty.
	principals, err = testStore.ListAuthorizedPrincipals(ctx, host.ID, "root")
	mustNoErr(t, err)
	if len(principals) != 0 {
		t.Errorf("root: %v, want empty", principals)
	}

	// Selector does not match (env=dev host).
	devHost := &store.Host{Name: "dev1.example.com"}
	mustNoErr(t, testStore.CreateHost(ctx, devHost))
	mustNoErr(t, testStore.SetHostTags(ctx, devHost.ID, map[string]string{"env": "dev"}))
	principals, err = testStore.ListAuthorizedPrincipals(ctx, devHost.ID, "deploy")
	mustNoErr(t, err)
	if len(principals) != 0 {
		t.Errorf("dev host: %v, want empty", principals)
	}

	// Empty selector matches every host.
	all := &store.AccessGrant{
		GroupID: ops.ID, TagSelector: map[string]string{},
		Principals: []string{"root"}, MaxValiditySeconds: 3600,
	}
	mustNoErr(t, testStore.CreateGrant(ctx, "test", all))
	principals, err = testStore.ListAuthorizedPrincipals(ctx, devHost.ID, "root")
	mustNoErr(t, err)
	if len(principals) != 2 {
		t.Errorf("empty selector: %v", principals)
	}
}
