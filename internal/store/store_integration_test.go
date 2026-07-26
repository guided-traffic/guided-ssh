//go:build integration

package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/guided-traffic/guided-ssh/internal/store"
)

var (
	testDSN   string
	testStore *store.Store
	rawPool   *pgxpool.Pool // for setup/asserts that bypass the repository API
)

func TestMain(m *testing.M) {
	code, err := run(m)
	if err != nil {
		fmt.Fprintln(os.Stderr, "setup:", err)
		code = 1
	}
	os.Exit(code)
}

func run(m *testing.M) (int, error) {
	ctx := context.Background()

	ctr, err := tcpostgres.Run(ctx, "postgres:17-alpine",
		tcpostgres.WithDatabase("guidedssh"),
		tcpostgres.WithUsername("guidedssh"),
		tcpostgres.WithPassword("guidedssh"),
		tcpostgres.BasicWaitStrategies(),
	)
	if ctr != nil {
		defer func() { _ = testcontainers.TerminateContainer(ctr) }()
	}
	if err != nil {
		return 1, fmt.Errorf("postgres container: %w", err)
	}

	testDSN, err = ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		return 1, err
	}
	if err := store.Migrate(ctx, testDSN); err != nil {
		return 1, err
	}
	testStore, err = store.New(ctx, testDSN)
	if err != nil {
		return 1, err
	}
	defer testStore.Close()

	rawPool, err = pgxpool.New(ctx, testDSN)
	if err != nil {
		return 1, err
	}
	defer rawPool.Close()

	return m.Run(), nil
}

// cleanDB empties all tables (TRUNCATE does not fire row triggers, so it
// deliberately bypasses the append-only protection — for test isolation only).
func cleanDB(t *testing.T) {
	t.Helper()
	_, err := rawPool.Exec(context.Background(), `
		TRUNCATE users, groups, hosts, access_grants, ci_grants, ca_keys,
			service_accounts, certificates, audit_events, enrollment_tokens
			RESTART IDENTITY CASCADE`)
	if err != nil {
		t.Fatalf("cleanDB: %v", err)
	}
}

func mustNoErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func wantNotFound(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got: %v", err)
	}
}

func TestMigrateIdempotent(t *testing.T) {
	// Migrations already ran in TestMain — running again must be a no-op.
	mustNoErr(t, store.Migrate(context.Background(), testDSN))
}

func TestNewInvalidDSN(t *testing.T) {
	if _, err := store.New(context.Background(), "postgres://invalid@localhost:1/nope?connect_timeout=1"); err == nil {
		t.Fatal("expected an error")
	}
	if err := store.Migrate(context.Background(), "postgres://invalid@localhost:1/nope?connect_timeout=1"); err == nil {
		t.Fatal("expected an error")
	}
}

func TestUsersCRUD(t *testing.T) {
	cleanDB(t)
	ctx := context.Background()

	u := &store.User{Issuer: "https://idp.example", Subject: "sub-1", Username: "alice", Email: "alice@example.com", Active: true}
	mustNoErr(t, testStore.CreateUser(ctx, u))
	if u.ID == uuid.Nil || u.CreatedAt.IsZero() {
		t.Fatal("ID/CreatedAt not filled")
	}

	got, err := testStore.GetUser(ctx, u.ID)
	mustNoErr(t, err)
	if got.Username != "alice" {
		t.Fatalf("Username = %q", got.Username)
	}

	got, err = testStore.GetUserBySubject(ctx, "https://idp.example", "sub-1")
	mustNoErr(t, err)
	if got.ID != u.ID {
		t.Fatal("GetUserBySubject returned the wrong user")
	}

	uid := int32(4200)
	u.UID = &uid
	u.Active = false
	mustNoErr(t, testStore.UpdateUser(ctx, u))
	if u.UID == nil || *u.UID != 4200 || u.Active {
		t.Fatalf("update not applied: %+v", u)
	}

	all, err := testStore.ListUsers(ctx)
	mustNoErr(t, err)
	if len(all) != 1 {
		t.Fatalf("ListUsers = %d entries", len(all))
	}

	_, err = testStore.GetUser(ctx, uuid.New())
	wantNotFound(t, err)
	_, err = testStore.GetUserBySubject(ctx, "https://idp.example", "missing")
	wantNotFound(t, err)

	mustNoErr(t, testStore.DeleteUser(ctx, u.ID))
	wantNotFound(t, testStore.DeleteUser(ctx, u.ID))
}

func TestUserGroups(t *testing.T) {
	cleanDB(t)
	ctx := context.Background()

	u := &store.User{Issuer: "idp", Subject: "s", Username: "bob", Email: "bob@example.com", Active: true}
	mustNoErr(t, testStore.CreateUser(ctx, u))
	g1 := &store.Group{Issuer: "idp", Name: "admins"}
	g2 := &store.Group{Issuer: "idp", Name: "devs"}
	mustNoErr(t, testStore.CreateGroup(ctx, g1))
	mustNoErr(t, testStore.CreateGroup(ctx, g2))

	mustNoErr(t, testStore.SetUserGroups(ctx, u.ID, []uuid.UUID{g1.ID, g2.ID}))
	groups, err := testStore.ListUserGroups(ctx, u.ID)
	mustNoErr(t, err)
	if len(groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(groups))
	}

	// Sync fully replaces the target state.
	mustNoErr(t, testStore.SetUserGroups(ctx, u.ID, []uuid.UUID{g2.ID}))
	groups, err = testStore.ListUserGroups(ctx, u.ID)
	mustNoErr(t, err)
	if len(groups) != 1 || groups[0].Name != "devs" {
		t.Fatalf("expected [devs], got %+v", groups)
	}

	mustNoErr(t, testStore.SetUserGroups(ctx, u.ID, nil))
	groups, err = testStore.ListUserGroups(ctx, u.ID)
	mustNoErr(t, err)
	if len(groups) != 0 {
		t.Fatalf("expected 0 groups, got %d", len(groups))
	}
}

func TestGroupsCRUD(t *testing.T) {
	cleanDB(t)
	ctx := context.Background()

	ext := "ext-1"
	g := &store.Group{Issuer: "idp", Name: "ops", ExternalID: &ext}
	mustNoErr(t, testStore.CreateGroup(ctx, g))

	got, err := testStore.GetGroup(ctx, g.ID)
	mustNoErr(t, err)
	if got.ExternalID == nil || *got.ExternalID != "ext-1" {
		t.Fatalf("ExternalID = %v", got.ExternalID)
	}

	got, err = testStore.GetGroupByName(ctx, "idp", "ops")
	mustNoErr(t, err)
	if got.ID != g.ID {
		t.Fatal("GetGroupByName returned the wrong group")
	}

	all, err := testStore.ListGroups(ctx)
	mustNoErr(t, err)
	if len(all) != 1 {
		t.Fatalf("ListGroups = %d", len(all))
	}

	_, err = testStore.GetGroupByName(ctx, "idp", "missing")
	wantNotFound(t, err)

	mustNoErr(t, testStore.DeleteGroup(ctx, g.ID))
	wantNotFound(t, testStore.DeleteGroup(ctx, g.ID))
}

func TestHostsCRUDAndTags(t *testing.T) {
	cleanDB(t)
	ctx := context.Background()

	h := &store.Host{Name: "web-1.example"}
	mustNoErr(t, testStore.CreateHost(ctx, h))

	got, err := testStore.GetHostByName(ctx, "web-1.example")
	mustNoErr(t, err)
	if got.ID != h.ID {
		t.Fatal("GetHostByName returned the wrong host")
	}
	if _, err := testStore.GetHost(ctx, h.ID); err != nil {
		t.Fatal(err)
	}

	pub := "ssh-ed25519 AAAA..."
	now := time.Now().UTC()
	h.PublicKey = &pub
	h.EnrolledAt = &now
	h.LastSeenAt = &now
	mustNoErr(t, testStore.UpdateHost(ctx, h))
	if h.PublicKey == nil || h.EnrolledAt == nil || h.LastSeenAt == nil {
		t.Fatalf("update not applied: %+v", h)
	}

	mustNoErr(t, testStore.SetHostTags(ctx, h.ID, map[string]string{"role": "web", "env": "prod"}))
	tags, err := testStore.GetHostTags(ctx, h.ID)
	mustNoErr(t, err)
	if len(tags) != 2 || tags["role"] != "web" || tags["env"] != "prod" {
		t.Fatalf("tags = %v", tags)
	}

	// Replaces, does not merge.
	mustNoErr(t, testStore.SetHostTags(ctx, h.ID, map[string]string{"role": "db"}))
	tags, err = testStore.GetHostTags(ctx, h.ID)
	mustNoErr(t, err)
	if len(tags) != 1 || tags["role"] != "db" {
		t.Fatalf("tags = %v", tags)
	}

	hosts, err := testStore.ListHosts(ctx)
	mustNoErr(t, err)
	if len(hosts) != 1 {
		t.Fatalf("ListHosts = %d", len(hosts))
	}

	_, err = testStore.GetHostByName(ctx, "missing")
	wantNotFound(t, err)

	mustNoErr(t, testStore.DeleteHost(ctx, h.ID))
	wantNotFound(t, testStore.DeleteHost(ctx, h.ID))
}

func TestGrantsCRUD(t *testing.T) {
	cleanDB(t)
	ctx := context.Background()

	g := &store.Group{Issuer: "idp", Name: "deployers"}
	mustNoErr(t, testStore.CreateGroup(ctx, g))

	grant := &store.AccessGrant{
		GroupID:            g.ID,
		TagSelector:        map[string]string{"env": "prod"},
		Principals:         []string{"deploy"},
		Sudo:               true,
		MaxValiditySeconds: 3600,
	}
	mustNoErr(t, testStore.CreateGrant(ctx, "admin:test", grant))
	if grant.MaxValidity() != time.Hour {
		t.Fatalf("MaxValidity = %v", grant.MaxValidity())
	}

	got, err := testStore.GetGrant(ctx, grant.ID)
	mustNoErr(t, err)
	if got.TagSelector["env"] != "prod" || !got.Sudo || len(got.Principals) != 1 {
		t.Fatalf("Grant = %+v", got)
	}

	detailed, err := testStore.GetGrantDetailed(ctx, grant.ID)
	mustNoErr(t, err)
	if detailed.GroupName != "deployers" || detailed.GroupIssuer != "idp" {
		t.Fatalf("GrantDetailed = %+v", detailed)
	}
	allDetailed, err := testStore.ListGrantsDetailed(ctx)
	mustNoErr(t, err)
	if len(allDetailed) != 1 || allDetailed[0].GroupName != "deployers" {
		t.Fatalf("ListGrantsDetailed = %+v", allDetailed)
	}

	grant.Principals = []string{"deploy", "root"}
	grant.Sudo = false
	mustNoErr(t, testStore.UpdateGrant(ctx, "admin:test", grant))
	if len(grant.Principals) != 2 || grant.Sudo {
		t.Fatalf("update not applied: %+v", grant)
	}

	all, err := testStore.ListGrants(ctx)
	mustNoErr(t, err)
	if len(all) != 1 {
		t.Fatalf("ListGrants = %d", len(all))
	}

	forGroups, err := testStore.ListGrantsForGroups(ctx, []uuid.UUID{g.ID})
	mustNoErr(t, err)
	if len(forGroups) != 1 {
		t.Fatalf("ListGrantsForGroups = %d", len(forGroups))
	}
	forGroups, err = testStore.ListGrantsForGroups(ctx, []uuid.UUID{uuid.New()})
	mustNoErr(t, err)
	if len(forGroups) != 0 {
		t.Fatalf("ListGrantsForGroups (unrelated group) = %d", len(forGroups))
	}

	// CHECK constraint: validity must be > 0.
	bad := &store.AccessGrant{GroupID: g.ID, Principals: []string{"x"}, MaxValiditySeconds: 0}
	if err := testStore.CreateGrant(ctx, "admin:test", bad); err == nil {
		t.Fatal("expected a CHECK violation")
	}

	mustNoErr(t, testStore.DeleteGrant(ctx, "admin:test", grant.ID))
	wantNotFound(t, testStore.DeleteGrant(ctx, "admin:test", grant.ID))
	_, err = testStore.GetGrant(ctx, grant.ID)
	wantNotFound(t, err)

	// Every mutation left an audit event with an actor
	// (created, updated, deleted — the CHECK error rolled back).
	for _, eventType := range []string{store.EventGrantCreated, store.EventGrantUpdated, store.EventGrantDeleted} {
		events, err := testStore.ListAuditEvents(ctx, store.AuditFilter{EventType: eventType})
		mustNoErr(t, err)
		if len(events) != 1 || events[0].Actor != "admin:test" {
			t.Errorf("%s: %d events (actor %s), want 1 from admin:test",
				eventType, len(events), eventActor(events))
		}
	}
}

// eventActor returns the actor of the first event (for error messages).
func eventActor(events []store.AuditEvent) string {
	if len(events) == 0 {
		return "<none>"
	}
	return events[0].Actor
}

func TestListGrantsForUser(t *testing.T) {
	cleanDB(t)
	ctx := context.Background()

	alice := &store.User{Issuer: "idp", Subject: "s1", Username: "alice", Email: "alice@example.com", Active: true}
	mustNoErr(t, testStore.CreateUser(ctx, alice))
	ops := &store.Group{Issuer: "idp", Name: "ops"}
	dev := &store.Group{Issuer: "idp", Name: "dev"}
	mustNoErr(t, testStore.CreateGroup(ctx, ops))
	mustNoErr(t, testStore.CreateGroup(ctx, dev))
	mustNoErr(t, testStore.SetUserGroups(ctx, alice.ID, []uuid.UUID{ops.ID}))

	opsGrant := &store.AccessGrant{GroupID: ops.ID, Principals: []string{"deploy"}, MaxValiditySeconds: 3600}
	devGrant := &store.AccessGrant{GroupID: dev.ID, Principals: []string{"root"}, MaxValiditySeconds: 7200}
	mustNoErr(t, testStore.CreateGrant(ctx, "admin:test", opsGrant))
	mustNoErr(t, testStore.CreateGrant(ctx, "admin:test", devGrant))

	// Only the grant of the user's own group counts.
	grants, err := testStore.ListGrantsForUser(ctx, alice.ID)
	mustNoErr(t, err)
	if len(grants) != 1 || grants[0].ID != opsGrant.ID {
		t.Fatalf("grants = %+v, want only the ops grant", grants)
	}

	// Groups revoked ⇒ no more grants.
	mustNoErr(t, testStore.SetUserGroups(ctx, alice.ID, nil))
	grants, err = testStore.ListGrantsForUser(ctx, alice.ID)
	mustNoErr(t, err)
	if len(grants) != 0 {
		t.Fatalf("grants after revocation = %+v, want empty", grants)
	}
}

func TestApplyGrants(t *testing.T) {
	cleanDB(t)
	ctx := context.Background()

	// Inventory: two grants for ops (one stays, one drops).
	ops := &store.Group{Issuer: "idp", Name: "ops"}
	mustNoErr(t, testStore.CreateGroup(ctx, ops))
	keep := &store.AccessGrant{
		GroupID: ops.ID, TagSelector: map[string]string{"env": "prod"},
		Principals: []string{"deploy"}, MaxValiditySeconds: 3600,
	}
	drop := &store.AccessGrant{
		GroupID: ops.ID, TagSelector: map[string]string{"env": "dev"},
		Principals: []string{"deploy"}, MaxValiditySeconds: 3600,
	}
	mustNoErr(t, testStore.CreateGrant(ctx, "admin:test", keep))
	mustNoErr(t, testStore.CreateGrant(ctx, "admin:test", drop))

	result, err := testStore.ApplyGrants(ctx, "admin:test", "idp", []store.GrantSpec{
		{ // identical ⇒ unchanged
			Group: "ops", TagSelector: map[string]string{"env": "prod"},
			Principals: []string{"deploy"}, MaxValiditySeconds: 3600,
		},
		{ // new group is created ⇒ created
			Group: "auditors", Principals: []string{"audit"}, MaxValiditySeconds: 7200,
		},
	})
	mustNoErr(t, err)
	if result.Created != 1 || result.Updated != 0 || result.Deleted != 1 || result.Unchanged != 1 {
		t.Fatalf("result = %+v", result)
	}
	if _, err := testStore.GetGrant(ctx, drop.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("undeclared grant still exists (err=%v)", err)
	}
	if _, err := testStore.GetGroupByName(ctx, "idp", "auditors"); err != nil {
		t.Errorf("group auditors was not created: %v", err)
	}

	// Second run with changed fields ⇒ updated, rest unchanged.
	result, err = testStore.ApplyGrants(ctx, "admin:test", "idp", []store.GrantSpec{
		{
			Group: "ops", TagSelector: map[string]string{"env": "prod"},
			Principals: []string{"deploy", "root"}, Sudo: true, MaxValiditySeconds: 3600,
		},
		{Group: "auditors", Principals: []string{"audit"}, MaxValiditySeconds: 7200},
	})
	mustNoErr(t, err)
	if result.Created != 0 || result.Updated != 1 || result.Deleted != 0 || result.Unchanged != 1 {
		t.Fatalf("second run: result = %+v", result)
	}
	updated, err := testStore.GetGrant(ctx, keep.ID)
	mustNoErr(t, err)
	if !updated.Sudo || len(updated.Principals) != 2 {
		t.Fatalf("update not applied: %+v", updated)
	}

	// An empty list clears everything.
	result, err = testStore.ApplyGrants(ctx, "admin:test", "idp", nil)
	mustNoErr(t, err)
	if result.Deleted != 2 {
		t.Fatalf("empty target state: result = %+v", result)
	}
	remaining, err := testStore.ListGrants(ctx)
	mustNoErr(t, err)
	if len(remaining) != 0 {
		t.Fatalf("%d grants remaining", len(remaining))
	}

	// Invalid specs abort transactionally.
	_, err = testStore.ApplyGrants(ctx, "admin:test", "idp", []store.GrantSpec{
		{Group: "ops", Principals: nil, MaxValiditySeconds: 3600},
	})
	if !errors.Is(err, store.ErrInvalidGrantSpec) {
		t.Fatalf("expected ErrInvalidGrantSpec, got: %v", err)
	}
	_, err = testStore.ApplyGrants(ctx, "admin:test", "idp", []store.GrantSpec{
		{Group: "ops", Principals: []string{"deploy"}, MaxValiditySeconds: 3600},
		{Group: "ops", Principals: []string{"root"}, MaxValiditySeconds: 3600},
	})
	if !errors.Is(err, store.ErrInvalidGrantSpec) {
		t.Fatalf("duplicate key: expected ErrInvalidGrantSpec, got: %v", err)
	}
}

func TestCAKeys(t *testing.T) {
	cleanDB(t)
	ctx := context.Background()

	k := &store.CAKey{Purpose: store.CertTypeUser, Algorithm: "ed25519", PublicKey: "ssh-ed25519 AAAA... user-ca", EncryptedPrivateKey: []byte{0x01}}
	mustNoErr(t, testStore.CreateCAKey(ctx, k))
	if k.State != store.CAKeyStateActive {
		t.Fatalf("state = %q, want active", k.State)
	}

	k2 := &store.CAKey{Purpose: store.CertTypeUser, PublicKey: "pk2", Algorithm: "ed25519", State: store.CAKeyStateRetiring}
	mustNoErr(t, testStore.CreateCAKey(ctx, k2))
	hostKey := &store.CAKey{Purpose: store.CertTypeHost, PublicKey: "pk3", Algorithm: "ed25519"}
	mustNoErr(t, testStore.CreateCAKey(ctx, hostKey))

	got, err := testStore.GetCAKey(ctx, k.ID)
	mustNoErr(t, err)
	if got.PublicKey != k.PublicKey {
		t.Fatal("GetCAKey returned the wrong key")
	}

	userKeys, err := testStore.ListCAKeys(ctx, store.CertTypeUser)
	mustNoErr(t, err)
	if len(userKeys) != 2 {
		t.Fatalf("ListCAKeys(user) = %d", len(userKeys))
	}

	retired, err := testStore.UpdateCAKeyState(ctx, k2.ID, store.CAKeyStateRetired)
	mustNoErr(t, err)
	if retired.State != store.CAKeyStateRetired || retired.RetiredAt == nil {
		t.Fatalf("retire not applied: %+v", retired)
	}

	active, err := testStore.ListActiveCAKeys(ctx, store.CertTypeUser)
	mustNoErr(t, err)
	if len(active) != 1 || active[0].ID != k.ID {
		t.Fatalf("ListActiveCAKeys = %+v", active)
	}

	_, err = testStore.GetCAKey(ctx, uuid.New())
	wantNotFound(t, err)
	_, err = testStore.UpdateCAKeyState(ctx, uuid.New(), store.CAKeyStateRetired)
	wantNotFound(t, err)
}

func TestServiceAccountsCRUD(t *testing.T) {
	cleanDB(t)
	ctx := context.Background()

	a := &store.ServiceAccount{
		Name:         "gitlab/infra/ansible",
		Kind:         "gitlab_ci",
		Issuer:       "https://gitlab.example",
		ClaimMatcher: map[string]string{"project_path": "infra/ansible", "ref_protected": "true"},
		Active:       true,
	}
	mustNoErr(t, testStore.CreateServiceAccount(ctx, a))

	got, err := testStore.GetServiceAccount(ctx, a.ID)
	mustNoErr(t, err)
	if got.ClaimMatcher["project_path"] != "infra/ansible" {
		t.Fatalf("ClaimMatcher = %v", got.ClaimMatcher)
	}

	got, err = testStore.GetServiceAccountByName(ctx, "gitlab/infra/ansible")
	mustNoErr(t, err)
	if got.ID != a.ID {
		t.Fatal("GetServiceAccountByName returned the wrong account")
	}

	a.Active = false
	a.ClaimMatcher = map[string]string{"project_path": "infra/ansible"}
	mustNoErr(t, testStore.UpdateServiceAccount(ctx, a))
	if a.Active || len(a.ClaimMatcher) != 1 {
		t.Fatalf("update not applied: %+v", a)
	}

	all, err := testStore.ListServiceAccounts(ctx)
	mustNoErr(t, err)
	if len(all) != 1 {
		t.Fatalf("ListServiceAccounts = %d", len(all))
	}

	_, err = testStore.GetServiceAccountByName(ctx, "missing")
	wantNotFound(t, err)

	mustNoErr(t, testStore.DeleteServiceAccount(ctx, a.ID))
	wantNotFound(t, testStore.DeleteServiceAccount(ctx, a.ID))
}

func TestCertificates(t *testing.T) {
	cleanDB(t)
	ctx := context.Background()

	s1, err := testStore.NextCertificateSerial(ctx)
	mustNoErr(t, err)
	s2, err := testStore.NextCertificateSerial(ctx)
	mustNoErr(t, err)
	if s2 <= s1 {
		t.Fatalf("serials not monotonic: %d, %d", s1, s2)
	}

	ca := &store.CAKey{Purpose: store.CertTypeUser, Algorithm: "ed25519", PublicKey: "ca-pk"}
	mustNoErr(t, testStore.CreateCAKey(ctx, ca))
	u := &store.User{Issuer: "idp", Subject: "s", Username: "carol", Email: "carol@example.com", Active: true}
	mustNoErr(t, testStore.CreateUser(ctx, u))

	now := time.Now().UTC().Truncate(time.Second)
	c := &store.Certificate{
		Serial:      s1,
		KeyID:       "user:s@idp",
		CertType:    store.CertTypeUser,
		PublicKey:   "ssh-ed25519 AAAA... signed",
		Principals:  []string{"carol", "carol@example.com"},
		ValidAfter:  now,
		ValidBefore: now.Add(16 * time.Hour),
		CAKeyID:     ca.ID,
		UserID:      &u.ID,
	}
	mustNoErr(t, testStore.CreateCertificate(ctx, c))
	if string(c.IssuerContext) != "{}" {
		t.Fatalf("IssuerContext default = %s", c.IssuerContext)
	}

	ctxJSON := json.RawMessage(`{"pipeline_id": 42}`)
	c2 := &store.Certificate{
		Serial: s2, KeyID: "ci:infra/ansible:42:7", CertType: store.CertTypeUser,
		PublicKey: "pk2", Principals: []string{"deploy"},
		ValidAfter: now, ValidBefore: now.Add(time.Hour),
		CAKeyID: ca.ID, IssuerContext: ctxJSON,
	}
	mustNoErr(t, testStore.CreateCertificate(ctx, c2))

	got, err := testStore.GetCertificateBySerial(ctx, s1)
	mustNoErr(t, err)
	if got.KeyID != "user:s@idp" || got.UserID == nil || *got.UserID != u.ID {
		t.Fatalf("certificate = %+v", got)
	}
	if !got.ValidBefore.Equal(c.ValidBefore) {
		t.Fatalf("ValidBefore = %v, want %v", got.ValidBefore, c.ValidBefore)
	}

	all, err := testStore.ListCertificates(ctx, 0)
	mustNoErr(t, err)
	if len(all) != 2 {
		t.Fatalf("ListCertificates = %d", len(all))
	}
	one, err := testStore.ListCertificates(ctx, 1)
	mustNoErr(t, err)
	if len(one) != 1 {
		t.Fatalf("ListCertificates(limit 1) = %d", len(one))
	}

	// Serial is unique.
	dup := &store.Certificate{
		Serial: s1, KeyID: "x", CertType: store.CertTypeUser, PublicKey: "x",
		Principals: []string{"x"}, ValidAfter: now, ValidBefore: now.Add(time.Hour), CAKeyID: ca.ID,
	}
	if err := testStore.CreateCertificate(ctx, dup); err == nil {
		t.Fatal("expected a uniqueness violation")
	}

	_, err = testStore.GetCertificateBySerial(ctx, 999999)
	wantNotFound(t, err)
}

func TestCreateCertificateWithAudit(t *testing.T) {
	cleanDB(t)
	ctx := context.Background()

	ca := &store.CAKey{Purpose: store.CertTypeUser, Algorithm: "ed25519", PublicKey: "ca-pk"}
	mustNoErr(t, testStore.CreateCAKey(ctx, ca))
	serial, err := testStore.NextCertificateSerial(ctx)
	mustNoErr(t, err)

	now := time.Now().UTC().Truncate(time.Second)
	cert := &store.Certificate{
		Serial: serial, KeyID: "user:s@idp", CertType: store.CertTypeUser,
		PublicKey: "pk", Principals: []string{"carol"},
		ValidAfter: now, ValidBefore: now.Add(time.Hour), CAKeyID: ca.ID,
	}
	event := &store.AuditEvent{EventType: "ca.cert_issued", Actor: "user:s@idp"}
	mustNoErr(t, testStore.CreateCertificateWithAudit(ctx, cert, event))
	if cert.ID == uuid.Nil || event.ID == 0 {
		t.Fatalf("IDs not filled: cert=%v event=%d", cert.ID, event.ID)
	}

	events, err := testStore.ListAuditEvents(ctx, store.AuditFilter{EventType: "ca.cert_issued"})
	mustNoErr(t, err)
	if len(events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(events))
	}

	// Rollback guarantee: if the certificate insert fails (serial duplicate),
	// no audit event may be written either.
	dup := &store.Certificate{
		Serial: serial, KeyID: "x", CertType: store.CertTypeUser, PublicKey: "x",
		Principals: []string{"x"}, ValidAfter: now, ValidBefore: now.Add(time.Hour), CAKeyID: ca.ID,
	}
	if err := testStore.CreateCertificateWithAudit(ctx, dup, &store.AuditEvent{EventType: "ca.cert_issued"}); err == nil {
		t.Fatal("expected a uniqueness violation")
	}
	events, err = testStore.ListAuditEvents(ctx, store.AuditFilter{EventType: "ca.cert_issued"})
	mustNoErr(t, err)
	if len(events) != 1 {
		t.Fatalf("rollback violated: %d audit events", len(events))
	}
	certs, err := testStore.ListCertificates(ctx, 0)
	mustNoErr(t, err)
	if len(certs) != 1 {
		t.Fatalf("rollback violated: %d certificates", len(certs))
	}
}

func TestAuditEvents(t *testing.T) {
	cleanDB(t)
	ctx := context.Background()

	e1 := &store.AuditEvent{EventType: "cert.issued", Actor: "user:alice", Payload: json.RawMessage(`{"serial": 1}`)}
	mustNoErr(t, testStore.AppendAuditEvent(ctx, e1))
	if e1.ID == 0 || e1.OccurredAt.IsZero() {
		t.Fatal("ID/OccurredAt not filled")
	}
	e2 := &store.AuditEvent{EventType: "cert.issued", Actor: "ci:infra"}
	mustNoErr(t, testStore.AppendAuditEvent(ctx, e2))
	if string(e2.Payload) != "{}" {
		t.Fatalf("payload default = %s", e2.Payload)
	}
	e3 := &store.AuditEvent{EventType: "host.enrolled", Actor: "host:web-1"}
	mustNoErr(t, testStore.AppendAuditEvent(ctx, e3))

	all, err := testStore.ListAuditEvents(ctx, store.AuditFilter{})
	mustNoErr(t, err)
	if len(all) != 3 {
		t.Fatalf("all events = %d", len(all))
	}

	issued, err := testStore.ListAuditEvents(ctx, store.AuditFilter{EventType: "cert.issued"})
	mustNoErr(t, err)
	if len(issued) != 2 {
		t.Fatalf("cert.issued = %d", len(issued))
	}

	byActor, err := testStore.ListAuditEvents(ctx, store.AuditFilter{Actor: "user:alice"})
	mustNoErr(t, err)
	if len(byActor) != 1 || byActor[0].ID != e1.ID {
		t.Fatalf("byActor = %+v", byActor)
	}

	windowed, err := testStore.ListAuditEvents(ctx, store.AuditFilter{
		Since: time.Now().Add(-time.Hour),
		Until: time.Now().Add(time.Hour),
		Limit: 2,
	})
	mustNoErr(t, err)
	if len(windowed) != 2 {
		t.Fatalf("windowed = %d", len(windowed))
	}

	none, err := testStore.ListAuditEvents(ctx, store.AuditFilter{Until: time.Now().Add(-time.Hour)})
	mustNoErr(t, err)
	if len(none) != 0 {
		t.Fatalf("none = %d", len(none))
	}
}

// Append-only guarantee: UPDATE and DELETE fail even via direct DB access
// (trigger), regardless of role grants.
func TestAuditEventsAppendOnly(t *testing.T) {
	cleanDB(t)
	ctx := context.Background()

	e := &store.AuditEvent{EventType: "cert.issued", Actor: "user:alice"}
	mustNoErr(t, testStore.AppendAuditEvent(ctx, e))

	if _, err := rawPool.Exec(ctx, `UPDATE audit_events SET actor = 'evil' WHERE id = $1`, e.ID); err == nil {
		t.Fatal("UPDATE must fail")
	} else if want := "append-only"; !strings.Contains(err.Error(), want) {
		t.Fatalf("error missing %q: %v", want, err)
	}

	if _, err := rawPool.Exec(ctx, `DELETE FROM audit_events WHERE id = $1`, e.ID); err == nil {
		t.Fatal("DELETE must fail")
	}

	// Event is still present unchanged.
	all, err := testStore.ListAuditEvents(ctx, store.AuditFilter{})
	mustNoErr(t, err)
	if len(all) != 1 || all[0].Actor != "user:alice" {
		t.Fatalf("event changed: %+v", all)
	}
}
