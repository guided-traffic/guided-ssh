//go:build integration

package store_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/guided-traffic/guided-ssh/internal/store"
)

func TestCIGrantsCRUD(t *testing.T) {
	cleanDB(t)
	ctx := context.Background()

	grant := &store.CIGrant{
		ProjectPath: "infra/ansible", RefPattern: "main", ProtectedOnly: true,
		TagSelector: map[string]string{"env": "prod"},
		Principals:  []string{"deploy"}, MaxValiditySeconds: 3600,
	}
	mustNoErr(t, testStore.CreateCIGrant(ctx, "admin:test", grant))
	if grant.ID == uuid.Nil || grant.CreatedAt.IsZero() {
		t.Fatalf("grant incomplete: %+v", grant)
	}

	got, err := testStore.GetCIGrant(ctx, grant.ID)
	mustNoErr(t, err)
	if got.ProjectPath != "infra/ansible" || !got.ProtectedOnly || got.TagSelector["env"] != "prod" {
		t.Errorf("get = %+v", got)
	}

	list, err := testStore.ListCIGrants(ctx)
	mustNoErr(t, err)
	if len(list) != 1 {
		t.Fatalf("list: %d entries", len(list))
	}

	grant.Principals = []string{"deploy", "ansible"}
	grant.RefPattern = "release/*"
	mustNoErr(t, testStore.UpdateCIGrant(ctx, "admin:test", grant))
	got, err = testStore.GetCIGrant(ctx, grant.ID)
	mustNoErr(t, err)
	if !slices.Equal(got.Principals, []string{"deploy", "ansible"}) || got.RefPattern != "release/*" {
		t.Errorf("update not persisted: %+v", got)
	}

	mustNoErr(t, testStore.DeleteCIGrant(ctx, "admin:test", grant.ID))
	_, err = testStore.GetCIGrant(ctx, grant.ID)
	wantNotFound(t, err)
	wantNotFound(t, testStore.DeleteCIGrant(ctx, "admin:test", grant.ID))

	// Every mutation wrote an audit event with an actor.
	for _, eventType := range []string{
		store.EventCIGrantCreated, store.EventCIGrantUpdated, store.EventCIGrantDeleted,
	} {
		events, err := testStore.ListAuditEvents(ctx, store.AuditFilter{EventType: eventType})
		mustNoErr(t, err)
		if len(events) != 1 || events[0].Actor != "admin:test" {
			t.Errorf("%s: %d events, actor %q", eventType, len(events), eventsActor(events))
		}
	}
}

// eventsActor returns the actor of the first event (diagnostics).
func eventsActor(events []store.AuditEvent) string {
	if len(events) == 0 {
		return ""
	}
	return events[0].Actor
}

func TestMatchCIGrantsProjectAndNamespace(t *testing.T) {
	cleanDB(t)
	ctx := context.Background()

	exact := &store.CIGrant{
		ProjectPath: "infra/ansible", ProtectedOnly: true,
		Principals: []string{"deploy"}, MaxValiditySeconds: 3600,
	}
	group := &store.CIGrant{
		ProjectPath: "infra", ProtectedOnly: false,
		Principals: []string{"ansible"}, MaxValiditySeconds: 1800,
	}
	other := &store.CIGrant{
		ProjectPath: "other/app", ProtectedOnly: false,
		Principals: []string{"deploy"}, MaxValiditySeconds: 3600,
	}
	prefixTrap := &store.CIGrant{
		ProjectPath: "inf", ProtectedOnly: false,
		Principals: []string{"deploy"}, MaxValiditySeconds: 3600,
	}
	for _, g := range []*store.CIGrant{exact, group, other, prefixTrap} {
		mustNoErr(t, testStore.CreateCIGrant(ctx, "admin:test", g))
	}

	// Protected main branch: both the exact and namespace grant match.
	matched, err := testStore.MatchCIGrants(ctx, store.CIMatch{
		ProjectPath: "infra/ansible", Ref: "main", RefProtected: true,
	})
	mustNoErr(t, err)
	if len(matched) != 2 {
		t.Fatalf("matched: %d grants (%+v)", len(matched), matched)
	}

	// Unprotected branch: only the namespace grant (ProtectedOnly=false).
	matched, err = testStore.MatchCIGrants(ctx, store.CIMatch{
		ProjectPath: "infra/ansible", Ref: "feature/x", RefProtected: false,
	})
	mustNoErr(t, err)
	if len(matched) != 1 || matched[0].ProjectPath != "infra" {
		t.Fatalf("matched: %+v", matched)
	}

	// Unrelated project: nothing ("inf" is not a valid namespace prefix).
	matched, err = testStore.MatchCIGrants(ctx, store.CIMatch{
		ProjectPath: "infrastructure/app", Ref: "main", RefProtected: true,
	})
	mustNoErr(t, err)
	if len(matched) != 0 {
		t.Fatalf("matched: %+v", matched)
	}
}

func TestApplyCIGrants(t *testing.T) {
	cleanDB(t)
	ctx := context.Background()

	specs := []store.CIGrantSpec{
		{
			ProjectPath: "infra/ansible", RefPattern: "main", ProtectedOnly: true,
			TagSelector: map[string]string{"env": "prod"},
			Principals:  []string{"deploy"}, MaxValiditySeconds: 3600,
		},
		{
			ProjectPath: "infra", ProtectedOnly: true,
			Principals: []string{"ansible"}, MaxValiditySeconds: 1800,
		},
	}
	result, err := testStore.ApplyCIGrants(ctx, "admin:test", specs)
	mustNoErr(t, err)
	if result.Created != 2 || result.Updated+result.Deleted+result.Unchanged != 0 {
		t.Fatalf("first apply: %+v", result)
	}

	// Idempotent: same target state ⇒ everything unchanged.
	result, err = testStore.ApplyCIGrants(ctx, "admin:test", specs)
	mustNoErr(t, err)
	if result.Unchanged != 2 || result.Created+result.Updated+result.Deleted != 0 {
		t.Fatalf("idempotent apply: %+v", result)
	}

	// Change principals + remove a grant.
	specs[0].Principals = []string{"deploy", "root"}
	result, err = testStore.ApplyCIGrants(ctx, "admin:test", specs[:1])
	mustNoErr(t, err)
	if result.Updated != 1 || result.Deleted != 1 {
		t.Fatalf("third apply: %+v", result)
	}
	remaining, err := testStore.ListCIGrants(ctx)
	mustNoErr(t, err)
	if len(remaining) != 1 || !slices.Equal(remaining[0].Principals, []string{"deploy", "root"}) {
		t.Fatalf("inventory: %+v", remaining)
	}

	// Invalid spec aborts the whole apply (transaction, inventory unchanged).
	if _, err := testStore.ApplyCIGrants(ctx, "admin:test", []store.CIGrantSpec{
		{ProjectPath: "", Principals: []string{"x"}, MaxValiditySeconds: 60},
	}); err == nil {
		t.Fatal("invalid spec: expected an error")
	}
	remaining, err = testStore.ListCIGrants(ctx)
	mustNoErr(t, err)
	if len(remaining) != 1 {
		t.Fatalf("inventory after failed apply: %+v", remaining)
	}

	// A duplicate condition within one file is a client error.
	dup := store.CIGrantSpec{
		ProjectPath: "x", ProtectedOnly: true,
		Principals: []string{"deploy"}, MaxValiditySeconds: 60,
	}
	if _, err := testStore.ApplyCIGrants(ctx, "admin:test", []store.CIGrantSpec{dup, dup}); err == nil {
		t.Fatal("duplicate spec: expected an error")
	}
}

func TestEnsureCIServiceAccount(t *testing.T) {
	cleanDB(t)
	ctx := context.Background()

	account, err := testStore.EnsureCIServiceAccount(ctx, "https://gitlab.example", "infra/ansible")
	mustNoErr(t, err)
	if account.Kind != store.KindGitLabCI || !account.Active || account.Name != "infra/ansible" {
		t.Fatalf("account = %+v", account)
	}

	// Idempotent: same ID on the second call.
	again, err := testStore.EnsureCIServiceAccount(ctx, "https://gitlab.example", "infra/ansible")
	mustNoErr(t, err)
	if again.ID != account.ID {
		t.Errorf("new id %s instead of %s", again.ID, account.ID)
	}

	// Deactivation (kill switch) survives further issuances.
	account.Active = false
	mustNoErr(t, testStore.UpdateServiceAccount(ctx, account))
	after, err := testStore.EnsureCIServiceAccount(ctx, "https://gitlab.example", "infra/ansible")
	mustNoErr(t, err)
	if after.Active {
		t.Error("active was reactivated by ensure")
	}
}

func TestListAuthorizedPrincipalsWithCIGrants(t *testing.T) {
	cleanDB(t)
	ctx := context.Background()

	// Host with env=prod.
	hash := newToken(t, nil, map[string]string{"env": "prod"}, time.Hour)
	host, err := testStore.EnrollHost(ctx, store.EnrollHostParams{
		TokenHash: hash, Name: "web1", PublicKey: "k",
	})
	mustNoErr(t, err)

	// CI grant for deploy on env=prod, a second one for different tags.
	mustNoErr(t, testStore.CreateCIGrant(ctx, "admin:test", &store.CIGrant{
		ProjectPath: "infra/ansible", ProtectedOnly: true,
		TagSelector: map[string]string{"env": "prod"},
		Principals:  []string{"deploy"}, MaxValiditySeconds: 3600,
	}))
	mustNoErr(t, testStore.CreateCIGrant(ctx, "admin:test", &store.CIGrant{
		ProjectPath: "infra/other", ProtectedOnly: true,
		TagSelector: map[string]string{"env": "staging"},
		Principals:  []string{"deploy"}, MaxValiditySeconds: 3600,
	}))

	// deploy gets the CI principal of the matching grant — not that of the
	// staging grant, and nothing for other local users.
	principals, err := testStore.ListAuthorizedPrincipals(ctx, host.ID, "deploy")
	mustNoErr(t, err)
	if !slices.Equal(principals, []string{"ci:infra/ansible"}) {
		t.Errorf("principals = %v", principals)
	}
	principals, err = testStore.ListAuthorizedPrincipals(ctx, host.ID, "root")
	mustNoErr(t, err)
	if len(principals) != 0 {
		t.Errorf("root-principals = %v", principals)
	}

	// User grants and CI grants complement each other.
	alice := &store.User{Issuer: "idp", Subject: "s1", Username: "alice", Email: "alice@example.com", Active: true}
	mustNoErr(t, testStore.CreateUser(ctx, alice))
	ops := &store.Group{Issuer: "idp", Name: "ops"}
	mustNoErr(t, testStore.CreateGroup(ctx, ops))
	mustNoErr(t, testStore.SetUserGroups(ctx, alice.ID, []uuid.UUID{ops.ID}))
	mustNoErr(t, testStore.CreateGrant(ctx, "admin:test", &store.AccessGrant{
		GroupID: ops.ID, Principals: []string{"deploy"}, MaxValiditySeconds: 3600,
	}))

	principals, err = testStore.ListAuthorizedPrincipals(ctx, host.ID, "deploy")
	mustNoErr(t, err)
	want := []string{"alice", "alice@example.com", "ci:infra/ansible"}
	if !slices.Equal(principals, want) {
		t.Errorf("principals = %v, want %v", principals, want)
	}
}
