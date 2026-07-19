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
		t.Fatalf("grant unvollständig: %+v", grant)
	}

	got, err := testStore.GetCIGrant(ctx, grant.ID)
	mustNoErr(t, err)
	if got.ProjectPath != "infra/ansible" || !got.ProtectedOnly || got.TagSelector["env"] != "prod" {
		t.Errorf("get = %+v", got)
	}

	list, err := testStore.ListCIGrants(ctx)
	mustNoErr(t, err)
	if len(list) != 1 {
		t.Fatalf("list: %d einträge", len(list))
	}

	grant.Principals = []string{"deploy", "ansible"}
	grant.RefPattern = "release/*"
	mustNoErr(t, testStore.UpdateCIGrant(ctx, "admin:test", grant))
	got, err = testStore.GetCIGrant(ctx, grant.ID)
	mustNoErr(t, err)
	if !slices.Equal(got.Principals, []string{"deploy", "ansible"}) || got.RefPattern != "release/*" {
		t.Errorf("update nicht persistiert: %+v", got)
	}

	mustNoErr(t, testStore.DeleteCIGrant(ctx, "admin:test", grant.ID))
	_, err = testStore.GetCIGrant(ctx, grant.ID)
	wantNotFound(t, err)
	wantNotFound(t, testStore.DeleteCIGrant(ctx, "admin:test", grant.ID))

	// Jede Mutation hat ein Audit-Event mit Actor geschrieben.
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

// eventsActor liefert den Actor des ersten Events (Diagnose).
func eventsActor(events []store.AuditEvent) string {
	if len(events) == 0 {
		return ""
	}
	return events[0].Actor
}

func TestMatchCIGrantsProjektUndNamespace(t *testing.T) {
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
		ProjectPath: "andere/app", ProtectedOnly: false,
		Principals: []string{"deploy"}, MaxValiditySeconds: 3600,
	}
	prefixTrap := &store.CIGrant{
		ProjectPath: "inf", ProtectedOnly: false,
		Principals: []string{"deploy"}, MaxValiditySeconds: 3600,
	}
	for _, g := range []*store.CIGrant{exact, group, other, prefixTrap} {
		mustNoErr(t, testStore.CreateCIGrant(ctx, "admin:test", g))
	}

	// Geschützter main-Branch: exakter und Namespace-Grant matchen.
	matched, err := testStore.MatchCIGrants(ctx, store.CIMatch{
		ProjectPath: "infra/ansible", Ref: "main", RefProtected: true,
	})
	mustNoErr(t, err)
	if len(matched) != 2 {
		t.Fatalf("matched: %d grants (%+v)", len(matched), matched)
	}

	// Ungeschützter Branch: nur der Namespace-Grant (ProtectedOnly=false).
	matched, err = testStore.MatchCIGrants(ctx, store.CIMatch{
		ProjectPath: "infra/ansible", Ref: "feature/x", RefProtected: false,
	})
	mustNoErr(t, err)
	if len(matched) != 1 || matched[0].ProjectPath != "infra" {
		t.Fatalf("matched: %+v", matched)
	}

	// Fremdes Projekt: nichts ("inf" ist kein gültiger Namespace-Präfix).
	matched, err = testStore.MatchCIGrants(ctx, store.CIMatch{
		ProjectPath: "infrastruktur/app", Ref: "main", RefProtected: true,
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
		t.Fatalf("erster apply: %+v", result)
	}

	// Idempotent: gleicher Zielzustand ⇒ nur unverändert.
	result, err = testStore.ApplyCIGrants(ctx, "admin:test", specs)
	mustNoErr(t, err)
	if result.Unchanged != 2 || result.Created+result.Updated+result.Deleted != 0 {
		t.Fatalf("idempotenter apply: %+v", result)
	}

	// Principals ändern + einen Grant entfernen.
	specs[0].Principals = []string{"deploy", "root"}
	result, err = testStore.ApplyCIGrants(ctx, "admin:test", specs[:1])
	mustNoErr(t, err)
	if result.Updated != 1 || result.Deleted != 1 {
		t.Fatalf("dritter apply: %+v", result)
	}
	remaining, err := testStore.ListCIGrants(ctx)
	mustNoErr(t, err)
	if len(remaining) != 1 || !slices.Equal(remaining[0].Principals, []string{"deploy", "root"}) {
		t.Fatalf("bestand: %+v", remaining)
	}

	// Ungültige Spec bricht ab (Transaktion, Bestand unverändert).
	if _, err := testStore.ApplyCIGrants(ctx, "admin:test", []store.CIGrantSpec{
		{ProjectPath: "", Principals: []string{"x"}, MaxValiditySeconds: 60},
	}); err == nil {
		t.Fatal("ungültige spec: fehler erwartet")
	}
	remaining, err = testStore.ListCIGrants(ctx)
	mustNoErr(t, err)
	if len(remaining) != 1 {
		t.Fatalf("bestand nach fehlgeschlagenem apply: %+v", remaining)
	}

	// Doppelte Bedingung in einer Datei ist ein Client-Fehler.
	dup := store.CIGrantSpec{
		ProjectPath: "x", ProtectedOnly: true,
		Principals: []string{"deploy"}, MaxValiditySeconds: 60,
	}
	if _, err := testStore.ApplyCIGrants(ctx, "admin:test", []store.CIGrantSpec{dup, dup}); err == nil {
		t.Fatal("doppelte spec: fehler erwartet")
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

	// Idempotent: gleiche ID beim zweiten Aufruf.
	again, err := testStore.EnsureCIServiceAccount(ctx, "https://gitlab.example", "infra/ansible")
	mustNoErr(t, err)
	if again.ID != account.ID {
		t.Errorf("neue id %s statt %s", again.ID, account.ID)
	}

	// Deaktivierung (Not-Aus) überlebt weitere Ausstellungen.
	account.Active = false
	mustNoErr(t, testStore.UpdateServiceAccount(ctx, account))
	after, err := testStore.EnsureCIServiceAccount(ctx, "https://gitlab.example", "infra/ansible")
	mustNoErr(t, err)
	if after.Active {
		t.Error("active wurde durch ensure reaktiviert")
	}
}

func TestListAuthorizedPrincipalsMitCIGrants(t *testing.T) {
	cleanDB(t)
	ctx := context.Background()

	// Host mit env=prod.
	hash := newToken(t, nil, map[string]string{"env": "prod"}, time.Hour)
	host, err := testStore.EnrollHost(ctx, store.EnrollHostParams{
		TokenHash: hash, Name: "web1", PublicKey: "k",
	})
	mustNoErr(t, err)

	// CI-Grant für deploy auf env=prod, zweiter für andere Tags.
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

	// deploy erhält den CI-Principal des passenden Grants — nicht den des
	// staging-Grants und nichts für andere lokale Benutzer.
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

	// Benutzer-Grants und CI-Grants ergänzen sich.
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
		t.Errorf("principals = %v, erwartet %v", principals, want)
	}
}
