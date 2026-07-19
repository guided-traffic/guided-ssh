package auth_test

import (
	"context"
	"io"
	"log/slog"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/guided-traffic/guided-ssh/internal/auth"
)

// fakeDirectory ist eine DirectorySource aus dem Speicher.
type fakeDirectory struct {
	issuer string
	users  []auth.DirectoryUser
	err    error
}

func (f *fakeDirectory) Issuer() string { return f.issuer }

func (f *fakeDirectory) Users(context.Context) ([]auth.DirectoryUser, error) {
	return f.users, f.err
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// seedUser legt via Mapper einen aktiven Benutzer mit Gruppen an und liefert
// seine ID.
func seedUser(t *testing.T, fs *fakeAuthStore, claims *auth.Claims) uuid.UUID {
	t.Helper()
	user, err := auth.NewMapper(fs).EnsureUser(context.Background(), claims)
	if err != nil {
		t.Fatalf("seed EnsureUser: %v", err)
	}
	return user.ID
}

func TestSyncOnceEntzugUndOffboarding(t *testing.T) {
	fs := newFakeAuthStore()
	alice := seedUser(t, fs, aliceClaims())

	bobClaims := aliceClaims()
	bobClaims.Subject = "bob-id"
	bobClaims.PreferredUsername = "bob"
	bobClaims.Email = "bob@example.com"
	bob := seedUser(t, fs, bobClaims)

	// IdP-Zustand: alice nur noch in "dev", bob gar nicht mehr vorhanden.
	dir := &fakeDirectory{issuer: testIssuer, users: []auth.DirectoryUser{
		{Subject: "alice-id", Username: "alice", Email: "alice@example.com", Groups: []string{"dev"}, Active: true},
	}}
	syncer := auth.NewSyncer(fs, dir, discardLogger())
	if err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatalf("SyncOnce: %v", err)
	}

	if names := fs.groupNames(alice); !slices.Equal(names, []string{"dev"}) {
		t.Errorf("alice-gruppen: %v, erwartet [dev]", names)
	}
	bobStored := fs.users[bob]
	if bobStored.Active {
		t.Error("bob muss deaktiviert sein")
	}
	if names := fs.groupNames(bob); len(names) != 0 {
		t.Errorf("bob-gruppen nicht entzogen: %v", names)
	}
	if len(fs.audits) != 1 || fs.audits[0].EventType != auth.EventUserDeactivated {
		t.Errorf("audit-events: %+v", fs.audits)
	}

	// Zweiter Lauf: idempotent, kein weiteres Audit-Event.
	if err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatalf("zweiter SyncOnce: %v", err)
	}
	if len(fs.audits) != 1 {
		t.Errorf("deaktivierung nicht idempotent: %+v", fs.audits)
	}
}

func TestSyncOnceDeaktiviertImIdPDeaktivierte(t *testing.T) {
	fs := newFakeAuthStore()
	alice := seedUser(t, fs, aliceClaims())

	dir := &fakeDirectory{issuer: testIssuer, users: []auth.DirectoryUser{
		{Subject: "alice-id", Username: "alice", Active: false},
	}}
	if err := auth.NewSyncer(fs, dir, discardLogger()).SyncOnce(context.Background()); err != nil {
		t.Fatalf("SyncOnce: %v", err)
	}
	if fs.users[alice].Active {
		t.Error("alice muss deaktiviert sein (im idp disabled)")
	}
}

func TestSyncOnceReaktiviertUndAktualisiert(t *testing.T) {
	fs := newFakeAuthStore()
	alice := seedUser(t, fs, aliceClaims())
	fs.users[alice].Active = false
	fs.userGroups[alice] = nil

	dir := &fakeDirectory{issuer: testIssuer, users: []auth.DirectoryUser{
		{Subject: "alice-id", Username: "alice2", Email: "alice2@example.com", Groups: []string{"/admins"}, Active: true},
	}}
	if err := auth.NewSyncer(fs, dir, discardLogger()).SyncOnce(context.Background()); err != nil {
		t.Fatalf("SyncOnce: %v", err)
	}
	stored := fs.users[alice]
	if !stored.Active || stored.Username != "alice2" || stored.Email != "alice2@example.com" {
		t.Errorf("nicht reaktiviert/aktualisiert: %+v", stored)
	}
	if names := fs.groupNames(alice); !slices.Equal(names, []string{"admins"}) {
		t.Errorf("gruppen: %v", names)
	}
	found := false
	for _, e := range fs.audits {
		if e.EventType == auth.EventUserReactivated {
			found = true
		}
	}
	if !found {
		t.Errorf("kein reaktivierungs-audit: %+v", fs.audits)
	}
}

func TestSyncOnceIgnoriertFremdeIssuer(t *testing.T) {
	fs := newFakeAuthStore()
	alice := seedUser(t, fs, aliceClaims())

	dir := &fakeDirectory{issuer: "https://anderer.example.com", users: nil}
	if err := auth.NewSyncer(fs, dir, discardLogger()).SyncOnce(context.Background()); err != nil {
		t.Fatalf("SyncOnce: %v", err)
	}
	if !fs.users[alice].Active {
		t.Error("benutzer eines anderen issuers darf nicht angefasst werden")
	}
}

func TestSyncOnceFehlerpfade(t *testing.T) {
	dirErr := &fakeDirectory{issuer: testIssuer, err: errFakeStore}
	if err := auth.NewSyncer(newFakeAuthStore(), dirErr, discardLogger()).SyncOnce(context.Background()); err == nil {
		t.Error("directory-fehler nicht durchgereicht")
	}

	for _, method := range []string{"ListUsers", "UpdateUser", "SetUserGroups", "AppendAuditEvent"} {
		fs := newFakeAuthStore()
		seedUser(t, fs, aliceClaims())
		fs.failOn = method
		dir := &fakeDirectory{issuer: testIssuer} // niemand mehr im IdP ⇒ Deaktivierungspfad
		if err := auth.NewSyncer(fs, dir, discardLogger()).SyncOnce(context.Background()); err == nil {
			t.Errorf("failOn=%s: erwartete fehler", method)
		}
	}
}

func TestRunSynctPeriodisch(t *testing.T) {
	fs := newFakeAuthStore()
	seedUser(t, fs, aliceClaims())

	dir := &fakeDirectory{issuer: testIssuer} // leer ⇒ Deaktivierung beim ersten Lauf
	syncer := auth.NewSyncer(fs, dir, discardLogger())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		syncer.Run(ctx, 10*time.Millisecond)
		close(done)
	}()
	deadline := time.After(2 * time.Second)
	for fs.auditCount() == 0 {
		select {
		case <-deadline:
			t.Fatal("Run hat nie synchronisiert")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run endet nicht bei context-cancel")
	}
}
