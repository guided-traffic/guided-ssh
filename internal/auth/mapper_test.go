package auth_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/guided-traffic/guided-ssh/internal/auth"
)

const testIssuer = "https://idp.example.com/realms/gssh"

func aliceClaims() *auth.Claims {
	return &auth.Claims{
		Issuer:            testIssuer,
		Subject:           "alice-id",
		Email:             "alice@example.com",
		PreferredUsername: "alice",
		Groups:            []string{"admins", "dev"},
	}
}

func TestEnsureUserLegtNeuAn(t *testing.T) {
	fs := newFakeAuthStore()
	mapper := auth.NewMapper(fs)

	user, err := mapper.EnsureUser(context.Background(), aliceClaims())
	if err != nil {
		t.Fatalf("EnsureUser: %v", err)
	}
	if user.Username != "alice" || user.Email != "alice@example.com" || !user.Active {
		t.Errorf("benutzer falsch: %+v", user)
	}
	names := fs.groupNames(user.ID)
	slices.Sort(names)
	if !slices.Equal(names, []string{"admins", "dev"}) {
		t.Errorf("gruppen falsch: %v", names)
	}
}

func TestEnsureUserAktualisiertUndSynctGruppen(t *testing.T) {
	fs := newFakeAuthStore()
	mapper := auth.NewMapper(fs)

	first, err := mapper.EnsureUser(context.Background(), aliceClaims())
	if err != nil {
		t.Fatalf("erster EnsureUser: %v", err)
	}

	// Umbenannt und aus "admins" entfernt.
	changed := aliceClaims()
	changed.PreferredUsername = "alice.neu"
	changed.Groups = []string{"dev"}
	second, err := mapper.EnsureUser(context.Background(), changed)
	if err != nil {
		t.Fatalf("zweiter EnsureUser: %v", err)
	}
	if second.ID != first.ID {
		t.Fatal("benutzer wurde dupliziert statt aktualisiert")
	}
	if second.Username != "alice.neu" {
		t.Errorf("username nicht aktualisiert: %+v", second)
	}
	if names := fs.groupNames(first.ID); !slices.Equal(names, []string{"dev"}) {
		t.Errorf("gruppen nicht ersetzt: %v", names)
	}
	// Gruppen wurden wiederverwendet, nicht dupliziert.
	if len(fs.groups) != 2 {
		t.Errorf("gruppenanzahl: %d, erwartet 2", len(fs.groups))
	}
}

func TestEnsureUserInaktivWirdAbgewiesen(t *testing.T) {
	fs := newFakeAuthStore()
	mapper := auth.NewMapper(fs)

	user, err := mapper.EnsureUser(context.Background(), aliceClaims())
	if err != nil {
		t.Fatalf("EnsureUser: %v", err)
	}
	stored := fs.users[user.ID]
	stored.Active = false

	if _, err := mapper.EnsureUser(context.Background(), aliceClaims()); !errors.Is(err, auth.ErrUserInactive) {
		t.Fatalf("erwartete ErrUserInactive, bekam %v", err)
	}
	if stored.Active {
		t.Error("benutzer darf nicht reaktiviert werden")
	}
}

func TestEnsureUserFehlerpfade(t *testing.T) {
	for _, method := range []string{
		"GetUserBySubject", "CreateUser", "SetUserGroups", "GetGroupByName", "CreateGroup",
	} {
		fs := newFakeAuthStore()
		fs.failOn = method
		if _, err := auth.NewMapper(fs).EnsureUser(context.Background(), aliceClaims()); err == nil {
			t.Errorf("failOn=%s: erwartete fehler", method)
		}
	}

	// UpdateUser-Fehler braucht einen existierenden Benutzer mit Änderung.
	fs := newFakeAuthStore()
	mapper := auth.NewMapper(fs)
	if _, err := mapper.EnsureUser(context.Background(), aliceClaims()); err != nil {
		t.Fatalf("EnsureUser: %v", err)
	}
	fs.failOn = "UpdateUser"
	changed := aliceClaims()
	changed.PreferredUsername = "neu"
	if _, err := mapper.EnsureUser(context.Background(), changed); err == nil {
		t.Error("failOn=UpdateUser: erwartete fehler")
	}
}
