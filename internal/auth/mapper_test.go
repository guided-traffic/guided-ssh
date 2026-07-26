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

func TestEnsureUserCreatesNew(t *testing.T) {
	fs := newFakeAuthStore()
	mapper := auth.NewMapper(fs)

	user, err := mapper.EnsureUser(context.Background(), aliceClaims())
	if err != nil {
		t.Fatalf("EnsureUser: %v", err)
	}
	if user.Username != "alice" || user.Email != "alice@example.com" || !user.Active {
		t.Errorf("user wrong: %+v", user)
	}
	names := fs.groupNames(user.ID)
	slices.Sort(names)
	if !slices.Equal(names, []string{"admins", "dev"}) {
		t.Errorf("groups wrong: %v", names)
	}
}

func TestEnsureUserUpdatesAndSyncsGroups(t *testing.T) {
	fs := newFakeAuthStore()
	mapper := auth.NewMapper(fs)

	first, err := mapper.EnsureUser(context.Background(), aliceClaims())
	if err != nil {
		t.Fatalf("first EnsureUser: %v", err)
	}

	// Renamed and removed from "admins".
	changed := aliceClaims()
	changed.PreferredUsername = "alice.new"
	changed.Groups = []string{"dev"}
	second, err := mapper.EnsureUser(context.Background(), changed)
	if err != nil {
		t.Fatalf("second EnsureUser: %v", err)
	}
	if second.ID != first.ID {
		t.Fatal("user was duplicated instead of updated")
	}
	if second.Username != "alice.new" {
		t.Errorf("username not updated: %+v", second)
	}
	if names := fs.groupNames(first.ID); !slices.Equal(names, []string{"dev"}) {
		t.Errorf("groups not replaced: %v", names)
	}
	// Groups were reused, not duplicated.
	if len(fs.groups) != 2 {
		t.Errorf("group count: %d, expected 2", len(fs.groups))
	}
}

func TestEnsureUserInactiveIsRejected(t *testing.T) {
	fs := newFakeAuthStore()
	mapper := auth.NewMapper(fs)

	user, err := mapper.EnsureUser(context.Background(), aliceClaims())
	if err != nil {
		t.Fatalf("EnsureUser: %v", err)
	}
	stored := fs.users[user.ID]
	stored.Active = false

	if _, err := mapper.EnsureUser(context.Background(), aliceClaims()); !errors.Is(err, auth.ErrUserInactive) {
		t.Fatalf("expected ErrUserInactive, got %v", err)
	}
	if stored.Active {
		t.Error("user must not be reactivated")
	}
}

func TestEnsureUserErrorPaths(t *testing.T) {
	for _, method := range []string{
		"GetUserBySubject", "CreateUser", "SetUserGroups", "GetGroupByName", "CreateGroup",
	} {
		fs := newFakeAuthStore()
		fs.failOn = method
		if _, err := auth.NewMapper(fs).EnsureUser(context.Background(), aliceClaims()); err == nil {
			t.Errorf("failOn=%s: expected error", method)
		}
	}

	// An UpdateUser error needs an existing user with a change.
	fs := newFakeAuthStore()
	mapper := auth.NewMapper(fs)
	if _, err := mapper.EnsureUser(context.Background(), aliceClaims()); err != nil {
		t.Fatalf("EnsureUser: %v", err)
	}
	fs.failOn = "UpdateUser"
	changed := aliceClaims()
	changed.PreferredUsername = "new"
	if _, err := mapper.EnsureUser(context.Background(), changed); err == nil {
		t.Error("failOn=UpdateUser: expected error")
	}
}
