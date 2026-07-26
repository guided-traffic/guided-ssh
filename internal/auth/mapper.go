package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/guided-traffic/guided-ssh/internal/store"
)

// ErrUserInactive: the user is deactivated (e.g. by the group sync after
// offboarding) — no reissuance, regardless of whether the token is still
// valid.
var ErrUserInactive = errors.New("auth: user is deactivated")

// Store is the persistence interface required by the auth package
// (*store.Store satisfies it; tests use a fake).
type Store interface {
	GetUserBySubject(ctx context.Context, issuer, subject string) (*store.User, error)
	CreateUser(ctx context.Context, u *store.User) error
	UpdateUser(ctx context.Context, u *store.User) error
	ListUsers(ctx context.Context) ([]store.User, error)
	SetUserGroups(ctx context.Context, userID uuid.UUID, groupIDs []uuid.UUID) error
	GetGroupByName(ctx context.Context, issuer, name string) (*store.Group, error)
	CreateGroup(ctx context.Context, g *store.Group) error
	AppendAuditEvent(ctx context.Context, e *store.AuditEvent) error
}

// Mapper maps validated token claims onto internal users.
type Mapper struct {
	store Store
}

// NewMapper builds a Mapper over the store.
func NewMapper(st Store) *Mapper {
	return &Mapper{store: st}
}

// EnsureUser creates or updates the user for the claims and replaces their
// group memberships with the groups from the token (group claims are the
// freshest source at issuance time). Deactivated users are rejected
// (ErrUserInactive) and not reactivated — reactivation is decided by the
// group sync or an admin.
func (m *Mapper) EnsureUser(ctx context.Context, claims *Claims) (*store.User, error) {
	user, err := m.store.GetUserBySubject(ctx, claims.Issuer, claims.Subject)
	switch {
	case errors.Is(err, store.ErrNotFound):
		user = &store.User{
			Issuer:   claims.Issuer,
			Subject:  claims.Subject,
			Username: claims.Username(),
			Email:    claims.Email,
			Active:   true,
		}
		if err := m.store.CreateUser(ctx, user); err != nil {
			return nil, fmt.Errorf("auth: creating user: %w", err)
		}
	case err != nil:
		return nil, err
	case !user.Active:
		return nil, fmt.Errorf("%w: %s@%s", ErrUserInactive, claims.Subject, claims.Issuer)
	default:
		if user.Username != claims.Username() || user.Email != claims.Email {
			user.Username = claims.Username()
			user.Email = claims.Email
			if err := m.store.UpdateUser(ctx, user); err != nil {
				return nil, fmt.Errorf("auth: updating user: %w", err)
			}
		}
	}

	groupIDs, err := m.ensureGroups(ctx, claims.Issuer, claims.Groups)
	if err != nil {
		return nil, err
	}
	if err := m.store.SetUserGroups(ctx, user.ID, groupIDs); err != nil {
		return nil, fmt.Errorf("auth: setting groups: %w", err)
	}
	return user, nil
}

// ensureGroups resolves group names to IDs and creates unknown groups.
func (m *Mapper) ensureGroups(ctx context.Context, issuer string, names []string) ([]uuid.UUID, error) {
	ids := make([]uuid.UUID, 0, len(names))
	for _, name := range names {
		group, err := m.store.GetGroupByName(ctx, issuer, name)
		if errors.Is(err, store.ErrNotFound) {
			group = &store.Group{Issuer: issuer, Name: name}
			if err := m.store.CreateGroup(ctx, group); err != nil {
				return nil, fmt.Errorf("auth: creating group %q: %w", name, err)
			}
		} else if err != nil {
			return nil, err
		}
		ids = append(ids, group.ID)
	}
	return ids, nil
}
