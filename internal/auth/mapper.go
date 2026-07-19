package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/guided-traffic/guided-ssh/internal/store"
)

// ErrUserInactive: Benutzer ist deaktiviert (z. B. durch Gruppen-Sync nach
// Offboarding) — keine Neuausstellung, egal ob das Token noch gültig ist.
var ErrUserInactive = errors.New("auth: benutzer ist deaktiviert")

// Store ist die vom Auth-Paket benötigte Persistenz-Schnittstelle
// (*store.Store erfüllt sie; Tests nutzen einen Fake).
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

// Mapper bildet validierte Token-Claims auf interne Benutzer ab.
type Mapper struct {
	store Store
}

// NewMapper baut einen Mapper über dem Store.
func NewMapper(st Store) *Mapper {
	return &Mapper{store: st}
}

// EnsureUser legt den Benutzer zu den Claims an bzw. aktualisiert ihn und
// ersetzt seine Gruppenzugehörigkeiten durch die Gruppen aus dem Token
// (Group-Claims sind bei Ausstellung die frischeste Quelle). Deaktivierte
// Benutzer werden abgewiesen (ErrUserInactive) und nicht reaktiviert —
// Reaktivierung entscheidet der Gruppen-Sync bzw. ein Admin.
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
			return nil, fmt.Errorf("auth: benutzer anlegen: %w", err)
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
				return nil, fmt.Errorf("auth: benutzer aktualisieren: %w", err)
			}
		}
	}

	groupIDs, err := m.ensureGroups(ctx, claims.Issuer, claims.Groups)
	if err != nil {
		return nil, err
	}
	if err := m.store.SetUserGroups(ctx, user.ID, groupIDs); err != nil {
		return nil, fmt.Errorf("auth: gruppen setzen: %w", err)
	}
	return user, nil
}

// ensureGroups löst Gruppennamen in IDs auf und legt unbekannte Gruppen an.
func (m *Mapper) ensureGroups(ctx context.Context, issuer string, names []string) ([]uuid.UUID, error) {
	ids := make([]uuid.UUID, 0, len(names))
	for _, name := range names {
		group, err := m.store.GetGroupByName(ctx, issuer, name)
		if errors.Is(err, store.ErrNotFound) {
			group = &store.Group{Issuer: issuer, Name: name}
			if err := m.store.CreateGroup(ctx, group); err != nil {
				return nil, fmt.Errorf("auth: gruppe %q anlegen: %w", name, err)
			}
		} else if err != nil {
			return nil, err
		}
		ids = append(ids, group.ID)
	}
	return ids, nil
}
