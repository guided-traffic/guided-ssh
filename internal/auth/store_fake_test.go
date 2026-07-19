package auth_test

import (
	"context"
	"fmt"
	"sync"

	"github.com/google/uuid"

	"github.com/guided-traffic/guided-ssh/internal/store"
)

// fakeAuthStore ist ein In-Memory-Fake der auth.Store-Schnittstelle
// (mutex-geschützt, da der Syncer-Test nebenläufig zugreift).
type fakeAuthStore struct {
	mu         sync.Mutex
	users      map[uuid.UUID]*store.User
	groups     map[uuid.UUID]*store.Group
	userGroups map[uuid.UUID][]uuid.UUID
	audits     []store.AuditEvent

	// failOn lässt die benannte Methode fehlschlagen (Fehlerpfade).
	failOn string
}

var errFakeStore = fmt.Errorf("fake-store-fehler")

func newFakeAuthStore() *fakeAuthStore {
	return &fakeAuthStore{
		users:      map[uuid.UUID]*store.User{},
		groups:     map[uuid.UUID]*store.Group{},
		userGroups: map[uuid.UUID][]uuid.UUID{},
	}
}

func (f *fakeAuthStore) fail(method string) error {
	if f.failOn == method {
		return errFakeStore
	}
	return nil
}

func (f *fakeAuthStore) GetUserBySubject(_ context.Context, issuer, subject string) (*store.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail("GetUserBySubject"); err != nil {
		return nil, err
	}
	for _, u := range f.users {
		if u.Issuer == issuer && u.Subject == subject {
			copied := *u
			return &copied, nil
		}
	}
	return nil, store.ErrNotFound
}

func (f *fakeAuthStore) CreateUser(_ context.Context, u *store.User) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail("CreateUser"); err != nil {
		return err
	}
	u.ID = uuid.New()
	copied := *u
	f.users[u.ID] = &copied
	return nil
}

func (f *fakeAuthStore) UpdateUser(_ context.Context, u *store.User) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail("UpdateUser"); err != nil {
		return err
	}
	if _, ok := f.users[u.ID]; !ok {
		return store.ErrNotFound
	}
	copied := *u
	f.users[u.ID] = &copied
	return nil
}

func (f *fakeAuthStore) ListUsers(context.Context) ([]store.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail("ListUsers"); err != nil {
		return nil, err
	}
	out := make([]store.User, 0, len(f.users))
	for _, u := range f.users {
		out = append(out, *u)
	}
	return out, nil
}

func (f *fakeAuthStore) SetUserGroups(_ context.Context, userID uuid.UUID, groupIDs []uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail("SetUserGroups"); err != nil {
		return err
	}
	f.userGroups[userID] = groupIDs
	return nil
}

func (f *fakeAuthStore) GetGroupByName(_ context.Context, issuer, name string) (*store.Group, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail("GetGroupByName"); err != nil {
		return nil, err
	}
	for _, g := range f.groups {
		if g.Issuer == issuer && g.Name == name {
			copied := *g
			return &copied, nil
		}
	}
	return nil, store.ErrNotFound
}

func (f *fakeAuthStore) CreateGroup(_ context.Context, g *store.Group) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail("CreateGroup"); err != nil {
		return err
	}
	g.ID = uuid.New()
	copied := *g
	f.groups[g.ID] = &copied
	return nil
}

func (f *fakeAuthStore) AppendAuditEvent(_ context.Context, e *store.AuditEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail("AppendAuditEvent"); err != nil {
		return err
	}
	f.audits = append(f.audits, *e)
	return nil
}

// auditCount liefert die Anzahl der Audit-Events (nebenläufigkeitssicher).
func (f *fakeAuthStore) auditCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.audits)
}

// groupNames liefert die Gruppennamen eines Benutzers (sortierfrei).
func (f *fakeAuthStore) groupNames(userID uuid.UUID) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var names []string
	for _, id := range f.userGroups[userID] {
		if g, ok := f.groups[id]; ok {
			names = append(names, g.Name)
		}
	}
	return names
}
