package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/guided-traffic/guided-ssh/internal/store"
)

// Audit event types of the group sync.
const (
	EventUserDeactivated = "auth.user_deactivated"
	EventUserReactivated = "auth.user_reactivated"
)

// DirectoryUser is a user's IdP state as seen by the directory API.
type DirectoryUser struct {
	Subject  string
	Username string
	Email    string
	Groups   []string
	Active   bool
}

// DirectorySource provides the IdP's current user and group state (e.g. via
// the Keycloak Admin API). The sync reconciles the database against it.
type DirectorySource interface {
	// Issuer is the issuer URL whose users this source manages.
	Issuer() string
	// Users returns all IdP users including groups.
	Users(ctx context.Context) ([]DirectoryUser, error)
}

// Syncer reconciles the local users/groups with the IdP at fixed intervals.
// Users removed from or deactivated in the IdP are deactivated and lose
// their groups — this immediately affects reissuance (Mapper.EnsureUser
// rejects deactivated users) and host ACLs (fed from the same tables,
// Phase 5/6).
type Syncer struct {
	store  Store
	source DirectorySource
	logger *slog.Logger
}

// NewSyncer builds a Syncer over the store and directory source.
func NewSyncer(st Store, source DirectorySource, logger *slog.Logger) *Syncer {
	return &Syncer{store: st, source: source, logger: logger}
}

// Run synchronizes immediately and then at every interval until the
// context ends. Errors from individual runs are logged but don't break the
// loop.
func (s *Syncer) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := s.SyncOnce(ctx); err != nil && ctx.Err() == nil {
			s.logger.Error("group sync failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// SyncOnce performs a single reconciliation pass. Only already-known users
// are reconciled — new IdP users are created only on their first login
// (Mapper.EnsureUser).
func (s *Syncer) SyncOnce(ctx context.Context) error {
	directory, err := s.source.Users(ctx)
	if err != nil {
		return fmt.Errorf("auth: loading idp users: %w", err)
	}
	bySubject := make(map[string]DirectoryUser, len(directory))
	for _, du := range directory {
		bySubject[du.Subject] = du
	}

	users, err := s.store.ListUsers(ctx)
	if err != nil {
		return fmt.Errorf("auth: loading local users: %w", err)
	}
	issuer := s.source.Issuer()
	for i := range users {
		user := &users[i]
		if user.Issuer != issuer {
			continue
		}
		du, found := bySubject[user.Subject]
		if !found || !du.Active {
			if err := s.deactivate(ctx, user); err != nil {
				return err
			}
			continue
		}
		if err := s.reconcile(ctx, user, du); err != nil {
			return err
		}
	}
	return nil
}

// deactivate marks the user inactive and revokes all groups.
func (s *Syncer) deactivate(ctx context.Context, user *store.User) error {
	if !user.Active {
		return nil
	}
	user.Active = false
	if err := s.store.UpdateUser(ctx, user); err != nil {
		return fmt.Errorf("auth: deactivating user %s: %w", user.Subject, err)
	}
	if err := s.store.SetUserGroups(ctx, user.ID, nil); err != nil {
		return fmt.Errorf("auth: revoking groups from %s: %w", user.Subject, err)
	}
	return s.audit(ctx, EventUserDeactivated, user)
}

// reconcile reconciles a user's profile data, active status, and groups
// with the IdP state.
func (s *Syncer) reconcile(ctx context.Context, user *store.User, du DirectoryUser) error {
	reactivated := !user.Active
	username := user.Username
	if du.Username != "" {
		username = du.Username
	}
	email := user.Email
	if du.Email != "" {
		email = du.Email
	}
	if reactivated || user.Username != username || user.Email != email {
		user.Active = true
		user.Username = username
		user.Email = email
		if err := s.store.UpdateUser(ctx, user); err != nil {
			return fmt.Errorf("auth: updating user %s: %w", user.Subject, err)
		}
	}

	groupIDs, err := (&Mapper{store: s.store}).ensureGroups(ctx, user.Issuer, normalizeGroups(du.Groups))
	if err != nil {
		return err
	}
	if err := s.store.SetUserGroups(ctx, user.ID, groupIDs); err != nil {
		return fmt.Errorf("auth: setting groups for %s: %w", user.Subject, err)
	}
	if reactivated {
		return s.audit(ctx, EventUserReactivated, user)
	}
	return nil
}

// audit writes a sync audit event for the user.
func (s *Syncer) audit(ctx context.Context, eventType string, user *store.User) error {
	payload, err := json.Marshal(map[string]any{
		"user_id": user.ID,
		"issuer":  user.Issuer,
		"subject": user.Subject,
	})
	if err != nil {
		return err
	}
	return s.store.AppendAuditEvent(ctx, &store.AuditEvent{
		EventType: eventType,
		Actor:     "group-sync",
		Payload:   payload,
	})
}
