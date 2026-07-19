package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/guided-traffic/guided-ssh/internal/store"
)

// Audit-Event-Typen des Gruppen-Syncs.
const (
	EventUserDeactivated = "auth.user_deactivated"
	EventUserReactivated = "auth.user_reactivated"
)

// DirectoryUser ist der IdP-Zustand eines Benutzers aus Sicht der
// Directory-API.
type DirectoryUser struct {
	Subject  string
	Username string
	Email    string
	Groups   []string
	Active   bool
}

// DirectorySource liefert den aktuellen Benutzer- und Gruppenzustand des IdP
// (z. B. via Keycloak-Admin-API). Der Sync gleicht die Datenbank dagegen ab.
type DirectorySource interface {
	// Issuer ist die Issuer-URL, deren Benutzer diese Source verwaltet.
	Issuer() string
	// Users liefert alle Benutzer des IdP inkl. Gruppen.
	Users(ctx context.Context) ([]DirectoryUser, error)
}

// Syncer gleicht in festen Intervallen die lokalen Benutzer/Gruppen mit dem IdP ab.
// Aus dem IdP entfernte oder deaktivierte Benutzer werden deaktiviert und
// verlieren ihre Gruppen — das wirkt sofort auf Neuausstellung
// (Mapper.EnsureUser weist deaktivierte Benutzer ab) und auf Host-ACLs
// (die aus denselben Tabellen gespeist werden, Phase 5/6).
type Syncer struct {
	store  Store
	source DirectorySource
	logger *slog.Logger
}

// NewSyncer baut einen Syncer über Store und Directory-Source.
func NewSyncer(st Store, source DirectorySource, logger *slog.Logger) *Syncer {
	return &Syncer{store: st, source: source, logger: logger}
}

// Run synchronisiert sofort und dann in jedem Intervall, bis der Kontext
// endet. Fehler einzelner Läufe werden geloggt, brechen den Loop aber nicht ab.
func (s *Syncer) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := s.SyncOnce(ctx); err != nil && ctx.Err() == nil {
			s.logger.Error("gruppen-sync fehlgeschlagen", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// SyncOnce führt einen einzelnen Abgleich durch. Nur bereits bekannte
// Benutzer werden abgeglichen — neue IdP-Benutzer entstehen erst beim ersten
// Login (Mapper.EnsureUser).
func (s *Syncer) SyncOnce(ctx context.Context) error {
	directory, err := s.source.Users(ctx)
	if err != nil {
		return fmt.Errorf("auth: idp-benutzer laden: %w", err)
	}
	bySubject := make(map[string]DirectoryUser, len(directory))
	for _, du := range directory {
		bySubject[du.Subject] = du
	}

	users, err := s.store.ListUsers(ctx)
	if err != nil {
		return fmt.Errorf("auth: lokale benutzer laden: %w", err)
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

// deactivate setzt den Benutzer inaktiv und entzieht alle Gruppen.
func (s *Syncer) deactivate(ctx context.Context, user *store.User) error {
	if !user.Active {
		return nil
	}
	user.Active = false
	if err := s.store.UpdateUser(ctx, user); err != nil {
		return fmt.Errorf("auth: benutzer %s deaktivieren: %w", user.Subject, err)
	}
	if err := s.store.SetUserGroups(ctx, user.ID, nil); err != nil {
		return fmt.Errorf("auth: gruppen von %s entziehen: %w", user.Subject, err)
	}
	return s.audit(ctx, EventUserDeactivated, user)
}

// reconcile gleicht Stammdaten, Aktiv-Status und Gruppen eines Benutzers mit
// dem IdP-Zustand ab.
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
			return fmt.Errorf("auth: benutzer %s aktualisieren: %w", user.Subject, err)
		}
	}

	groupIDs, err := (&Mapper{store: s.store}).ensureGroups(ctx, user.Issuer, normalizeGroups(du.Groups))
	if err != nil {
		return err
	}
	if err := s.store.SetUserGroups(ctx, user.ID, groupIDs); err != nil {
		return fmt.Errorf("auth: gruppen von %s setzen: %w", user.Subject, err)
	}
	if reactivated {
		return s.audit(ctx, EventUserReactivated, user)
	}
	return nil
}

// audit schreibt ein Sync-Audit-Event für den Benutzer.
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
