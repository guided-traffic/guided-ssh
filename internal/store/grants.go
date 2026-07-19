package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Audit-Events für Grant-Änderungen (Phase 6): jede Mutation ist einem Actor
// zuordenbar und wird transaktional mit der Änderung geschrieben.
const (
	EventGrantCreated = "grant.created"
	EventGrantUpdated = "grant.updated"
	EventGrantDeleted = "grant.deleted"
)

// grantAuditEvent baut das Audit-Event zu einer Grant-Änderung.
func grantAuditEvent(eventType, actor string, g *AccessGrant) (*AuditEvent, error) {
	payload, err := json.Marshal(map[string]any{
		"grant_id":             g.ID,
		"group_id":             g.GroupID,
		"tag_selector":         g.TagSelector,
		"principals":           g.Principals,
		"sudo":                 g.Sudo,
		"max_validity_seconds": g.MaxValiditySeconds,
	})
	if err != nil {
		return nil, err
	}
	return &AuditEvent{EventType: eventType, Actor: actor, Payload: payload}, nil
}

// createGrantTx legt eine Zugriffsregel innerhalb der Transaktion an und
// schreibt das Audit-Event.
func createGrantTx(ctx context.Context, tx pgx.Tx, actor string, g *AccessGrant) error {
	if g.TagSelector == nil {
		g.TagSelector = map[string]string{}
	}
	created, err := queryOne[AccessGrant](ctx, tx, `
		INSERT INTO access_grants (group_id, tag_selector, principals, sudo, max_validity_seconds)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING *`,
		g.GroupID, g.TagSelector, g.Principals, g.Sudo, g.MaxValiditySeconds)
	if err != nil {
		return err
	}
	*g = *created
	event, err := grantAuditEvent(EventGrantCreated, actor, g)
	if err != nil {
		return err
	}
	return insertAuditEvent(ctx, tx, event)
}

// CreateGrant legt eine Zugriffsregel an (füllt ID und Zeitstempel) und
// schreibt transaktional ein Audit-Event mit dem Actor.
func (s *Store) CreateGrant(ctx context.Context, actor string, g *AccessGrant) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		return createGrantTx(ctx, tx, actor, g)
	})
}

// GetGrant liefert eine Zugriffsregel per ID.
func (s *Store) GetGrant(ctx context.Context, id uuid.UUID) (*AccessGrant, error) {
	return queryOne[AccessGrant](ctx, s.pool, `SELECT * FROM access_grants WHERE id = $1`, id)
}

// GrantWithGroup ist eine Zugriffsregel inklusive Gruppenname und -Issuer
// (für API/CLI, wo Gruppen per Name statt UUID angesprochen werden).
type GrantWithGroup struct {
	AccessGrant
	GroupName   string `db:"group_name"`
	GroupIssuer string `db:"group_issuer"`
}

// GetGrantDetailed liefert eine Zugriffsregel inklusive Gruppeninfo.
func (s *Store) GetGrantDetailed(ctx context.Context, id uuid.UUID) (*GrantWithGroup, error) {
	return queryOne[GrantWithGroup](ctx, s.pool, `
		SELECT g.*, gr.name AS group_name, gr.issuer AS group_issuer
		FROM access_grants g
		JOIN groups gr ON gr.id = g.group_id
		WHERE g.id = $1`, id)
}

// ListGrantsDetailed liefert alle Zugriffsregeln inklusive Gruppeninfo.
func (s *Store) ListGrantsDetailed(ctx context.Context) ([]GrantWithGroup, error) {
	return queryAll[GrantWithGroup](ctx, s.pool, `
		SELECT g.*, gr.name AS group_name, gr.issuer AS group_issuer
		FROM access_grants g
		JOIN groups gr ON gr.id = g.group_id
		ORDER BY gr.name, g.created_at, g.id`)
}

// ListGrants liefert alle Zugriffsregeln.
func (s *Store) ListGrants(ctx context.Context) ([]AccessGrant, error) {
	return queryAll[AccessGrant](ctx, s.pool, `SELECT * FROM access_grants ORDER BY created_at, id`)
}

// ListGrantsForGroups liefert alle Zugriffsregeln der angegebenen Gruppen.
func (s *Store) ListGrantsForGroups(ctx context.Context, groupIDs []uuid.UUID) ([]AccessGrant, error) {
	return queryAll[AccessGrant](ctx, s.pool, `
		SELECT * FROM access_grants
		WHERE group_id = ANY ($1::uuid[])
		ORDER BY created_at, id`, groupIDs)
}

// ListGrantsForUser liefert alle Zugriffsregeln, die über eine
// Gruppenmitgliedschaft für diesen Benutzer gelten (Auswertung bei
// Zertifikatsausstellung).
func (s *Store) ListGrantsForUser(ctx context.Context, userID uuid.UUID) ([]AccessGrant, error) {
	return queryAll[AccessGrant](ctx, s.pool, `
		SELECT g.* FROM access_grants g
		JOIN user_groups ug ON ug.group_id = g.group_id
		WHERE ug.user_id = $1
		ORDER BY g.created_at, g.id`, userID)
}

// UpdateGrant aktualisiert die veränderlichen Felder einer Zugriffsregel und
// schreibt transaktional ein Audit-Event mit dem Actor.
func (s *Store) UpdateGrant(ctx context.Context, actor string, g *AccessGrant) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		return updateGrantTx(ctx, tx, actor, g)
	})
}

// updateGrantTx aktualisiert eine Zugriffsregel innerhalb der Transaktion.
func updateGrantTx(ctx context.Context, tx pgx.Tx, actor string, g *AccessGrant) error {
	if g.TagSelector == nil {
		g.TagSelector = map[string]string{}
	}
	updated, err := queryOne[AccessGrant](ctx, tx, `
		UPDATE access_grants
		SET tag_selector = $2, principals = $3, sudo = $4, max_validity_seconds = $5, updated_at = now()
		WHERE id = $1
		RETURNING *`,
		g.ID, g.TagSelector, g.Principals, g.Sudo, g.MaxValiditySeconds)
	if err != nil {
		return err
	}
	*g = *updated
	event, err := grantAuditEvent(EventGrantUpdated, actor, g)
	if err != nil {
		return err
	}
	return insertAuditEvent(ctx, tx, event)
}

// DeleteGrant entfernt eine Zugriffsregel und schreibt transaktional ein
// Audit-Event mit dem Actor.
func (s *Store) DeleteGrant(ctx context.Context, actor string, id uuid.UUID) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		return deleteGrantTx(ctx, tx, actor, id)
	})
}

// deleteGrantTx entfernt eine Zugriffsregel innerhalb der Transaktion.
func deleteGrantTx(ctx context.Context, tx pgx.Tx, actor string, id uuid.UUID) error {
	deleted, err := queryOne[AccessGrant](ctx, tx,
		`DELETE FROM access_grants WHERE id = $1 RETURNING *`, id)
	if err != nil {
		return err
	}
	event, err := grantAuditEvent(EventGrantDeleted, actor, deleted)
	if err != nil {
		return err
	}
	return insertAuditEvent(ctx, tx, event)
}

// ErrInvalidGrantSpec: eine deklarative Zugriffsregel ist unvollständig oder
// widersprüchlich (Client-Fehler, kein technischer Fehler).
var ErrInvalidGrantSpec = errors.New("ungültige grant-spezifikation")

// GrantSpec ist eine deklarative Zugriffsregel (YAML-Import/Apply): die
// Gruppe wird per Name referenziert und bei Bedarf angelegt.
type GrantSpec struct {
	// Group ist der Gruppenname im IdP.
	Group string
	// Issuer der Gruppe; leer ⇒ DefaultIssuer des Aufrufs.
	Issuer string
	// TagSelector muss Teilmenge der Host-Tags sein (leer = alle Hosts).
	TagSelector map[string]string
	// Principals sind die lokalen Ziel-Benutzer auf den Hosts.
	Principals []string
	// Sudo markiert den Grant für sudo-Berechtigung (Durchsetzung Phase 9).
	Sudo bool
	// MaxValiditySeconds ist die maximale Zertifikatslaufzeit.
	MaxValiditySeconds int64
}

// ApplyResult fasst einen deklarativen Grant-Abgleich zusammen.
type ApplyResult struct {
	Created   int `json:"created"`
	Updated   int `json:"updated"`
	Deleted   int `json:"deleted"`
	Unchanged int `json:"unchanged"`
}

// grantKey identifiziert einen Grant für den deklarativen Abgleich:
// Issuer + Gruppenname + kanonischer Tag-Selektor (JSON sortiert Map-Keys).
func grantKey(issuer, group string, selector map[string]string) (string, error) {
	if selector == nil {
		selector = map[string]string{}
	}
	canonical, err := json.Marshal(selector)
	if err != nil {
		return "", err
	}
	return issuer + "\x00" + group + "\x00" + string(canonical), nil
}

// ApplyGrants gleicht den Grant-Bestand deklarativ mit specs ab (GitOps):
// Grants werden über (Issuer, Gruppe, Tag-Selektor) identifiziert — neue
// werden angelegt, abweichende aktualisiert, nicht mehr deklarierte gelöscht.
// Unbekannte Gruppen werden angelegt (der IdP-Sync verknüpft Mitglieder,
// sobald die Gruppe dort existiert). Alles läuft in einer Transaktion; jede
// Änderung erzeugt ein Audit-Event mit dem Actor.
func (s *Store) ApplyGrants(ctx context.Context, actor, defaultIssuer string, specs []GrantSpec) (*ApplyResult, error) {
	result := &ApplyResult{}
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		existing, err := queryAll[GrantWithGroup](ctx, tx, `
			SELECT g.*, gr.name AS group_name, gr.issuer AS group_issuer
			FROM access_grants g
			JOIN groups gr ON gr.id = g.group_id
			ORDER BY g.created_at, g.id`)
		if err != nil {
			return err
		}
		// Bestand nach Schlüssel gruppieren; mehrere Grants pro Schlüssel sind
		// Duplikate — der älteste wird Update-Kandidat, der Rest gelöscht.
		byKey := map[string][]GrantWithGroup{}
		for _, grant := range existing {
			key, err := grantKey(grant.GroupIssuer, grant.GroupName, grant.TagSelector)
			if err != nil {
				return err
			}
			byKey[key] = append(byKey[key], grant)
		}

		seen := map[string]bool{}
		for i, spec := range specs {
			issuer := spec.Issuer
			if issuer == "" {
				issuer = defaultIssuer
			}
			if err := validateGrantSpec(i, issuer, spec); err != nil {
				return err
			}
			key, err := grantKey(issuer, spec.Group, spec.TagSelector)
			if err != nil {
				return err
			}
			if seen[key] {
				return fmt.Errorf("store: %w: grant %d (gruppe %q): doppelter eintrag für gruppe und tag-selektor",
					ErrInvalidGrantSpec, i+1, spec.Group)
			}
			seen[key] = true

			if candidates, ok := byKey[key]; ok {
				delete(byKey, key)
				current := candidates[0]
				for _, dup := range candidates[1:] {
					if err := deleteGrantTx(ctx, tx, actor, dup.ID); err != nil {
						return err
					}
					result.Deleted++
				}
				if slices.Equal(current.Principals, spec.Principals) &&
					current.Sudo == spec.Sudo &&
					current.MaxValiditySeconds == spec.MaxValiditySeconds {
					result.Unchanged++
					continue
				}
				grant := current.AccessGrant
				grant.Principals = spec.Principals
				grant.Sudo = spec.Sudo
				grant.MaxValiditySeconds = spec.MaxValiditySeconds
				if err := updateGrantTx(ctx, tx, actor, &grant); err != nil {
					return err
				}
				result.Updated++
				continue
			}

			group, err := ensureGroupTx(ctx, tx, issuer, spec.Group)
			if err != nil {
				return err
			}
			grant := &AccessGrant{
				GroupID:            group.ID,
				TagSelector:        spec.TagSelector,
				Principals:         spec.Principals,
				Sudo:               spec.Sudo,
				MaxValiditySeconds: spec.MaxValiditySeconds,
			}
			if err := createGrantTx(ctx, tx, actor, grant); err != nil {
				return err
			}
			result.Created++
		}

		for _, grants := range byKey {
			for _, grant := range grants {
				if err := deleteGrantTx(ctx, tx, actor, grant.ID); err != nil {
					return err
				}
				result.Deleted++
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// validateGrantSpec prüft Pflichtfelder einer deklarativen Zugriffsregel;
// Verstöße wrappen ErrInvalidGrantSpec (Client-Fehler).
func validateGrantSpec(index int, issuer string, spec GrantSpec) error {
	fail := func(reason string) error {
		return fmt.Errorf("store: %w: grant %d (gruppe %q): %s",
			ErrInvalidGrantSpec, index+1, spec.Group, reason)
	}
	if spec.Group == "" {
		return fail("gruppe fehlt")
	}
	if issuer == "" {
		return fail("issuer fehlt (weder im grant noch als default gesetzt)")
	}
	if len(spec.Principals) == 0 {
		return fail("principals fehlen")
	}
	if spec.MaxValiditySeconds <= 0 {
		return fail("max_validity muss größer 0 sein")
	}
	return nil
}

// ensureGroupTx löst eine Gruppe per Issuer+Name auf und legt sie bei Bedarf an.
func ensureGroupTx(ctx context.Context, tx pgx.Tx, issuer, name string) (*Group, error) {
	group, err := queryOne[Group](ctx, tx,
		`SELECT * FROM groups WHERE issuer = $1 AND name = $2`, issuer, name)
	if err == nil {
		return group, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	return queryOne[Group](ctx, tx,
		`INSERT INTO groups (issuer, name) VALUES ($1, $2) RETURNING *`, issuer, name)
}
