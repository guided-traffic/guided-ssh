package store

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Audit-Events für CI-Grant-Änderungen (Phase 7): wie Gruppen-Grants ist jede
// Mutation einem Actor zuordenbar und wird transaktional geschrieben.
const (
	EventCIGrantCreated = "ci_grant.created"
	EventCIGrantUpdated = "ci_grant.updated"
	EventCIGrantDeleted = "ci_grant.deleted"
)

// CIGrant ist eine Zugriffsregel für GitLab-CI-Pipelines (ADR-019):
// Projekt/Gruppe × Ref-Bedingung × Tag-Selektor → Ziel-Principals.
type CIGrant struct {
	ID uuid.UUID `db:"id"`
	// ProjectPath ist der GitLab-Projekt- oder Namespace-Pfad; matcht exakt
	// oder als Namespace-Präfix ("infra" deckt "infra/ansible" ab).
	ProjectPath string `db:"project_path"`
	// RefPattern ist ein Glob über den Ref-Namen ('*' matcht beliebig,
	// auch '/'); leer = alle Refs.
	RefPattern string `db:"ref_pattern"`
	// ProtectedOnly beschränkt den Grant auf geschützte Refs (ref_protected).
	ProtectedOnly bool `db:"protected_only"`
	// EnvironmentPattern ist ein Glob über den environment-Claim; leer =
	// keine Bedingung (matcht auch Jobs ohne Environment).
	EnvironmentPattern string `db:"environment_pattern"`
	// TagSelector muss Teilmenge der Host-Tags sein (leer = alle Hosts).
	TagSelector map[string]string `db:"tag_selector"`
	// Principals sind die lokalen Ziel-Benutzer auf den Hosts.
	Principals         []string  `db:"principals"`
	MaxValiditySeconds int64     `db:"max_validity_seconds"`
	CreatedAt          time.Time `db:"created_at"`
	UpdatedAt          time.Time `db:"updated_at"`
}

// MaxValidity ist die maximale Zertifikatslaufzeit als Duration.
func (g *CIGrant) MaxValidity() time.Duration {
	return time.Duration(g.MaxValiditySeconds) * time.Second
}

// CIMatch sind die für die Grant-Auswertung relevanten Claims eines
// GitLab-Job-Tokens.
type CIMatch struct {
	ProjectPath  string
	Ref          string
	RefProtected bool
	Environment  string
}

// Matches prüft, ob der Grant auf die Job-Claims passt.
func (g *CIGrant) Matches(m CIMatch) bool {
	if !projectMatches(g.ProjectPath, m.ProjectPath) {
		return false
	}
	if g.ProtectedOnly && !m.RefProtected {
		return false
	}
	if g.RefPattern != "" && !wildcardMatch(g.RefPattern, m.Ref) {
		return false
	}
	if g.EnvironmentPattern != "" && !wildcardMatch(g.EnvironmentPattern, m.Environment) {
		return false
	}
	return true
}

// projectMatches: exakter Pfad oder Namespace-Präfix (Grenze an '/').
func projectMatches(grantPath, projectPath string) bool {
	return grantPath == projectPath || strings.HasPrefix(projectPath, grantPath+"/")
}

// wildcardMatch matcht value gegen ein Glob-Muster, in dem '*' beliebige
// Zeichen (auch '/') überspannt; andere Zeichen matchen wörtlich.
func wildcardMatch(pattern, value string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == value
	}
	if !strings.HasPrefix(value, parts[0]) {
		return false
	}
	value = value[len(parts[0]):]
	for _, part := range parts[1 : len(parts)-1] {
		idx := strings.Index(value, part)
		if idx < 0 {
			return false
		}
		value = value[idx+len(part):]
	}
	return strings.HasSuffix(value, parts[len(parts)-1])
}

// ciGrantAuditEvent baut das Audit-Event zu einer CI-Grant-Änderung.
func ciGrantAuditEvent(eventType, actor string, g *CIGrant) (*AuditEvent, error) {
	payload, err := json.Marshal(map[string]any{
		"ci_grant_id":          g.ID,
		"project_path":         g.ProjectPath,
		"ref_pattern":          g.RefPattern,
		"protected_only":       g.ProtectedOnly,
		"environment_pattern":  g.EnvironmentPattern,
		"tag_selector":         g.TagSelector,
		"principals":           g.Principals,
		"max_validity_seconds": g.MaxValiditySeconds,
	})
	if err != nil {
		return nil, err
	}
	return &AuditEvent{EventType: eventType, Actor: actor, Payload: payload}, nil
}

// createCIGrantTx legt eine CI-Zugriffsregel innerhalb der Transaktion an und
// schreibt das Audit-Event.
func createCIGrantTx(ctx context.Context, tx pgx.Tx, actor string, g *CIGrant) error {
	if g.TagSelector == nil {
		g.TagSelector = map[string]string{}
	}
	created, err := queryOne[CIGrant](ctx, tx, `
		INSERT INTO ci_grants (project_path, ref_pattern, protected_only,
		                       environment_pattern, tag_selector, principals,
		                       max_validity_seconds)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING *`,
		g.ProjectPath, g.RefPattern, g.ProtectedOnly, g.EnvironmentPattern,
		g.TagSelector, g.Principals, g.MaxValiditySeconds)
	if err != nil {
		return err
	}
	*g = *created
	event, err := ciGrantAuditEvent(EventCIGrantCreated, actor, g)
	if err != nil {
		return err
	}
	return insertAuditEvent(ctx, tx, event)
}

// CreateCIGrant legt eine CI-Zugriffsregel an (füllt ID und Zeitstempel) und
// schreibt transaktional ein Audit-Event mit dem Actor.
func (s *Store) CreateCIGrant(ctx context.Context, actor string, g *CIGrant) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		return createCIGrantTx(ctx, tx, actor, g)
	})
}

// GetCIGrant liefert eine CI-Zugriffsregel per ID.
func (s *Store) GetCIGrant(ctx context.Context, id uuid.UUID) (*CIGrant, error) {
	return queryOne[CIGrant](ctx, s.pool, `SELECT * FROM ci_grants WHERE id = $1`, id)
}

// ListCIGrants liefert alle CI-Zugriffsregeln.
func (s *Store) ListCIGrants(ctx context.Context) ([]CIGrant, error) {
	return queryAll[CIGrant](ctx, s.pool, `
		SELECT * FROM ci_grants ORDER BY project_path, created_at, id`)
}

// MatchCIGrants liefert alle CI-Zugriffsregeln, die auf die Job-Claims passen
// (Auswertung bei Zertifikatsausstellung). Kandidaten kommen per Projekt-
// bzw. Namespace-Match aus der Datenbank, die Ref-/Environment-Bedingungen
// werden in Go geprüft.
func (s *Store) MatchCIGrants(ctx context.Context, m CIMatch) ([]CIGrant, error) {
	candidates, err := queryAll[CIGrant](ctx, s.pool, `
		SELECT * FROM ci_grants
		WHERE project_path = $1 OR $1 LIKE project_path || '/%'
		ORDER BY created_at, id`, m.ProjectPath)
	if err != nil {
		return nil, err
	}
	matched := make([]CIGrant, 0, len(candidates))
	for _, g := range candidates {
		if g.Matches(m) {
			matched = append(matched, g)
		}
	}
	return matched, nil
}

// updateCIGrantTx aktualisiert eine CI-Zugriffsregel innerhalb der Transaktion.
func updateCIGrantTx(ctx context.Context, tx pgx.Tx, actor string, g *CIGrant) error {
	if g.TagSelector == nil {
		g.TagSelector = map[string]string{}
	}
	updated, err := queryOne[CIGrant](ctx, tx, `
		UPDATE ci_grants
		SET ref_pattern = $2, protected_only = $3, environment_pattern = $4,
		    tag_selector = $5, principals = $6, max_validity_seconds = $7,
		    updated_at = now()
		WHERE id = $1
		RETURNING *`,
		g.ID, g.RefPattern, g.ProtectedOnly, g.EnvironmentPattern,
		g.TagSelector, g.Principals, g.MaxValiditySeconds)
	if err != nil {
		return err
	}
	*g = *updated
	event, err := ciGrantAuditEvent(EventCIGrantUpdated, actor, g)
	if err != nil {
		return err
	}
	return insertAuditEvent(ctx, tx, event)
}

// UpdateCIGrant aktualisiert die veränderlichen Felder einer CI-Zugriffsregel
// (project_path ist Identität und bleibt fix) und schreibt transaktional ein
// Audit-Event mit dem Actor.
func (s *Store) UpdateCIGrant(ctx context.Context, actor string, g *CIGrant) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		return updateCIGrantTx(ctx, tx, actor, g)
	})
}

// deleteCIGrantTx entfernt eine CI-Zugriffsregel innerhalb der Transaktion.
func deleteCIGrantTx(ctx context.Context, tx pgx.Tx, actor string, id uuid.UUID) error {
	deleted, err := queryOne[CIGrant](ctx, tx,
		`DELETE FROM ci_grants WHERE id = $1 RETURNING *`, id)
	if err != nil {
		return err
	}
	event, err := ciGrantAuditEvent(EventCIGrantDeleted, actor, deleted)
	if err != nil {
		return err
	}
	return insertAuditEvent(ctx, tx, event)
}

// DeleteCIGrant entfernt eine CI-Zugriffsregel und schreibt transaktional ein
// Audit-Event mit dem Actor.
func (s *Store) DeleteCIGrant(ctx context.Context, actor string, id uuid.UUID) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		return deleteCIGrantTx(ctx, tx, actor, id)
	})
}

// CIGrantSpec ist eine deklarative CI-Zugriffsregel (YAML-Import/Apply).
type CIGrantSpec struct {
	ProjectPath        string
	RefPattern         string
	ProtectedOnly      bool
	EnvironmentPattern string
	TagSelector        map[string]string
	Principals         []string
	MaxValiditySeconds int64
}

// ciGrantKey identifiziert einen CI-Grant für den deklarativen Abgleich über
// seine vollständige Bedingung (Projekt, Ref-/Environment-Muster, Selektor).
func ciGrantKey(projectPath, refPattern string, protectedOnly bool, envPattern string, selector map[string]string) (string, error) {
	if selector == nil {
		selector = map[string]string{}
	}
	canonical, err := json.Marshal(selector)
	if err != nil {
		return "", err
	}
	return strings.Join([]string{
		projectPath, refPattern, fmt.Sprintf("%t", protectedOnly), envPattern, string(canonical),
	}, "\x00"), nil
}

// validateCIGrantSpec prüft Pflichtfelder einer deklarativen CI-Zugriffsregel;
// Verstöße wrappen ErrInvalidGrantSpec (Client-Fehler).
func validateCIGrantSpec(index int, spec CIGrantSpec) error {
	fail := func(reason string) error {
		return fmt.Errorf("store: %w: ci-grant %d (projekt %q): %s",
			ErrInvalidGrantSpec, index+1, spec.ProjectPath, reason)
	}
	if spec.ProjectPath == "" {
		return fail("project fehlt")
	}
	if len(spec.Principals) == 0 {
		return fail("principals fehlen")
	}
	if spec.MaxValiditySeconds <= 0 {
		return fail("max_validity muss größer 0 sein")
	}
	return nil
}

// ApplyCIGrants gleicht den CI-Grant-Bestand deklarativ mit specs ab (GitOps):
// Identität ist die vollständige Bedingung (Projekt, Ref-/Environment-Muster,
// Tag-Selektor) — neue werden angelegt, abweichende aktualisiert, nicht mehr
// deklarierte gelöscht. Alles läuft in einer Transaktion; jede Änderung
// erzeugt ein Audit-Event mit dem Actor.
func (s *Store) ApplyCIGrants(ctx context.Context, actor string, specs []CIGrantSpec) (*ApplyResult, error) {
	result := &ApplyResult{}
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		existing, err := queryAll[CIGrant](ctx, tx, `
			SELECT * FROM ci_grants ORDER BY created_at, id`)
		if err != nil {
			return err
		}
		byKey := map[string][]CIGrant{}
		for _, grant := range existing {
			key, err := ciGrantKey(grant.ProjectPath, grant.RefPattern,
				grant.ProtectedOnly, grant.EnvironmentPattern, grant.TagSelector)
			if err != nil {
				return err
			}
			byKey[key] = append(byKey[key], grant)
		}

		seen := map[string]bool{}
		for i, spec := range specs {
			if err := validateCIGrantSpec(i, spec); err != nil {
				return err
			}
			key, err := ciGrantKey(spec.ProjectPath, spec.RefPattern,
				spec.ProtectedOnly, spec.EnvironmentPattern, spec.TagSelector)
			if err != nil {
				return err
			}
			if seen[key] {
				return fmt.Errorf("store: %w: ci-grant %d (projekt %q): doppelter eintrag für dieselbe bedingung",
					ErrInvalidGrantSpec, i+1, spec.ProjectPath)
			}
			seen[key] = true

			if err := applyCISpecTx(ctx, tx, actor, spec, byKey[key], result); err != nil {
				return err
			}
			delete(byKey, key)
		}

		for _, grants := range byKey {
			for _, grant := range grants {
				if err := deleteCIGrantTx(ctx, tx, actor, grant.ID); err != nil {
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

// applyCISpecTx wendet eine einzelne CI-Spec gegen den Bestand an: vorhandener
// Grant wird aktualisiert (Duplikate gelöscht), fehlender angelegt.
func applyCISpecTx(ctx context.Context, tx pgx.Tx, actor string, spec CIGrantSpec, candidates []CIGrant, result *ApplyResult) error {
	if len(candidates) == 0 {
		grant := &CIGrant{
			ProjectPath:        spec.ProjectPath,
			RefPattern:         spec.RefPattern,
			ProtectedOnly:      spec.ProtectedOnly,
			EnvironmentPattern: spec.EnvironmentPattern,
			TagSelector:        spec.TagSelector,
			Principals:         spec.Principals,
			MaxValiditySeconds: spec.MaxValiditySeconds,
		}
		if err := createCIGrantTx(ctx, tx, actor, grant); err != nil {
			return err
		}
		result.Created++
		return nil
	}

	current := candidates[0]
	for _, dup := range candidates[1:] {
		if err := deleteCIGrantTx(ctx, tx, actor, dup.ID); err != nil {
			return err
		}
		result.Deleted++
	}
	if slices.Equal(current.Principals, spec.Principals) &&
		current.MaxValiditySeconds == spec.MaxValiditySeconds {
		result.Unchanged++
		return nil
	}
	current.Principals = spec.Principals
	current.MaxValiditySeconds = spec.MaxValiditySeconds
	if err := updateCIGrantTx(ctx, tx, actor, &current); err != nil {
		return err
	}
	result.Updated++
	return nil
}
