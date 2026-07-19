package store

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// CreateUser legt einen Benutzer an und füllt ID und Zeitstempel.
func (s *Store) CreateUser(ctx context.Context, u *User) error {
	created, err := queryOne[User](ctx, s, `
		INSERT INTO users (issuer, subject, username, email, uid, gid, active)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING *`,
		u.Issuer, u.Subject, u.Username, u.Email, u.UID, u.GID, u.Active)
	if err != nil {
		return err
	}
	*u = *created
	return nil
}

// GetUser liefert einen Benutzer per ID.
func (s *Store) GetUser(ctx context.Context, id uuid.UUID) (*User, error) {
	return queryOne[User](ctx, s, `SELECT * FROM users WHERE id = $1`, id)
}

// GetUserBySubject liefert einen Benutzer per IdP-Identität (issuer, sub).
func (s *Store) GetUserBySubject(ctx context.Context, issuer, subject string) (*User, error) {
	return queryOne[User](ctx, s,
		`SELECT * FROM users WHERE issuer = $1 AND subject = $2`, issuer, subject)
}

// ListUsers liefert alle Benutzer.
func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	return queryAll[User](ctx, s, `SELECT * FROM users ORDER BY username, id`)
}

// UpdateUser aktualisiert die veränderlichen Felder eines Benutzers.
func (s *Store) UpdateUser(ctx context.Context, u *User) error {
	updated, err := queryOne[User](ctx, s, `
		UPDATE users
		SET username = $2, email = $3, uid = $4, gid = $5, active = $6, updated_at = now()
		WHERE id = $1
		RETURNING *`,
		u.ID, u.Username, u.Email, u.UID, u.GID, u.Active)
	if err != nil {
		return err
	}
	*u = *updated
	return nil
}

// DeleteUser entfernt einen Benutzer (Gruppenzuordnungen kaskadieren).
func (s *Store) DeleteUser(ctx context.Context, id uuid.UUID) error {
	return s.execAffectingOne(ctx, `DELETE FROM users WHERE id = $1`, id)
}

// SetUserGroups ersetzt die Gruppenzugehörigkeiten eines Benutzers atomar
// (Zielzustand aus dem IdP-Sync).
func (s *Store) SetUserGroups(ctx context.Context, userID uuid.UUID, groupIDs []uuid.UUID) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM user_groups WHERE user_id = $1`, userID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO user_groups (user_id, group_id)
			SELECT $1, unnest($2::uuid[])`, userID, groupIDs)
		return err
	})
}

// ListUserGroups liefert die Gruppen eines Benutzers.
func (s *Store) ListUserGroups(ctx context.Context, userID uuid.UUID) ([]Group, error) {
	return queryAll[Group](ctx, s, `
		SELECT g.*
		FROM groups g
		JOIN user_groups ug ON ug.group_id = g.id
		WHERE ug.user_id = $1
		ORDER BY g.name`, userID)
}
