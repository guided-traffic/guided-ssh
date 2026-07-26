package store

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// CreateUser creates a user and fills in the ID and timestamp.
func (s *Store) CreateUser(ctx context.Context, u *User) error {
	created, err := queryOne[User](ctx, s.pool, `
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

// GetUser returns a user by ID.
func (s *Store) GetUser(ctx context.Context, id uuid.UUID) (*User, error) {
	return queryOne[User](ctx, s.pool, `SELECT * FROM users WHERE id = $1`, id)
}

// GetUserBySubject returns a user by IdP identity (issuer, sub).
func (s *Store) GetUserBySubject(ctx context.Context, issuer, subject string) (*User, error) {
	return queryOne[User](ctx, s.pool,
		`SELECT * FROM users WHERE issuer = $1 AND subject = $2`, issuer, subject)
}

// ListUsers returns all users.
func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	return queryAll[User](ctx, s.pool, `SELECT * FROM users ORDER BY username, id`)
}

// UserDetailed is a user including its group names (for the web UI, phase 8).
type UserDetailed struct {
	User
	Groups []string `db:"groups"`
}

// ListUsersDetailed returns all users including their group names.
func (s *Store) ListUsersDetailed(ctx context.Context) ([]UserDetailed, error) {
	return queryAll[UserDetailed](ctx, s.pool, `
		SELECT u.*,
			COALESCE((SELECT array_agg(g.name ORDER BY g.name)
				FROM user_groups ug
				JOIN groups g ON g.id = ug.group_id
				WHERE ug.user_id = u.id), '{}') AS groups
		FROM users u
		ORDER BY u.username, u.id`)
}

// UpdateUser updates the mutable fields of a user.
func (s *Store) UpdateUser(ctx context.Context, u *User) error {
	updated, err := queryOne[User](ctx, s.pool, `
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

// DeleteUser removes a user (group memberships cascade).
func (s *Store) DeleteUser(ctx context.Context, id uuid.UUID) error {
	return s.execAffectingOne(ctx, `DELETE FROM users WHERE id = $1`, id)
}

// SetUserGroups atomically replaces the group memberships of a user
// (target state from the IdP sync).
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

// ListUserGroups returns the groups of a user.
func (s *Store) ListUserGroups(ctx context.Context, userID uuid.UUID) ([]Group, error) {
	return queryAll[Group](ctx, s.pool, `
		SELECT g.*
		FROM groups g
		JOIN user_groups ug ON ug.group_id = g.id
		WHERE ug.user_id = $1
		ORDER BY g.name`, userID)
}
