// Package store implements the PostgreSQL persistence layer:
// schema migrations (goose, embedded) and repository functions (pgx).
package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound is returned when a record does not exist.
var ErrNotFound = errors.New("store: not found")

// Store bundles access to PostgreSQL via a connection pool.
type Store struct {
	pool *pgxpool.Pool
}

// New opens a pool and checks the connection.
func New(ctx context.Context, dsn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("check connection: %w", err)
	}
	return &Store{pool: pool}, nil
}

// Close closes the connection pool.
func (s *Store) Close() {
	s.pool.Close()
}

// notFound maps pgx.ErrNoRows to ErrNotFound.
func notFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}
