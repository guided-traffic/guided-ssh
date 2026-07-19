// Package store implementiert den PostgreSQL-Persistenz-Layer:
// Schema-Migrationen (goose, embedded) und Repository-Funktionen (pgx).
package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound wird zurückgegeben, wenn ein Datensatz nicht existiert.
var ErrNotFound = errors.New("store: not found")

// Store bündelt den Zugriff auf PostgreSQL über einen Connection-Pool.
type Store struct {
	pool *pgxpool.Pool
}

// New öffnet einen Pool und prüft die Verbindung.
func New(ctx context.Context, dsn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("pool erstellen: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("verbindung prüfen: %w", err)
	}
	return &Store{pool: pool}, nil
}

// Close schließt den Connection-Pool.
func (s *Store) Close() {
	s.pool.Close()
}

// notFound mappt pgx.ErrNoRows auf ErrNotFound.
func notFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}
