package store

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// querier abstrahiert Pool und Transaktion, damit Repository-Helfer in beiden
// Kontexten laufen (pgxpool.Pool und pgx.Tx erfüllen das Interface).
type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// queryOne führt eine Query aus, die genau eine Zeile liefert, und mappt sie
// per Spaltenname auf T. Keine Zeile ⇒ ErrNotFound.
func queryOne[T any](ctx context.Context, q querier, sql string, args ...any) (*T, error) {
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	v, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByName[T])
	if err != nil {
		return nil, notFound(err)
	}
	return &v, nil
}

// queryAll führt eine Query aus und mappt alle Zeilen per Spaltenname auf T.
func queryAll[T any](ctx context.Context, q querier, sql string, args ...any) ([]T, error) {
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByName[T])
}

// execAffectingOne führt ein Statement aus, das genau eine Zeile treffen muss
// (UPDATE/DELETE per Schlüssel). Keine getroffene Zeile ⇒ ErrNotFound.
func (s *Store) execAffectingOne(ctx context.Context, sql string, args ...any) error {
	tag, err := s.pool.Exec(ctx, sql, args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
