package store

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// querier abstracts a pool and a transaction, so repository helpers run in
// both contexts (pgxpool.Pool and pgx.Tx both satisfy the interface).
type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// queryOne runs a query that returns exactly one row and maps it onto T by
// column name. No row ⇒ ErrNotFound.
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

// queryAll runs a query and maps all rows onto T by column name.
func queryAll[T any](ctx context.Context, q querier, sql string, args ...any) ([]T, error) {
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByName[T])
}

// execAffectingOne runs a statement that must affect exactly one row
// (UPDATE/DELETE by key). No affected row ⇒ ErrNotFound.
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
