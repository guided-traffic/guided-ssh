package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"

	// pgx-Treiber für database/sql (goose benötigt *sql.DB).
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Migrate wendet alle ausstehenden Migrationen an. Idempotent: bereits
// angewendete Migrationen werden übersprungen (goose-Versionstabelle).
// Ein Postgres-Advisory-Lock serialisiert konkurrierende Läufe (mehrere
// Replikas bzw. Init-Container, Plan Phase 11).
func Migrate(ctx context.Context, dsn string) error {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return fmt.Errorf("db öffnen: %w", err)
	}
	defer db.Close()

	fsys, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("migrations-fs: %w", err)
	}
	locker, err := lock.NewPostgresSessionLocker()
	if err != nil {
		return fmt.Errorf("migrations-lock: %w", err)
	}
	provider, err := goose.NewProvider(goose.DialectPostgres, db, fsys, goose.WithSessionLocker(locker))
	if err != nil {
		return fmt.Errorf("goose-provider: %w", err)
	}
	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("migrationen anwenden: %w", err)
	}
	return nil
}
