# ADR-012: Schema-Migrationen mit goose (embedded)

- Status: akzeptiert
- Datum: 2026-07-19

## Kontext

Das PostgreSQL-Schema (Phase 1) braucht versionierte, idempotente Migrationen —
lokal, in Tests und später als Init-Container/Job im Helm-Deployment (Phase 11).
Kandidaten laut Plan: goose oder golang-migrate. Beide sind etabliert und
unterstützen SQL-Dateien via `embed.FS`.

## Entscheidung

`pressly/goose` v3 mit reinen SQL-Migrationen, eingebettet ins Binary
(`internal/store/migrations/`, `//go:embed`). Anwendung programmatisch über die
Provider-API (`store.Migrate`), kein separates CLI im Deployment nötig.

## Konsequenzen

- Ein Binary migriert sich selbst — Init-Container braucht kein Zusatz-Image.
- goose-Versionstabelle macht Migrationen idempotent (Test in Phase 1).
- Multi-Statement-SQL (Trigger-Funktionen) via `+goose StatementBegin/End`.
- Rückbaupfad: Migrationsdateien sind Plain SQL — Wechsel zu golang-migrate
  wäre im Wesentlichen eine Umbenennung der Direktiven.
