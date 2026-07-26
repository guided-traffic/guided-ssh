# ADR-013: Repository layer directly on pgx (no sqlc)

- Status: accepted
- Date: 2026-07-19

## Context

The persistence layer (Phase 1) needs type-safe access to ~9 tables with
PostgreSQL specifics (JSONB, `text[]`, partitioning, triggers). Candidates per
the plan: sqlc (codegen from SQL) or pgx directly.

## Decision

`jackc/pgx` v5 directly, with hand-written repository functions in
`internal/store`. Boilerplate is kept small via `pgx.RowToStructByName` plus
generic helpers (`queryOne`/`queryAll`); structs carry `db` tags.

## Consequences

- No codegen step in build/CI, no extra tool version to pin.
- Full control over SQL (JSONB expressions like `jsonb_each_text`, `unnest`,
  partition queries) without generator constraints.
- No compile-time check of the SQL strings — mitigated instead through
  integration tests against a testcontainer-based Postgres (enforced by the
  coverage gate).
- Fallback path: if the number of queries grows significantly, sqlc could be
  introduced per package; the schema stays unchanged.
