# ADR-012: Schema migrations with goose (embedded)

- Status: accepted
- Date: 2026-07-19

## Context

The PostgreSQL schema (Phase 1) needs versioned, idempotent migrations —
locally, in tests, and later as an init container/job in the Helm deployment
(Phase 11). Candidates per the plan: goose or golang-migrate. Both are
established and support SQL files via `embed.FS`.

## Decision

`pressly/goose` v3 with plain SQL migrations, embedded into the binary
(`internal/store/migrations/`, `//go:embed`). Applied programmatically through
the provider API (`store.Migrate`); no separate CLI needed in the deployment.

## Consequences

- A single binary migrates itself — the init container needs no extra image.
- The goose version table makes migrations idempotent (tested in Phase 1).
- Multi-statement SQL (trigger functions) via `+goose StatementBegin/End`.
- Fallback path: migration files are plain SQL — switching to golang-migrate
  would essentially just mean renaming the directives.
