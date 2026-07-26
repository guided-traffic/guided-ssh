# ADR-009: Build tooling — Makefile + golangci-lint

- Status: accepted
- Date: 2026-07-19

## Context

The plan left Makefile vs. Taskfile open; linting was already set to
`golangci-lint`. Build targets also serve as the CI pipeline's interface.

## Decision

Makefile (instead of Taskfile): `build`, `test`, `cover` (including a coverage
gate ≥ 80%, threshold `COVERAGE_MIN`), `lint`, `fmt`, `image`, `clean`.
golangci-lint v2 with the standard linter set plus `gosec`, `revive`,
`misspell`, `unconvert`, `unparam`, `copyloopvar`; formatting via `gofumpt` +
`goimports`.

## Consequences

- `make` is available on every runner/developer machine — no additional tool
  to install (Taskfile would need the `task` binary).
- CI calls the same targets developers use locally ⇒ "works on my machine"
  gaps stay small.
- `gosec` is active from the start — fitting the project's security focus.
- Makefile syntax is brittle; as complexity grows, steps move into scripts
  under `hack/` (example: `hack/coverage.sh`).
