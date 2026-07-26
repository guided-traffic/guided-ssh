# ADR-003: Angular SPA, embedded into the Go binary

- Status: accepted
- Date: 2026-07-19

## Context

A web UI (hosts, grants, audit) is required, and Angular has been chosen. What
remained to be decided was delivery: a separate frontend deployment vs.
delivery through the API server.

## Decision

Angular SPA (standalone components, Angular Material) with OIDC via
Authorization Code + PKCE. The production build is embedded into the Go
binary via `embed.FS` and served by the API server.

## Consequences

- One container image, one deployment, no CORS, same origin for API and UI.
- CI builds Angular first, then Go (assets must be present at `go build` time).
- The UI version is always consistent with the API version.
- The frontend stays read-mostly; logic lives in the backend and is testable
  there — the frontend is exempt from the coverage gate.
