# ADR-008: REST+JSON; mTLS for host agents, OIDC for humans and CI

- Status: accepted
- Date: 2026-07-19

## Context

Three kinds of API consumers with different trust models: humans (CLI/browser),
CI jobs (GitLab), and host agents.

## Decision

REST + JSON as the uniform API style, described via an OpenAPI spec (`api/`,
single source of truth, generated clients). Authentication is strictly separated:

- Humans: OIDC (Authorization Code + PKCE, device flow as fallback)
- CI: GitLab OIDC `id_token`, validated against GitLab's JWKS
- Host agents: mTLS with a host-bound client certificate

## Consequences

- Separate auth paths mean separate attack surfaces and clear policy
  assignment (user grants vs. CI grants vs. host scope).
- No gRPC: simple debugging, UI and CLI use the same API; OpenAPI generates
  Angular and Go clients.
- mTLS requires certificate rotation for agents (Phase 10) — deliberately
  budgeted for.
