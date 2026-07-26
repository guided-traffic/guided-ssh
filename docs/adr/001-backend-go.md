# ADR-001: Backend in Go

- Status: accepted
- Date: 2026-07-19

## Context

The platform consists of the API server/CA, the user CLI (`gssh`), the admin
CLI (`gssh-admin`), and the host agent (`gssh-agentd`). The host agent and
CLIs must run on heterogeneous target systems without runtime dependencies;
SSH certificate logic is at the core.

## Decision

All server components, CLIs, and the host agent are implemented in Go.

## Consequences

- `golang.org/x/crypto/ssh` natively covers SSH certificates (building, signing, parsing).
- Static binaries (`CGO_ENABLED=0`) for host agent/CLI — package-based
  installation without dependencies; simple cross-compiling (linux/amd64, linux/arm64, darwin/arm64).
- A single language stack for server, CLI, and agent — shared code (API types, client).
- NSS/PAM modules (Phase 9) may require C interop; deliberately deferred
  (see ADR-005).
