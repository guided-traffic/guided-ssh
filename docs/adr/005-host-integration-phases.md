# ADR-005: Host integration — sshd-native first, NSS/PAM later

- Status: accepted
- Date: 2026-07-19

## Context

Access control on the host can be handled via built-in sshd mechanisms
(`TrustedUserCAKeys`, `AuthorizedPrincipalsCommand`) or, at a deeper level, via
NSS/PAM modules (centralized accounts, sudo audit). NSS/PAM implies C interop,
delicate failure paths in the login stack, and considerably more testing effort.

## Decision

Stage 1 (MVP): certificate authentication purely via sshd mechanics —
`TrustedUserCAKeys`, `HostCertificate`, `AuthorizedPrincipalsCommand` against
the local host agent (Unix socket, cache, fail-closed).
Stage 2 (Phase 9, after MVP experience): PAM for session/sudo audit,
optionally NSS for centralized accounts (UID/GID from the IdP).

## Consequences

- MVP without C code, low risk in the login path; local accounts must
  initially exist via the operator's existing provisioning.
- Offboarding still takes effect immediately via the host ACL (principals),
  within the cache TTL.
- Session/sudo audit on the host only arrives with Stage 2; until then, only
  issuance audit (server-side) and sshd logs are available.
- Stage 2 implemented (Phase 9): `pam_exec` instead of a C module, serial
  correlation via the sshd tokens `%s`/`%i`, host-local opt-in — details in
  ADR-021. NSS remains open.
