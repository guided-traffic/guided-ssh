# ADR-017: Host enrollment with one-time token, dedicated mTLS mini-PKI, fail-closed principals

- Status: accepted
- Date: 2026-07-19

## Context

Phase 5 needs: host enrollment (trust bootstrap), a host agent
(`gssh-agentd`) for certificate renewal and CA bundle maintenance, and the
`AuthorizedPrincipalsCommand` path with fail-closed behavior. ADR-008
mandates mTLS for host agents.

## Decision

- **Enrollment token**: single-use, generated via `gssh-server enroll-token`
  (direct database access — there is no admin API yet). Only the SHA-256
  hash is stored in the database; consumption is a single transactional
  UPDATE (single-use even under concurrent attempts). Tokens optionally
  carry a hostname binding and host tags; a bound token used with the wrong
  name is deliberately burned. Re-enrollment (new token, same name) updates
  the host instead of duplicating it.
- **mTLS mini-PKI**: a dedicated X.509 CA (Ed25519) in `ca_keys` (purpose
  `mtls`, private key AES-GCM-encrypted like the SSH CAs, ADR-014). During
  enrollment, the agent sends a CSR; the server sets the CommonName to the
  host UUID — identity never comes from the CSR. The agent listener
  (`-agent-listen`) terminates TLS with a server certificate freshly issued
  from the same CA on every start (SANs via `GSSH_AGENT_TLS_NAMES`) and
  requires client certificates (`RequireAndVerifyClientCert`). Enrollment
  itself runs over the public listener (chicken-and-egg problem), optionally
  with SPKI pinning (`--pin`, ADR-016). Client certificates: 1 year; rotation
  is Phase 10.
- **Host certificates**: 30 days (policy maximum), principals = full name +
  short name; the agent renews at 2/3 of the validity period and optionally
  runs a `reload_command` (sshd only reads `HostCertificate` at startup).
- **Principals path**: sshd → `AuthorizedPrincipalsCommand gssh-agentd
  principals` → daemon's Unix socket → cache/API. Response = identity
  principals (username, email) of all active members of groups whose grant
  includes the local user as a target principal and whose tag selector
  matches the host tags (selector ⊆ tags; full grant management follows in
  Phase 6). Fail-closed: if the API returns nothing and the cache is older
  than `cache_ttl`, the helper outputs nothing and sshd denies access. The
  cache is persisted to disk (survives restarts).
- **sshd integration**: enrollment idempotently writes
  `sshd_config.d/guided-ssh.conf` (TrustedUserCAKeys, HostCertificate,
  AuthorizedPrincipalsCommand), placing the host certificate alongside the
  existing host key plus the user CA bundle. The existing sshd host key
  continues to be used (no new key material on the host).
- **Packaging**: nfpm (deb/rpm) + systemd unit + install script; the service
  only starts after explicit enrollment.

## Consequences

- Enrollment security hinges on the token (single-use, expiring, hashed,
  optionally name-bound) and on TLS of the public listener.
- The agent API is unreachable without a valid client certificate; host
  identity is embedded in the certificate (CN = host UUID), not in requests.
- Offboarding takes effect on hosts via the principals path within the
  cache TTL (default 5 min) — consistent with the group sync from ADR-015.
- When `AuthorizedPrincipalsCommand` is configured, sshd only honors its
  output (no username fallback) — logins then strictly require matching
  grants; this is intentional (centralized control).
- Tested end-to-end in the integration test: containerized sshd,
  enrollment, login via user certificate (principal and grant path),
  rejection without a grant.
