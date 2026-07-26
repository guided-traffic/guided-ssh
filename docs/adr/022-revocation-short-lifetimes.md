# ADR-022: Revocation — short lifetimes as the primary mechanism, RevokedKeys as an emergency path

## Status

Accepted (Phase 10).

## Context

SSH certificates have no online status check (no OCSP/CRL protocol as with
X.509/TLS). sshd's only revocation mechanism is the `RevokedKeys` directive
(KRL file or authorized_keys list), which must live on every host and be
kept up to date. For guided-ssh, the question is: how is a compromised key
or a departed user effectively locked out — and how quickly?

## Decision

1. **Short lifetimes are the primary mechanism.** The policy caps user
   certificates at 16 h and CI certificates at 1 h (additionally capped by
   token expiry = job timeout). A stolen certificate thus becomes worthless
   on its own within hours; there is no long-lived client-credential
   inventory that would need to be managed.

2. **The fast revocation lever is the principals lookup, not the
   certificate.** Hosts decide on every login via the
   `AuthorizedPrincipalsCommand` helper (fail-closed, cache TTL 5 min) based
   on grants. Revoking a grant, disabling a user, or removing a group in the
   IdP (sync interval 5 min) thus take effect independent of the remaining
   validity of already-issued certificates — typically within ~10 minutes
   on any reachable host. From that point on, the user receives no new
   certificates (no grant ⇒ no issuance).

3. **mTLS agent certificates: revocation via the host record.** The agent
   API resolves identity on every request via the host record (CN = host
   UUID). If a host is deleted, its mTLS certificate — and with it
   renew/principals/sessions — becomes immediately ineffective, regardless
   of the certificate's validity period (1 year, rotation at 2/3, see
   Phase 10).

4. **`RevokedKeys` distribution via the host agent as an emergency path
   (future extension).** For the case of "certificate compromised and
   remaining validity unacceptable," distribution of a centrally maintained
   revocation list is planned: a serial-based KRL on the server, fetched by
   the agent analogous to the CA bundle (`/v1/agent/…`, hourly), and a
   `RevokedKeys` directive in the generated sshd snippet. Deliberately
   **not yet implemented** — the cases it covers are already bounded to a
   window of hours by (1)–(3), and a partially distributed revocation list
   (unreachable hosts) must not be sold as reliable.

5. **Nuclear option: CA rotation.** If the CA key itself is compromised, a
   new CA key is rolled out (agents pull the bundle hourly) and the old one
   is removed from `TrustedUserCAKeys`; all old certificates become invalid
   in one stroke. The mechanism already exists through bundle distribution,
   but costs a re-issuance for all active users.

## Consequences

- The maximum residual-risk window for a stolen user certificate is its
  remaining validity (≤ 16 h) — but only on hosts whose grants continue to
  authorize the affected user. Revoking the grants closes this window too,
  down to the principals cache TTL (5 min).
- Offline/unreachable hosts learn of revocations only on their next API
  contact; until then, the principals cache answers from cache for at most
  `cache_ttl` (default 5 min) and is fail-closed afterward.
- KRL distribution (4) is scoped as a follow-up: store table for revoked
  serials, admin endpoint/CLI, agent fetch, snippet extension. Until then,
  the documented emergency measure is: revoke grants/users (effective
  immediately via principals) and rotate on CA suspicion (5).
