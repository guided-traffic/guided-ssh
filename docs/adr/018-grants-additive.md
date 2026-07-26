# ADR-018: Grant model — additive, identity principals in the certificate, declarative reconciliation

- Status: accepted
- Date: 2026-07-19

## Context

Phase 6 needs full access control: a grant links an IdP group via a tag
selector to target principals (local users such as `deploy`, `root`), a sudo
flag, and a maximum certificate validity. Evaluation happens in two places —
at issuance and on the host (ADR-017: `AuthorizedPrincipalsCommand`,
fail-closed). Open questions were: conflict rules, what grants do inside the
certificate, and how grants are managed.

## Decision

- **Additive grants only, no deny.** Every grant expands access; there is no
  rule that revokes access. Revocation happens exclusively by removing
  grants or group memberships (IdP sync, ADR-015). This makes conflicts
  impossible: the effect of multiple grants is the union of their effects.
  Concretely: validity = maximum of `max_validity` across the user's grants;
  sudo = true as soon as any matching grant sets it.
- **Certificates continue to carry only identity principals** (username,
  email) — not target principals like `deploy`. Which local users an
  identity can reach is decided by the host at login time via the
  principals path (grant evaluation server-side, cache TTL default 5 min).
  If target principals were embedded in the certificate, a grant revocation
  would only take effect once the certificate expired, and hosts without
  `AuthorizedPrincipalsCommand` would accept the certificate directly.
- **Evaluation at issuance** (`POST /v1/sign/user`): without at least one
  grant (via the user's groups), no certificate is issued (403) — anyone
  without access anywhere gets no certificate at all. The requested validity
  is capped to the grant maximum (not rejected, so the default works
  everywhere); the global policy (ADR: 16 h for users) applies additionally.
- **Management via an admin API** (`/v1/admin/grants…`): CRUD plus
  declarative reconciliation (`POST /v1/admin/grants/apply`). Authorization
  uses the same OIDC validation as the sign endpoint plus membership in a
  configured admin group (`GSSH_ADMIN_GROUP`; unconfigured ⇒ admin API
  disabled, fail-closed). Every mutation transactionally writes an audit
  event (`grant.created/updated/deleted`) with the admin as actor.
- **CLI `gssh-admin`**: `grant list/create/update/delete` and
  `apply -f grants.yaml`. Apply performs a full reconciliation (GitOps): the
  file is the target state; grants are identified by (issuer, group, tag
  selector) — new ones are created, deviating ones updated, and ones no
  longer declared are deleted. Unknown groups are created and later linked
  to members by the IdP sync.

## Consequences

- No conflict resolution needed; reviewing `grants.yaml` fully answers
  "who can do what," because nothing else can grant access.
- A restrictive grant cannot constrain a more generous one (max rather than
  min for validity) — anyone wanting to enforce shorter validities must
  remove the more generous grants.
- Grant revocation takes effect on hosts within the cache TTL, and on
  issuance at the user's next login with a fresh token; already-issued
  certificates remain valid until expiry (which is why short validities
  remain important).
- The sudo flag is stored and managed via the admin API; enforcement on the
  host (sudoers/PAM) follows in Phase 9.
- CI grants (project × branch condition, Phase 7) build on this same
  additive model.
