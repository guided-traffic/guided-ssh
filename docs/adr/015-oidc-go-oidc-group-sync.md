# ADR-015: OIDC via go-oidc/x-oauth2, group sync via Keycloak admin API

- Status: accepted
- Date: 2026-07-19

## Context

Phase 3 needs (1) server-side validation of ID tokens (issuer, audience,
signature via JWKS, expiry), (2) CLI login flows (Authorization Code + PKCE,
device flow as fallback), and (3) periodic group sync from the IdP so that
offboarding takes effect immediately on both re-issuance and host ACLs — per
the plan, without a SCIM server (OIDC claims + periodic group sync).

## Decision

- **Token validation**: `github.com/coreos/go-oidc/v3` (discovery, JWKS cache
  with automatic reload on unknown key ID, standard checks). No in-house
  implementation of JOSE verification.
- **CLI flows**: `golang.org/x/oauth2` (PKCE via `GenerateVerifier`/
  `S256ChallengeOption`, device flow via `DeviceAuth`/`DeviceAccessToken`).
  Callback listener bound only to `127.0.0.1` with a random port.
- **Claim mapping**: On every issuance, user master data and group
  memberships are taken from the token claims (`sub`, `email`,
  `preferred_username`, `groups`) and written to the database; principals are
  username + email. Disabled users are rejected and are not reactivated by
  logging in.
- **Group sync**: Interface `DirectorySource`; first implementation is the
  Keycloak admin API (service account with `view-users`, client
  credentials). The sync disables users that were removed/disabled in the IdP
  and revokes their groups; it does not create new users (that happens on
  first login). Other IdPs can be added later via the same interface.

## Consequences

- Two established, lightweight dependencies instead of custom JOSE/OAuth
  logic; go-jose comes in transitively and is used for signing in tests.
- Offboarding latency = sync interval (default 5 min,
  `GSSH_KC_SYNC_INTERVAL`), not token lifetime; each issuance additionally
  checks the active status.
- Only the `DirectorySource` implementation is Keycloak-specific; the claims
  path and sync logic are IdP-neutral. Group claims are stripped of a leading
  "/" (Keycloak path notation).
- Without a configured sync (`GSSH_KC_CLIENT_ID` empty), revocation only takes
  effect via token expiry plus group claims on re-issuance — a warning is
  logged.
