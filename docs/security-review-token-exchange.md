# Security Review: Token Exchange (Phase 10)

Subject: the unauthenticated exchange endpoints `POST /v1/sign/user`
(ID token → user certificate), `POST /v1/sign/ci` (GitLab job token →
CI certificate), and `POST /v1/enroll` (one-time token → host/mTLS certificate).
Reviewed: replay, audience confusion, clock skew, brute force/DoS.
Status: Phase 10; findings are either resolved (→ Fix) or justified as an
accepted residual risk.

## Replay

- **ID tokens can be exchanged multiple times within their validity period.**
  There is deliberately no `jti` replay cache: the server scales statelessly,
  and a reliable cache would require shared state across replicas.
  Assessment: transport is TLS-protected; anyone able to capture an ID token
  can usually also intercept the legitimate exchange within the same access.
  Every issuance is audited transactionally (actor, serial, context) and is
  therefore traceable. **Residual risk accepted.** Operational recommendation:
  short ID token lifetime in the IdP (minutes — the CLI fetches fresh tokens
  per login flow anyway).
- **CI tokens:** GitLab sets `exp` to the job timeout; the certificate
  validity is additionally capped to `exp`
  (`sign_ci.go`) — after the job ends, neither the token nor the
  certificate is usable. Multiple exchanges within the same job are
  possible, but only produce further certificates for the same project
  identity with a full audit trail (`pipeline_id`, `job_id`).
- **Enrollment tokens are true one-time tokens:** consumption is
  transactional (hash comparison in the DB); a second attempt hits an
  already-consumed token → 403.

## Audience confusion

- User and CI tokens go through **separate verifiers with their own
  issuer and audience** (ADR-019); a CI token at the user endpoint fails
  on audience (and usually issuer), and vice versa.
- **Fix (fail-fast):** `GSSH_OIDC_ISSUER` without `GSSH_OIDC_CLIENT_ID` is
  now a startup error instead of a runtime rejection of all tokens —
  previously the server appeared to start correctly while silently
  rejecting every sign request.
- **Fix (configuration trap):** if user OIDC and GitLab CI were configured
  with the same issuer **and** the audience equaled the client ID, tokens
  would be exchangeable at both endpoints (a CI token could create a user).
  The server now refuses this configuration at startup
  (`checkAudienceSeparation`).
- The web UI deliberately uses the same audience as the CLI
  (`GSSH_UI_OIDC_CLIENT_ID`, default `GSSH_OIDC_CLIENT_ID`) — the admin API
  and the sign endpoint accept the same token class; authorization happens
  downstream via groups (roles) and grants.

## Clock skew

- go-oidc checks `exp` **with no leeway** and `nbf` (if present) with
  **5 min leeway**. A server whose clock runs fast may reject fresh tokens
  as expired — operational prerequisite: NTP on both server and IdP
  (in place in the Kubernetes deployment).
- Certificates are backdated by 1 min (`signBackdate`) so that hosts with
  a slightly lagging clock accept freshly issued certificates; policy caps
  backdating at 5 min. Total validity is counted from the backdated
  `ValidAfter` and thus stays under the policy maximum.
- CI: `validBefore` is capped to the token's `exp`; if the token expires
  too soon, issuance is rejected instead of delivering a stillborn
  certificate (`sign_ci.go`).

## Brute force / DoS (fixes in Phase 10)

- **Rate limiting per client IP** on `sign/user`, `sign/ci`, `enroll`:
  a request budget (default 60/min, burst 20) plus a separate, tighter
  failure budget (default 10/min) — 401/403 responses consume it, then
  429. Configuration: `GSSH_SIGN_RATE_PER_MINUTE`,
  `GSSH_SIGN_FAIL_PER_MINUTE`, `GSSH_RATE_TRUST_PROXY` (X-Forwarded-For only
  behind a trusted proxy).
- **Body limits (64 KiB)** on all exchange endpoints against memory DoS;
  the agent session ingestion already had 1 MiB.
- Enrollment tokens are 256 bits of randomness (base64URL), stored only as
  a SHA-256 hash — brute force is computationally hopeless, and the rate
  limit further bounds the attempt rate.

## Non-findings (reviewed, OK)

- Verifier error messages go to the log, never the raw token; 401 responses
  are generic.
- `validity_seconds ≤ 0` falls back to the server default; capping via the
  grant maximum and policy remains effective regardless.
- An already-signed certificate passed as `public_key` is rejected (no
  certificate chains).
- mTLS agent identity is derived exclusively from the CN of the verified
  client certificate; CSRs cannot assert an identity (both for enrollment
  and rotation).
