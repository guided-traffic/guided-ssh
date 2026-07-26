# Threat Model (Sketch)

Status: initial sketch from Phase 0. Deeper work (security review, fuzzing,
KMS/HSM) in Phase 10. This file is updated as the architecture evolves.

## Protected assets

1. **CA private keys** (user and host CA — separate): compromise allows
   arbitrary SSH certificates for all managed hosts. Crown jewel.
2. **OIDC tokens** (IdP ID tokens, GitLab job tokens): exchanged for certificates.
3. **mTLS client certificates of the host agents**: access to the host API (ACLs, CA bundle).
4. **Enrollment tokens**: allow registration of new hosts.
5. **Audit log integrity**: traceability is the platform's core promise.
6. **Grants/policies in the DB**: define who is allowed where.

## Trust boundaries

- CLI ↔ API: OIDC (Authorization Code + PKCE), TLS
- Browser ↔ API: server-side OIDC login (BFF); HttpOnly session cookie
  (AES-GCM, key derived via HKDF from the CA master key), SameSite=Lax +
  X-Requested-With against CSRF; tokens never leave the server
- Host agent ↔ API: mTLS with a host-bound client certificate
- CI job ↔ API: GitLab OIDC token, validated against the GitLab JWKS
- API ↔ Postgres: internal cluster traffic, NetworkPolicy, dedicated DB roles
- API ↔ IdP/GitLab: TLS, pinned issuer URLs, JWKS cache

## Attack surfaces and mitigations

| Attack surface | Threat | Mitigations (phase) |
|---|---|---|
| CA key | Exfiltration from DB/secret; misuse via compromised API | encrypted at rest (2); separate user/host CA (2); every signature audited synchronously (2); key rotation (2); KMS/HSM — key never leaves the module (10) |
| Token theft | stolen ID/job token exchanged for a certificate; replay; audience confusion | short token and certificate lifetimes (2/3); strict `iss`/`aud`/`exp`/signature verification with JWKS (3/7); PKCE against code interception (3); bounded clock-skew window (10); rate limiting (10); audit of every issuance (2) |
| Host agent compromised | mTLS identity misused: query foreign ACLs, manipulate principals | client certificate host-bound, API returns only data for its own host (5); minimal API privileges (5); mTLS rotation (10); compromise limited to this host — CA and other hosts remain unaffected |
| Compromised CI runner | runner token misused for broad access | certificate pipeline-bound, lifetime ≤ 1 h (7); principals restricted by CI grants (7); `ref_protected` conditions (7); KeyID makes the pipeline identifiable in the audit log (7) |
| Audit log | after-the-fact manipulation/deletion by an attacker or insider | append-only: DB role without UPDATE/DELETE + protective trigger (1); export/streaming to SIEM as an external copy (8) |
| Enrollment | leaked enrollment token registers an attacker's host | token is one-time and short-lived (5); enrollment audited (5); host deactivation via API |
| Sign endpoints | brute force, DoS, manipulated requests | AuthN before any policy evaluation (3/7); policy engine bounds lifetime/principals/extensions (2); rate limiting (10); fuzzing/negative tests (10) |
| Web UI/admin | privilege escalation, unnoticed grant changes | roles from token claims (8); every admin change produces an audit event (8); grants reviewable declaratively via GitOps (12) |

## Assumptions

- The IdP and the GitLab instance are trusted and secured on their own
  (their compromise ⇒ identities are no longer reliable; outside our scope).
- Kubernetes cluster admins are considered trusted (they can reach secrets;
  hardening against this only comes with KMS/HSM in Phase 10).
- Root compromise of a managed host = that host is lost; the design limits
  the damage to that host (short-lived certificates, host-bound mTLS identity).
- Revocation relies primarily on short lifetimes; `RevokedKeys` distribution
  as an emergency path (10).

## Open items (→ Phase 10)

- Formal review of the token exchange (replay window, clock-skew limits)
- KMS/PKCS#11 selection and SoftHSM test setup
- Threats from malicious `CertRequest` content (fuzzing plan)
