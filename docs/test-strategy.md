# Test Strategy

Applies to all Go code (backend, CLI `gssh`, `gssh-admin`, host agent `gssh-agentd`).
The Angular frontend is exempt from the coverage gate; its logic stays deliberately thin
(read-mostly UI), API behavior is tested on the backend side.

## Coverage gate

- **≥ 80% overall coverage** across all Go packages, measured with
  `go test -coverpkg=./... ./...` (also counts packages without their own tests).
- Enforcement: `make cover` → `hack/coverage.sh` — fails the build locally and in CI.
- Threshold centralized in the Makefile (`COVERAGE_MIN`); lowering it requires justification in the PR.
- Once integration tests exist, they count toward overall coverage
  (same `go test` run on the runner, build tag see below).

## Test levels

### Unit

- Pure Go tests without external systems; `go test -race ./...` (`make test`).
- Mandatory for: certificate construction (contents, expiry times), policy engine, claim mapping,
  grant evaluation, configuration parsing.
- Runs on every push/PR, must stay under 2 minutes.

### Integration (testcontainers)

- `testcontainers-go`; tagged with build tag `integration`
  (`go test -tags integration ./...`), so unit runs work without Docker.
- Container dependencies:
  - **Postgres** — repository layer, migrations, append-only trigger (`audit_events`)
  - **Keycloak** — OIDC flows, token validation, group sync
  - **sshd host** (container with sshd) — enrollment, `AuthorizedPrincipalsCommand`,
    login with a user certificate
- Runs on every push/PR on the self-hosted runner (Docker available).

### E2E (kind)

- A full end-to-end pass in a disposable cluster (`test/e2e`, build tag `e2e`,
  `make e2e`): the production Helm chart, **Dex + GLAuth** as IdP (Dex static
  passwords can't do groups — GLAuth provides them via the LDAP connector;
  offboarding = ConfigMap change), simulated GitLab OIDC (static
  discovery/JWKS behind nginx, job tokens signed by the suite), two
  sshd test hosts as pods (`role=web`/`role=db`), and a workstation pod
  ("human": real `gssh` binary + `ssh-agent` + OpenSSH client).
- Scenarios (in this order, shared environment):
  1. **SSO login** — `gssh login --device`, the suite "clicks through" the
     Dex device flow (LDAP login), then transparent `ssh` with strict
     host certificate checking (`@cert-authority`); fail-closed for root and
     non-granted hosts.
  2. **Grant change** — `gssh-admin apply` adds/removes a grant,
     effect on the host ACL within the cache TTL (30 s in the test).
  3. **CI + Ansible** — simulated GitLab job token → `gssh ci-login`
     (real binary, own ssh-agent) → `ansible-playbook` provisions
     the test host via the agent; key ID `ci:<project>:<pipeline>:<job>`,
     403 for unprotected refs. Without ansible installed, a
     Go SSH fallback covers the same certificate path.
  4. **Host rotation** — `GSSH_HOST_CERT_VALIDITY=3m` makes the
     2/3 renewal observable; the serial changes, sshd is reloaded via
     `reload_command`, logins keep working.
  5. **Chaos** — API scaled to 0: existing SSH sessions keep working,
     the agent cache carries new logins until the TTL, then fail-closed;
     back to normal after restart.
  6. **Offboarding** — alice loses the IdP group: no new issuance
     (403), the host ACL rejects the still-valid certificate within the
     cache TTL.
  7. **Audit** — issuances (human + CI with pipeline attribution),
     enrollments, and grant changes are queryable via `/v1/admin/audit/export`
     (JSON + CSV). Session/sudo events are not covered here
     (opt-in feature; PAM behavior verified in the Phase 9 tests).
- Runs per PR and on main (job `e2e-tests` in `release.yml`,
  self-hosted runner, kind); releases are gated on it.
  Locally: `make e2e` (switches `E2E_KEEP`, `E2E_SKIP_BUILD`, `E2E_CLUSTER`).

### Load & Chaos (Phase 13)

- **Load test for the sign endpoint** (`test/load`, build tag `loadtest`,
  `make loadtest`): real API + Postgres (testcontainer) + OIDC verifier,
  without rate limiting. **Target: ≥ 50 certificates/s** over 15 s with 16
  parallel clients, error-free; p50/p95 are logged.
  Reference measurement (Apple Silicon development machine): ~1770 certs/s,
  p95 11 ms — ample margin over the target. CI: job `load-test` on main
  (not release-blocking — shared runners make throughput gates flaky).
- **Chaos case API outage**: scenario 5 of the E2E suite (see above) plus
  `TestPrincipalsCacheAndFailClosed` (unit, `internal/agentd`).

## Scope

| Level | Scope | Dependencies | When |
|---|---|---|---|
| Unit | single package, pure logic | none | every push/PR |
| Integration | module against a real neighboring system | Docker (testcontainer) | every push/PR (self-hosted) |
| E2E | whole system in a cluster | Docker, kind, kubectl, Helm | every push/PR (self-hosted); releases gated |
| Load | sign endpoint throughput | Docker (testcontainer) | main (informative) + local |

Rule of thumb: push error handling and edge cases down (unit), wiring
up (integration), business scenarios all the way up (E2E) — never test
the same scenario twice.

## Test cases per phase (core cases, maintained alongside implementation)

| Phase | Core test cases |
|---|---|
| 1 Data model | Migrations idempotent; CRUD repository layer; `audit_events`: UPDATE/DELETE fails (trigger + missing grants) |
| 2 Core CA | Certificate contents (serial, key ID, principals, validity, extensions); policy violations (validity, principals) rejected; signing ⇒ audit event + `certificates` row in one transaction; key rotation: old + new CA valid in parallel |
| 3 OIDC | Token expired/wrong audience/wrong issuer/broken signature ⇒ 401; claim mapping `sub`/`email`/`groups`; group sync revokes authorization |
| 4 CLI | Login places key+cert only in the agent (nothing on disk); `status`/`logout`; config parsing; error paths (API unreachable) |
| 5 Host agent | Enrollment with valid/invalid/consumed token; certificate renewal at 2/3 validity; `AuthorizedPrincipalsCommand`: cache hit, cache TTL expired + API down ⇒ fail-closed; sshd login E2E in a container |
| 6 Grants | Group×tag evaluation at issuance and host ACL; additive grants (no deny); YAML import idempotent; group removed ⇒ login fails |
| 7 GitLab CI | GitLab token claims (`project_path`, `ref_protected`, …) mapped to CI grants; validity ≤ 1 h enforced; key ID contains pipeline/job; simulated GitLab OIDC ⇒ certificate ⇒ Ansible ping |
| 8 Web UI | API contracts via OpenAPI-generated clients; roles from claims (admin/auditor); audit filter; admin change produces an audit event |
| 9 Session audit | Session start/end and sudo events reported; spool buffers during API outage; correlation via cert serial |
| 10 Hardening | Rate limit engages; replay/audience-confusion/clock-skew negative tests; fuzzing sign endpoints; KMS signer against SoftHSM |
| 11 Helm | `helm test`/chart-testing; migration job with lock; probes; deployment with `existingSecret` |
| 12 GitOps | HelmRelease example installable; SOPS decryption; `gssh-admin apply` idempotent from repo file |
| 13 QA/Release | Consolidated suite green (unit + integration + E2E in `release.yml`); sign endpoint load test ≥ 50 certs/s (`test/load`, measured ~1770/s); chaos: API down ⇒ existing sessions keep working, agent cache until TTL, then fail-closed (E2E scenario 5) |

## Maintenance

- New features only with tests at the appropriate level; bug fixes with a regression test.
- This file is updated per phase (making test cases more concrete, striking out what's done).
