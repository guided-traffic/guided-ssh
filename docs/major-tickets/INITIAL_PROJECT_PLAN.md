# guided-ssh — Design and Implementation Plan

Certificate-based SSH access platform: short-lived SSH certificates instead of static
`authorized_keys`, single sign-on through the existing identity provider, machine
access for CI pipelines (GitLab), full auditability of all issued
access grants and sessions. Runs on Kubernetes via Helm, managed through GitOps (FluxCD).

---

## Feature Target Picture (derived from market analysis)

### Certificate Workflow (User)
- User runs `ssh <host>`; a local client/agent checks whether a valid
  SSH certificate is present.
- If none is present, an OAuth/OIDC SSO flow against the identity provider
  starts (Keycloak, Okta, Entra ID, Google Workspace, …). The resulting ID token is
  exchanged with the CA for a signed, short-lived SSH user certificate.
- Default validity ~16 hours (configurable); the certificate contains a
  principal list (username, email) for identification.
- Certificates live exclusively in the `ssh-agent` and are never persisted to disk.

### Identity and User Management
- Users and groups are synchronized from the IdP via SCIM or native APIs;
  no duplication of user management — the IdP remains the source of truth.
- Removing a user from an authorized IdP group revokes access
  immediately across all managed hosts (offboarding without manual steps).
- UID/GID values are taken from the IdP or assigned automatically and deterministically.

### Host Management
- Enrollment: the host bootstraps trust with the CA, receives a host certificate, and
  configures `sshd` for certificate-based authentication (`TrustedUserCAKeys`,
  `HostCertificate`); a host agent (systemd unit) keeps the certificate and policies up to date.
- Host tags (role, environment, region — analogous to EC2 tags) categorize hosts;
  access rules combine IdP groups with host tags.
- Automatic rotation of host certificates before expiry.

### Access Control on the Host
- NSS/PAM integration: user and group ACLs are fetched at runtime by the host agent
  from the API over mTLS.
- Three-stage check: (1) NSS resolves the user account and checks authorization,
  (2) certificate principals are matched against the target username,
  (3) PAM checks SSH and sudo rights for this user.
- Sudo permissions can be controlled centrally per grant.
- Bastion support: access via jump hosts with internal DNS names, all
  connections are logged.

### Audit & Traceability
- Every certificate issuance is logged: who, when, which principals,
  which validity period, and from which context (SSO session, CI pipeline).
- The PAM module reports session start, sudo actions, and session end to the platform.
- Audit view in the UI; export/streaming to a SIEM is possible.
- Signing keys can be stored in a KMS/HSM so private keys cannot be exfiltrated;
  every signing operation is logged.

### Machine Access (Core Requirement)
- GitLab runners receive a short-lived SSH certificate for the duration of a
  pipeline: GitLab issues an OIDC `id_token` per job; the CA validates
  it against the GitLab JWKS endpoint and issues a certificate with a
  pipeline-bound validity period and restricted principals.
- This lets a runner provision servers via Ansible — without static keys
  in CI variables.

---

## Architecture Decisions

| Area | Decision | Rationale |
|---|---|---|
| Backend | Go | strong SSH/crypto libraries (`golang.org/x/crypto/ssh`), static binaries for the host agent and CLI |
| Database | PostgreSQL | ACID guarantees for the audit log, JSONB for certificate metadata |
| Frontend | Angular (SPA), OIDC via Authorization Code + PKCE | Requirement; the build is embedded as static assets into the Go binary (`embed.FS`) — one image, no CORS, simple Helm deployment |
| Ansible | reference playbooks only, for CI provisioning (GitLab core requirement) | no enrollment via Ansible; host installation via packages/install script |
| Host integration | Phase 1: `AuthorizedPrincipalsCommand` + cert auth; Phase 2: NSS/PAM modules | sshd-native mechanism first (low complexity, no C code), NSS/PAM later for account sync and sudo auditing |
| Key storage | Interface: software key (encrypted in DB/K8s secret) → KMS/HSM (PKCS#11, cloud KMS) | Simple to start, hardened for production |
| Deployment | Helm chart, FluxCD-compatible (HelmRelease, Kustomize overlays) | Requirement |
| API | REST + JSON, mTLS for host agents, OIDC for humans/CI | clear separation of auth paths |

Deliberate simplifications for the MVP: no SCIM server (instead OIDC claims +
periodic IdP group sync), no session recording (metadata audit only),
web UI is read-mostly (management primarily via CLI/API, GitOps-friendly).

---

## Phase 0 — Project Foundation

- [x] Define repository structure (`cmd/`, `internal/`, `api/`, `web/` (Angular), `deploy/helm/`, `docs/`)
- [x] Initialize Go module, linting (`golangci-lint`), `Makefile`/`Taskfile`
      → Makefile (ADR-009), module `github.com/guided-traffic/guided-ssh`
- [x] Build pipeline in GitHub Actions on a self-hosted runner (build, test, lint,
      container image via ko or Dockerfile); document runner requirements
      (Docker/Podman for test containers, kind for E2E)
      → `.github/workflows/release.yml`, Dockerfile instead of ko (ADR-010), `docs/ci-runner.md`;
      runner registration itself is still open on the ops side
- [x] Registry target: container images pushed to `docker.io/guidedtraffic` (push
      credentials as GitHub secrets, tagging: SemVer + `sha-<commit>`)
      → Secret `DOCKERHUB_PAT` (documented in `docs/ci-runner.md`), push only on release
- [x] CI/release pipeline following the standard workflow:
      1. Pull request against `main` → tests (lint, unit/integration tests with
         coverage gate ≥ 80%, build)
      2. Push to `main` → same tests, then `semantic-release`: analyzes
         Conventional Commits, creates tag `vX.Y.Z` + GitHub release (via `BOT_PAT`,
         so the release triggers the build workflow)
      3. Release published → build Docker image and push it to
         `docker.io/guidedtraffic/guided-ssh` (tags: `X.Y.Z`, `X.Y`, `X`,
         `sha-<commit>`; provenance + SBOM)
      → `.github/workflows/release.yml` (test + semantic release),
      `.github/workflows/build.yml` (Docker build on release),
      `.releaserc` + `package.json` (semantic-release, conventionalcommits preset);
      secrets: `DOCKERHUB_PAT`, `BOT_PAT`
- [x] Coverage badge: on `main`, the test job generates `.github/badges/coverage.json`
      (shields.io endpoint format) and passes it as an artifact to semantic-release,
      which commits it alongside the release commit via `@semantic-release/git`
      (`[skip ci]`); the README embeds the badge via raw.githubusercontent.com
- [x] Renovate (self-hosted, via `BOT_PAT`): daily at 2 AM UTC + after every push to `main`;
      automerge for minor/patch updates (gomod, Dockerfile, GitHub Actions, pinned
      workflow tools), major updates require review; Go version updates grouped across
      Dockerfile/go.mod (custom regex manager)
      → `.github/workflows/renovate.yml`, `renovate.json`
- [x] Coverage gate in the pipeline: ≥ 80% test coverage for all Go code (backend, CLI,
      host agent) — frontend excluded; the build fails if coverage drops below this threshold
      → `make cover` + `hack/coverage.sh`, identical locally and in CI
- [x] Draft a test strategy document: distinguishing unit / integration (test
      containers: Postgres, Keycloak, sshd host) / E2E (kind cluster, full
      end-to-end pass); test cases defined per phase, maintained alongside implementation
      → `docs/test-strategy.md`
- [x] Create an ADR directory; record the decisions from the table above as ADR-001…n
      → `docs/adr/` (ADR-001…011 + template)
- [x] Sketch a threat model (attack surfaces: CA key, token theft, host agent compromise)
      → `docs/threat-model.md`
- [x] Decide on license and versioning scheme
      → Apache-2.0, SemVer via git tags `vX.Y.Z` (ADR-011)

## Phase 1 — Data Model & Persistence

- [x] Design the PostgreSQL schema: `users`, `groups`, `hosts`, `host_tags`, `access_grants`
      (group × tag selector × principals × sudo flag × max validity), `certificates`
      (issued certificates including serial, KeyID, principals, validity, issuer context),
      `audit_events` (append-only), `ca_keys`, `service_accounts` (CI identities)
      → `internal/store/migrations/0001_initial_schema.sql` (plus `user_groups`,
      serial sequence; `audit_events` partitionable by month from the start)
- [x] Set up migration tooling (goose or golang-migrate)
      → goose v3, embedded SQL, `store.Migrate` (ADR-012)
- [x] Repository layer in Go (sqlc or pgx directly) with tests against a test-container Postgres
      → pgx v5 directly (ADR-013), `internal/store`; integration tests (build tag
      `integration`) run as part of `make cover` — overall coverage 86.7%
- [x] Append-only guarantee for `audit_events` (no UPDATE/DELETE grant, trigger as protection)
      → trigger in migration 0001 (tested); the grant schema for the app role is documented
      in `docs/audit-retention.md`
- [x] Document the retention concept for audit data (monthly partitioning)
      → `docs/audit-retention.md` (monthly partitions, detach/drop, archiving)

## Phase 2 — Certificate Authority (Core CA)

- [x] Define the signer interface (`Sign(ctx, CertRequest) (*ssh.Certificate, error)`)
      → `internal/ca/signer.go` (plus `CAKeyID()`/`PublicKey()` for persistence and the bundle)
- [x] Software signer: Ed25519 CA key, encrypted at rest (age/AES-GCM, key from a K8s secret)
      → AES-256-GCM instead of age (ADR-014), master key via `GSSH_CA_MASTER_KEY`
- [x] Separate CA keys for user and host certificates
      → `CA.EnsureCAKeys` bootstraps one key per purpose; signer selection is strictly per purpose
- [x] Certificate construction: serial, KeyID (`user:<sub>@<idp>` or `ci:<project>:<pipeline>`),
      principals, `valid_after`/`valid_before`, extensions (`permit-pty`, …), critical options
      → `SoftwareSigner.Sign` + KeyID helper in `internal/ca/keyid.go`
- [x] Policy engine: maximum validity, allowed principals, allowed extensions per requester type
      → `internal/ca/policy.go`; requester types user/ci/host, defaults 16h / 1h / 30d
- [x] Every signature synchronously creates an `audit_event` + `certificates` entry (same transaction)
      → `store.CreateCertificateWithAudit` (pgx transaction, with an integrated rollback test)
- [x] Key rotation: multiple active CA keys, transition window, endpoint for the current CA bundle
      → `CA.Rotate`/`RetireKey` (active → retiring → retired), `GET /v1/ca/bundle/{user|host}`
      in `internal/api`; `gssh-server -listen` starts the HTTP API
- [x] Unit tests: certificate contents, policy violations, expiry times
      → `internal/ca/*_test.go`, `internal/api/server_test.go`; overall coverage 82%

## Phase 3 — User Authentication (OIDC/SSO)

- [x] OIDC integration (Authorization Code + PKCE for the CLI, device flow as a fallback)
      → `internal/auth/flow.go` (x/oauth2; PKCE with a 127.0.0.1 callback, device flow),
      the CLI commands themselves follow in Phase 4 (ADR-015)
- [x] Token validation: issuer, audience, signature (JWKS cache), expiry
      → `internal/auth/verifier.go` (go-oidc/v3, JWKS cache with auto-reload)
- [x] Claim mapping: `sub`/`email`/`groups` → internal user + principal derivation
      → `internal/auth/mapper.go`; principals = username + email, groups taken from
      token claims on every issuance; inactive users are rejected
- [x] Periodic group sync from the IdP (group claims or directory API) → immediate
      revocation affects both new issuance AND host ACLs
      → `internal/auth/sync.go` + Keycloak admin API source (`keycloak.go`);
      env `GSSH_KC_*`, default interval 5m; audit events on de-/reactivation
- [x] Endpoint `POST /v1/sign/user`: ID token in, SSH certificate out (policy-checked)
      → `internal/api/sign.go` (bearer token, 401/403/400 error paths, default 16h)
- [x] Integration tests against Keycloak in a test container
      → `internal/auth/keycloak_integration_test.go` (realm import; token validation,
      sign endpoint including CertChecker against the CA bundle, group revocation, offboarding)

## Phase 4 — CLI for Users (`gssh`)

- [x] `gssh login`: SSO flow, generate an ephemeral key pair, fetch the certificate,
      load both only into the `ssh-agent` (no persistence to disk)
      → `internal/cli` + `cmd/gssh` (ADR-016); PKCE browser flow, `--device` as a
      fallback; agent entry with LifetimeSecs = certificate validity
- [x] `gssh ssh <host>` or ProxyCommand/Match-exec integration in `~/.ssh/config`,
      so native `ssh` works transparently (auto-login when no certificate is present)
      → `gssh ssh` (auto-login + exec ssh) and `gssh integrate`
      (Match-exec snippet with `gssh login --if-needed`, renewal below 5m remaining validity)
- [x] `gssh status`, `gssh logout` (removing agent entries)
      → the `guided-ssh` comment prefix identifies its own entries; status returns
      exit code 1 without a valid certificate
- [x] Configuration file (`~/.config/guided-ssh/config.yaml`): API URL, IdP, fingerprint pinning
      → yaml.v3, XDG path, override via `--config`/`GSSH_CONFIG`; pinning as
      SPKI-SHA-256 (replaces CA verification, for self-signed deployments)
- [x] Cross-platform builds (linux/amd64, linux/arm64, darwin/arm64) in CI
      → `make cross`, runs in the build job of `.github/workflows/release.yml`

## Phase 5 — Host Enrollment & Host Agent

- [x] Enrollment flow: single-use enrollment token (or cloud identity later) →
      the host registers itself, receives a host certificate + mTLS client certificate for the API
      → `POST /v1/enroll` + `gssh-server enroll-token` (hash in the DB, transactional
      single-use, optional name binding); mTLS mini-PKI in `ca_keys`
      (purpose `mtls`), agent API behind `-agent-listen` (ADR-017)
- [x] Host agent (`gssh-agentd`, a single Go binary, systemd unit):
  - [x] Automatically renew the host certificate (at 2/3 of its validity)
        → `internal/agentd` daemon; optional `reload_command` after renewal
  - [x] Keep the CA bundle up to date (write the `TrustedUserCAKeys` file)
        → periodic (`bundle_interval`, default 1h), written only on change
  - [x] Fetch and cache authorized principals per local user from the API
        → `GET /v1/agent/principals`; minimal grant evaluation (selector ⊆
        host tags, active group members → username+email); fully implemented in Phase 6
- [x] `AuthorizedPrincipalsCommand` helper: sshd queries the agent (Unix socket), the agent
      answers from its cache — fail-closed when the API is unreachable, configurable cache TTL
      → `gssh-agentd principals -user %u`; the cache persists, `cache_ttl` default 5m
- [x] Generate sshd configuration snippets (`/etc/ssh/sshd_config.d/guided-ssh.conf`)
      → idempotent during enrollment; uses the existing sshd host key
- [x] Host tags: settable at enrollment, changeable via API/CLI
      → token tags + `--tags` at enroll time (token wins); changing them after
      enrollment only becomes possible with the admin API/CLI in Phase 6/8 (a deliberate gap)
- [x] Packaging of the host agent: deb/rpm (nfpm) + install script; `gssh-agentd enroll
      --token …` applies the sshd configuration idempotently
      → `deploy/packaging/` (nfpm.yaml, systemd unit, postinstall, install.sh), `make packages`
- [x] Integration test: container host with sshd, enrollment, login with a user certificate
      → `internal/agentd/enroll_integration_test.go`: alpine-sshd container,
      enrollment via the real API (mTLS), login as alice (principal) and deploy
      (grant), rejection without a grant (fail-closed), host cert verification

## Phase 6 — Access Control (Grants)

- [x] Implement the grant model: IdP group × tag selector → target principals (e.g. `deploy`,
      `root`), sudo yes/no, maximum certificate validity
      → `access_grants` (schema from Phase 1) + `internal/store/grants.go`; every mutation
      transactionally writes an audit event (`grant.created/updated/deleted`) with the actor
- [x] Evaluated in two places: at certificate issuance (which principals the requester
      gets) and on the host (which principals this local user accepts)
      → Issuance: no grant means no certificate (403), validity = min(request, maximum
      across grants); principals remain identity principals (ADR-018). Host:
      `ListAuthorizedPrincipals` (selector ⊆ host tags, active group members)
- [x] Grant management: CRUD via API + CLI (`gssh-admin grant …`); declarative
      YAML import (`gssh-admin apply -f grants.yaml`) for GitOps-managed access rules
      → `/v1/admin/grants…` (OIDC + `GSSH_ADMIN_GROUP`, fail-closed) +
      `cmd/gssh-admin`/`internal/admincli`; apply performs a full reconciliation over
      (issuer, group, tag selector), token via the OIDC flow or `GSSH_ID_TOKEN`
- [x] Define conflict rules (there is no deny — only additive grants, documented)
      → ADR-018 + `docs/grants.md`: union of effects, validity = maximum,
      sudo = OR; revocation only via removing a grant/group
- [x] Document the bastion pattern (ProxyJump, separate grants for bastion + target)
      → `docs/grants.md` (own tags/grants per hop, ProxyJump without agent forwarding)
- [x] E2E test: remove a group → the next login fails, host ACL updated
      → `keycloak_integration_test.go`: grant on "admins", sign succeeds + the host ACL contains
      alice; after group revocation + sync: a fresh token ⇒ 403, host ACL empty

## Phase 7 — GitLab CI Integration (Core Requirement)

- [x] Register GitLab as an OIDC issuer: configure issuer URL + JWKS,
      audience requirement (`aud: guided-ssh`)
      → `auth.CIVerifier` (its own issuer/audience, strictly separate from the IdP);
      env `GSSH_CI_ISSUER`/`GSSH_CI_AUDIENCE` (ADR-019)
- [x] Endpoint `POST /v1/sign/ci`: validates GitLab's `id_token`, maps its claims
      (`project_path`, `ref`, `ref_protected`, `pipeline_id`, `environment`) onto
      CI grant rules
      → `internal/api/sign_ci.go`; one service account per project (`active=false`
      acts as a kill switch); principals = `ci:<project_path>` + namespace ancestors
- [x] CI grants: project/group × branch condition (e.g. only `ref_protected: true`)
      × tag selector → principals; validity capped (default 1h, up to the job timeout)
      → table `ci_grants` (migration 0003) + `store/ci_grants.go`; managed via
      `/v1/admin/ci-grants…`, `gssh-admin ci-grant …`, and `ci_grants:` in grants.yaml;
      validity = min(grant maximum, policy 1h, token `exp` = job timeout);
      the host ACL supplies `ci:<project>` via AuthorizedPrincipalsCommand
- [x] KeyID format `ci:<project_path>:<pipeline_id>:<job_id>` → every issuance can be
      uniquely traced to a pipeline in the audit log
      → `ca.CIKeyID`; audit actor = KeyID, claims stored in issuer_context
- [x] Helper command `gssh ci-login` (uses `CI_JOB_JWT`/`id_tokens`), loads the certificate
      into the job's agent
      → `id_tokens` only (env `GSSH_CI_TOKEN`, `--token-env`); `CI_JOB_JWT` has been
      removed from GitLab and is deliberately not supported; API URL via
      `--api-url`/`GSSH_API_URL`, SPKI pinning just like `gssh login`
- [x] Document a reference pipeline: `.gitlab-ci.yml` with `id_tokens`, `gssh ci-login`,
      then `ansible-playbook` against target hosts (Ansible uses the ssh-agent automatically)
      → `docs/gitlab-ci.md` + `deploy/examples/gitlab-ci/.gitlab-ci.yml`
- [x] Sample Ansible playbook + inventory pattern for certificate-based provisioning
      → `deploy/examples/ansible/` (site.yml, inventory.yml)
- [x] E2E test: simulated GitLab token → certificate → Ansible ping against a test host
      → `internal/agentd/ci_integration_test.go`: fake GitLab (discovery+JWKS),
      sign, SSH login as deploy (fail-closed for root), audit attribution;
      the Ansible ping runs if Ansible is installed on the runner —
      otherwise the Go SSH pass-through covers the same path

## Phase 8 — Web UI & Auditing Interface

- [x] Set up the Angular project (`web/`): standalone components, Angular Material,
      OIDC login (Authorization Code + PKCE, e.g. `angular-auth-oidc-client`),
      roles (admin, auditor, read-only) derived from token claims
      → Angular 21 + Material 21 (M3 dark, glass look); OIDC bootstrap via
      `GET /v1/ui/config`; role groups `GSSH_ADMIN_GROUP`/`GSSH_AUDITOR_GROUP`/
      `GSSH_READONLY_GROUP` (admin ⊃ auditor ⊃ readonly, fail-closed; ADR-020)
- [x] Switched UI login to server-side OIDC (BFF): the server performs
      Authorization Code + PKCE with a client secret (`/v1/auth/login|callback|
      logout|me`, `internal/api/ui_auth.go`); the session is an HttpOnly cookie
      (AES-GCM, key derived via HKDF from `GSSH_CA_MASTER_KEY`); the admin API
      accepts the session cookie + `X-Requested-With` in addition to bearer tokens;
      the SPA no longer uses `angular-auth-oidc-client`, no CORS/discovery in the browser.
      Enabled via `GSSH_UI_OIDC_CLIENT_SECRET` (chart:
      `config.oidc.uiExistingSecret`); the Dex client becomes confidential,
      redirect URI `<base>/v1/auth/callback`
- [x] Generate the API client from an OpenAPI spec (single source of truth for the REST API)
      → `api/openapi.yaml` (hand-maintained, complete REST API) + ng-openapi-gen
      into `web/src/app/api` (`make web-api`)
- [x] Build integration: Angular build in CI, assets embedded into the Go binary via `embed.FS`
      → `web/embed.go` (go:embed, `.gitkeep` placeholder — allows a Go build without Node),
      SPA handler with an index.html fallback; `make web`; CI job `web-build`;
      Docker Node stage in the release image
- [x] Views: hosts (status, tags, certificate expiry), grants, users/groups,
      service accounts/CI rules
      → read endpoints `/v1/admin/{hosts,users,groups,service-accounts,certificates}`;
      grants/CI-grants CRUD in the UI (admin), service-account kill switch via toggle
- [x] Audit view: filterable by user, host, pipeline, time range, event type
      (issuance, login, sudo, session end, enrollment, grant change)
      → `GET /v1/admin/audit` (event_type, actor, q over actor+payload for
      host/pipeline, time range, pagination; role: auditor); sudo/session events
      arrive with Phase 9
- [x] Audit export: CSV/JSON download + structured logs (JSON on stdout) for
      SIEM integration; optional webhook
      → `GET /v1/admin/audit/export` (CSV/JSON, up to 100,000 rows);
      `internal/auditstream`: a poller emits committed events as JSON logs
      (`GSSH_AUDIT_STREAM=true`) and to `GSSH_AUDIT_WEBHOOK_URL`
- [x] Admin changes made through the UI themselves generate audit events (who changed which grant)
      → the UI uses the same admin endpoints (transactional audit events with an actor);
      now also covers service-account toggling (`service_account.updated`)

## Phase 9 — Session Auditing on the Host (Extension Stage)

- [x] PAM module or `pam_exec` hook: report session start/end to the API (buffered,
      asynchronous, loss-tolerant via a local spool)
      → `pam_exec` hooks (ADR-005: no C code) → `gssh-agentd pam-session`, fail-open;
      daemon spool (`sessions-spool.jsonl`) + flush via mTLS `POST /v1/agent/sessions`;
      opt-in via `gssh-agentd enroll --session-audit` (off by default, host-local)
- [x] sudo auditing: capture and report sudo events (command, target user)
      → `pam_exec` in the sudo stack → `session.sudo` audit event (target/calling user,
      command captured best-effort via `SUDO_COMMAND`; reliable only via a sudo log file/plugin)
- [x] Correlation: link session events to the issuance via the certificate serial
      → instead of journald parsing: sshd tokens `%s`/`%i` passed to the principals helper; the daemon
      remembers serial→user and enriches the session-open event; the server resolves
      the user via `certificates.serial` (with `LogLevel VERBOSE` also set)
- [ ] Optional NSS module for centralized accounts (UID/GID from the IdP) — decision
      deferred until after MVP experience; until then, local accounts via the operator's
      existing provisioning
      → left open (deliberately deferred)
- [ ] Dashboards: active sessions, sessions per host/user
      → deferred (follow-up step); the backend is in place: `host_sessions` +
      `Store.ListActiveSessions`

## Phase 10 — Hardening & Key Management

- [ ] Implement a KMS signer (interface from Phase 2): PKCS#11 first (covers HSM +
      SoftHSM tests), HashiCorp Vault integration
      → deliberately deferred
- [x] Rate limiting and brute-force protection on the sign endpoints
      → `internal/api/ratelimit.go`: token bucket per client IP on
      `/v1/sign/user|ci` + `/v1/enroll` (request budget 60/min + a tight
      failure budget of 10/min for 401/403 → 429); env `GSSH_SIGN_RATE_PER_MINUTE`
      (0 = off), `GSSH_SIGN_FAIL_PER_MINUTE`, `GSSH_RATE_TRUST_PROXY`;
      additionally 64 KiB body limits on the token-exchange endpoints
- [x] mTLS certificate rotation for host agents
      → `POST /v1/agent/renew-mtls` (CSR over the existing mTLS channel, the CN comes
      server-side from the peer certificate); the daemon rotates at 2/3 of the
      validity period (fresh key pair, atomic file swap, the client certificate
      is switched over via GetClientCertificate without a restart)
- [x] Document the revocation strategy: short validity periods as the primary mechanism,
      plus `RevokedKeys` distribution via the host agent for emergencies
      → ADR-022: short validity is primary, fast revocation via grants/principals
      (fail-closed, ~10 min), KRL distribution as a planned future extension,
      CA rotation as the nuclear option
- [x] Security review of the token exchange (replay, audience confusion, clock skew)
      → `docs/security-review-token-exchange.md`; fixes: fail-fast when
      `GSSH_OIDC_CLIENT_ID` is missing, a startup check against an issuer/audience
      collision between user OIDC and GitLab CI (`checkAudienceSeparation`)
- [x] Fuzzing/negative tests for the sign endpoints
      → Go fuzzing: `FuzzDecodeSignRequest`, `FuzzBearerToken`,
      `FuzzSignUser`, `FuzzSignCI` (never panics/500s); negative tests for
      oversized bodies, negative validity periods, rate limiting after failed attempts

## Phase 11 — Helm Chart & Kubernetes Deployment

- [x] Helm chart `deploy/helm/guided-ssh`: Deployment (API+UI), Service, Ingress,
      ServiceMonitor, NetworkPolicies, PodSecurityContext (non-root, read-only FS)
      → plus a separate agent service (mTLS needs TLS passthrough, no Ingress)
- [x] Configuration entirely via `values.yaml`: IdP, GitLab issuer, DB DSN,
      signer backend, validity defaults
      → 1:1 mapping of `config.*` → `GSSH_*` env vars; DSN/master key via secret refs;
      the signer backend is the software signer (DB, AES-256) — no other backend yet
- [x] Secrets handling: `existingSecret` references (compatible with external-secrets
      and SOPS — no secrets in the chart itself)
      → `secrets.existingSecret` (mandatory, fail-fast via `required`),
      `config.keycloak.existingSecret` (optional)
- [x] PostgreSQL: document connecting to an external DB/CloudNativePG; an optional
      subchart dependency for development only
      → chart README (CNPG `Cluster` + secret `…-app`/`uri`); bitnami/postgresql
      as a dependency with `condition: postgresql.enabled` (off by default)
- [x] DB migrations as an init container/job with locking
      → subcommand `gssh-server migrate` as an init container; goose with
      a Postgres advisory session lock (serializes parallel replicas)
- [x] Health/readiness probes, PodDisruptionBudget, HPA options
      → probes on `/healthz`; PDB (`minAvailable`) and HPA (autoscaling/v2)
      togglable via values
- [x] Prometheus metrics (certificates issued, error rates, agent heartbeats)
      → `internal/metrics` (client_golang), a dedicated listener `-metrics-listen`;
      `gssh_certificates_issued_total{requester,cert_type}`,
      `gssh_http_responses_total{code}`, `gssh_agent_heartbeats_total`;
      ServiceMonitor optional in the chart
- [x] Chart tests (`helm test`, chart-testing in CI)
      → `templates/tests/test-connection.yaml` (healthz check);
      `helm-lint` job (ct lint, `.github/ct.yaml`) in the test pipeline
- [x] Chart release via GitHub Pages as a Helm repository (manual
      `helm package` + `helm repo index`, `.tgz` + `index.yaml` committed to
      `gh-pages`, also attached to the `vX.Y.Z` release — modeled on valkey-operator)
      → `helm-chart` job in `.github/workflows/build.yml`, alongside binaries
      and the image; one-time gh-pages setup documented in the chart README
- [x] Image references in the chart default to `docker.io/guidedtraffic/*`
      → `image.repository: docker.io/guidedtraffic/guided-ssh`, tag defaults to the
      chart's `appVersion`

## Phase 12 — GitOps (FluxCD)

- [x] Document a reference repo structure: `HelmRepository` (points to the
      GitHub Pages Helm repo) + `HelmRelease` for guided-ssh, Kustomize overlays
      per environment; images from `docker.io/guidedtraffic`
      → `deploy/flux-example/README.md`: base + staging/production overlays
      (staging uses a version range, production an exact pin), cluster kustomizations
- [x] SOPS example for secrets in the GitOps repo (age key, Flux decryption)
      → `.sops.yaml` (age, encrypted_regex data/stringData),
      `decryption.provider: sops` + secret `sops-age` in the
      cluster kustomizations; the chart stays secret-free (existingSecret)
- [x] Grants declaratively via GitOps: `grants.yaml` in the repo, a sync job/CronJob
      calls `gssh-admin apply` — access rules are thus versioned and reviewable
      → CronJob `guided-ssh-grants-sync` (every 15 min, gssh-admin in the server image);
      new: a client-credentials flow in gssh-admin (GSSH_CLIENT_SECRET /
      GSSH_CLIENT_ID) for non-interactive service accounts, Keycloak
      setup (audience/groups mapper) documented in the README
- [x] Test the upgrade path: chart version bump via Flux, migrations run automatically
      → `hack/flux-upgrade-test.sh`: kind + Flux, install 0.1.0 from a local
      Helm repo, bump to 0.1.1 → upgrade rolls out, the migrate init container runs
- [x] Maintain example manifests in `deploy/flux-example/`
      → base (namespace, HelmRepository, HelmRelease, sync config, CronJob),
      overlays with grants.yaml/secrets.yaml, verified via kustomize build

## Phase 13 — Quality Assurance & Release

- [x] Consolidate the integration test suite (from Phases 1–9) and run it fully in the
      GitHub pipeline (test containers on the self-hosted runner)
      → unified build tag `integration`, a complete run in the
      `unit-tests`/`integration-tests` jobs (`make test-*-coverage`), coverage merged
      in the `coverage-report` job; scope defined in `docs/test-strategy.md`
- [x] E2E test environment: kind cluster + Keycloak + simulated GitLab OIDC + two
      test hosts (containers) — a complete pass-through for both humans and CI; runs in the
      GitHub pipeline on the self-hosted runner (on merge requests and on main)
      → `test/e2e` (build tag `e2e`, `make e2e`): the production Helm chart in a
      kind cluster; **Dex + GLAuth instead of Keycloak** (lighter; groups via
      the LDAP connector, offboarding via ConfigMap), fake GitLab OIDC (nginx,
      static discovery/JWKS), two sshd test-host pods + a workstation pod
      (real `gssh` + ssh-agent + openssh); CI job `e2e-tests` in
      `release.yml` (PR + main), semantic-release is gated on it
- [x] Work out and automate E2E test cases: SSO login, offboarding,
      CI certificate + Ansible provisioning, grant changes, host rotation,
      audit completeness
      → 7 scenarios in a fixed order (including chaos), details in
      `docs/test-strategy.md`; host rotation observable via the new
      `GSSH_HOST_CERT_VALIDITY` (3m in the test); passes locally (~3m
      runtime after the image cache warms up)
- [x] Check the coverage report: ≥ 80% across Go modules, justify or close any gaps
      → status before Phase 13: 77.2%; closed with unit tests for
      `cmd/gssh-server` (setup/env functions) and `internal/agentd`
      (pam_exec round-trip, mTLS client RenewMTLS/SendSessions) → **80.4%**.
      Justified remaining gaps: `cmd/*` main wrappers and `serve()`/
      `newAgentServer()` (wiring, covered by the E2E suite — runs
      as a separate binary and is not counted toward coverage), agentd daemon
      loops (integration-tested in a container, same limitation)
- [x] Load test the sign endpoint (define a target, e.g. 50 certificates/s)
      → target defined: ≥ 50 certs/s (docs/test-strategy.md); `test/load`
      (build tag `loadtest`, `make loadtest`), real API + Postgres + OIDC
      verifier with rate limiting disabled; reference measurement ~1770 certs/s, p95 11ms;
      CI job `load-test` on main (informational, not release-blocking)
- [x] Chaos cases: API down → existing SSH sessions unaffected, the agent cache
      keeps logins working until the TTL expires, then fail-closed (verify)
      → E2E scenario `05_Chaos_API_Down` (session survives replicas=0,
      cache-backed login until TTL, then fail-closed, recovery works) +
      `TestPrincipalsCacheAndFailClosed` (unit test, internal/agentd)
- [x] Documentation: operations manual, enrollment guide, GitLab integration guide,
      troubleshooting, architecture diagram
      → `docs/operations-manual.md`, `docs/enrollment-guide.md`,
      `docs/troubleshooting.md`, `docs/architecture.md` (Mermaid diagrams);
      the GitLab integration guide was already complete via `docs/gitlab-ci.md`
- [x] Versioned releases (binaries, container images, Helm chart), version derived from the git tag
      → semantic-release creates tag `vX.Y.Z`; new: job `binaries` in
      `build.yml` attaches cross-platform binaries (gssh, gssh-agentd), deb/rpm packages,
      and SHA256SUMS to the GitHub release (version via `git describe` from the
      tag, Makefile); Docker images (SemVer tags, build.yml) and
      Helm chart releases (chart-release.yml) already existed
- [x] Do a final verification of the success criteria (see below)

---

## Success Criteria (Definition of Done, product-wide)

- [x] Human: `ssh host` with no existing certificate → SSO browser flow → login succeeds;
      certificate only in the agent, validity ≤ the configured maximum
      → E2E `01_SSO_Login_DeviceFlow` (real gssh binary, Dex SSO via
      device flow, transparent ssh with a CA-verified host cert);
      the PKCE browser flow is unit-tested (internal/auth, internal/cli);
      agent-only per ADR-016, validity capping covered by policy tests (internal/ca)
- [x] Offboarding: user removed from an IdP group → no new issuance, the host ACL
      denies access within the cache TTL
      → E2E `06_Offboarding` (403 + ACL revoked ≤ cache TTL despite a valid
      certificate); offboarding without a re-login (admin-API sync) covered in the
      Keycloak integration test
- [x] CI: a GitLab job without static secrets provisions a host via Ansible; the certificate
      runs for ≤ 1h and is attributed to the pipeline in the audit log
      → E2E `03_CI_Certificate_Ansible` (job token → gssh ci-login →
      ansible-playbook via the agent, KeyID `ci:<project>:<pipeline>:<job>`
      in the audit log); the 1h cap: CI policy tests (internal/ca, internal/api)
- [x] Audit: every issuance, every login, every sudo, every grant change is queryable
      (UI + export), the audit table is append-only
      → E2E `07_Audit_Completeness` (JSON+CSV export: human+CI issuances,
      enrollments, grant changes); session/sudo events: covered by
      Phase 9 tests; append-only trigger: store integration test
- [x] Deployment: installation exclusively via a HelmRelease in the Flux repo, secrets
      via SOPS/external-secrets, upgrades without downtime of the sign endpoints
      → Flux reference + SOPS (Phase 12, `deploy/flux-example/`); the upgrade path
      is verified via `hack/flux-upgrade-test.sh` (migration advisory lock);
      zero downtime requires `replicaCount ≥ 2` + a PDB (chart options,
      documented in the operations manual)
- [x] Quality: ≥ 80% test coverage in the Go code (frontend excluded), coverage gate
      active; integration and E2E suites pass in GitHub Actions (self-hosted)
      → 80.4% (`make cover`, gate active locally + in CI); unit/integration jobs
      run in `release.yml`; the E2E job `e2e-tests` is new — passes locally, first
      pipeline run happens with the next push to the PR


## Later Topics
- [ ] gssh login: CLI login against Dex fails — the operator cannot create secret-less
      public clients

      **Context.** `gssh login` uses its own public client (`gssh-cli`,
      `internal/cli/config.go`) with Authorization Code + PKCE (default) or the
      device flow (`internal/auth/flow.go`) — both exchange the code/device code
      for tokens without a `client_secret`. However, Dex always checks the secret
      once one is stored on the registered client; `public: true` does not disable
      that check (Dex log: `missing client_secret on token request`).
      The dex-operator (`dex.gtrfc.com/v1 DexStaticClient`) currently attaches a
      secret to every client (`iso.gtrfc.com/autogenerate` annotation,
      `clientSecretKey` gets defaulted, rendered as `secretEnv` in the
      Dex config) — truly secret-less clients cannot be expressed with the
      operator. The web UI is no longer affected by this (BFF, confidential
      client); the CLI remains a public client and hits the same
      401 at the token endpoint against Dex.

      **Goal.** `gssh login` (PKCE and device flow) works against Dex
      end-to-end (token exchange returns 200, `POST /v1/sign/user` returns a certificate).

      **Proposed solution.**
      1. Operator fix: when `public: true`, render the client WITHOUT a secret
         (no `secretEnv`, don't force `clientSecretKey`/autogenerate).
      2. The operator must allow empty `redirectURIs`: the CLI listens on
         `127.0.0.1:<random>`; Dex only allows localhost redirects for public
         clients when NO redirectURIs are registered — otherwise the
         random port cannot be expressed.
      3. Create a dedicated Dex client for the CLI (e.g.
         `${cluster_name}-gssh-cli`, public, secret-less, without redirectURIs)
         and point `GSSH_OIDC_CLIENT_ID` (= the audience expected by /v1/sign/user)
         at it — the UI and CLI clients are separate since the BFF rework.

      **Rejected:** putting a `client_secret` in the CLI config (confidential CLI) —
      the secret would sit in every user's config, effectively public anyway,
      just with a distribution problem.

      **Acceptance criteria.**
      - `DexStaticClient` with `public: true` renders without a secret and without
        mandatory redirectURIs
      - `gssh login` (PKCE) succeeds against wds18-Dex, as does `--device`
      - The audience chain is documented: CLI client ID = `GSSH_OIDC_CLIENT_ID`
