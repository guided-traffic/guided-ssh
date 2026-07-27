# Production Setup Guide

An opinionated guide to running guided-ssh in production: what an ideal
deployment looks like, what to do, what to avoid, and what the
security-relevant settings actually protect.

Audience: the operator planning or reviewing a real installation. This guide
tells you *what* to set and *why*; the *how* lives in the
[operations manual](operations-manual.md) (procedures, config reference,
monitoring), the [chart README](../deploy/helm/guided-ssh/README.md)
(all Helm values), and the
[Flux example](../deploy/flux-example/) (GitOps reference).

## Reference architecture

The setup the project is designed around:

- **Kubernetes + GitOps.** The server runs from the Helm chart, deployed via
  FluxCD (HelmRelease); all configuration and secrets live in Git (SOPS) or an
  external secret store. Staging tracks a version range, production pins an
  exact chart version.
- **External PostgreSQL**, ideally [CloudNativePG](https://cloudnative-pg.io)
  with ≥ 3 instances and continuous backup (PITR). PostgreSQL is the *only*
  stateful component — its backup covers the entire platform.
- **Two ingress paths.** The HTTP API + web UI (`:8080`) sit behind a normal
  TLS-terminating ingress. The agent API (`:8443`) is mTLS and terminates TLS
  **in the application** — expose it via `agent.service.type=LoadBalancer` or
  an ingress with TLS passthrough, never through a terminating proxy.
- **Metrics stay internal.** `:9090` is scraped by Prometheus in-cluster
  (`metrics.serviceMonitor.enabled=true`) and is not exposed via ingress.
- **Audit events leave the cluster.** `GSSH_AUDIT_STREAM=true` (stdout JSON →
  log pipeline) and/or `GSSH_AUDIT_WEBHOOK_URL` feed the SIEM, so an external
  copy of the audit trail exists independently of the database.
- **≥ 2 replicas** with a PodDisruptionBudget — the server is stateless and
  scales horizontally; the sign endpoints stay available through node drains
  and rolling updates.

Component overview and auth-path diagrams: [architecture.md](architecture.md).

## Do / Don't

**Do**

- Use an **external PostgreSQL with tested backups** (CNPG PITR or pg_dump on
  a schedule) — see [Backup & DR](#backup--disaster-recovery).
- Keep **`GSSH_CA_MASTER_KEY` redundantly and separately** from the database
  and its backups (SOPS/Vault + offline copy). A DB backup without the master
  key is worthless for the CA.
- Decide the **CA mode consciously** (`managed` vs. `self-managed`) before
  go-live — switching later means re-anchoring trust.
- Set **both role groups** (`GSSH_ADMIN_GROUP`, `GSSH_AUDITOR_GROUP`) to
  dedicated IdP groups.
- Enable **`networkPolicy.enabled=true`**, the **ServiceMonitor**, and the
  [alerts from the operations manual](operations-manual.md#monitoring).
- Run **`replicaCount ≥ 2`** with `podDisruptionBudget.enabled=true`.
- Stream the **audit log to a SIEM** and set up
  [partition-based retention](audit-retention.md) (recommendation: 18 months).
- Use `sslmode=require` (or `verify-full`) for the **database connection**
  whenever the database is not in-cluster traffic secured otherwise.
- Pick **one host-install path per host** — one-command script *or* deb/rpm,
  never both ([host-rollout.md](host-rollout.md)).

**Don't**

- **Never `internalDatabase.enabled=true` in production.** It is an ephemeral
  sidecar: every pod restart starts with an empty database — and in `managed`
  mode that means a **new CA**. The chart's guard rails (mutually exclusive
  with a DB secret, no replicas) exist precisely so this cannot happen by
  accident.
- **Don't disable rate limiting** (`GSSH_SIGN_RATE_PER_MINUTE=0` is for load
  tests only) — it is the brute-force protection on the sign/enroll endpoints.
- **Don't set `config.rateLimit.trustProxy=true` without a trusted proxy** in
  front of the server — `X-Forwarded-For` can be forged by clients otherwise.
  (Behind your ingress it is correct, and it is the chart default; without a
  proxy the whole ingress would otherwise count as one client.)
- **Don't terminate TLS for the agent API** at a proxy — the mTLS client
  certificate must reach the application.
- **Don't put plain-HTTP URLs into the host rollout** — the server refuses
  them, and a cleartext `curl | sudo sh` would defeat the hash check and the
  SPKI pin.
- **Don't hand out the admin group broadly.** Every grant mutation is audited,
  but admins define who may log in where — treat membership like root.

## Security-relevant settings, explained

### CA: master key and CA mode

`GSSH_CA_MASTER_KEY` (32 bytes, base64) encrypts the CA private keys at rest
(AES-256-GCM) and derives the web UI's session key. **Loss of the master key
in `managed` mode is total loss of the CA**: the encrypted keys in `ca_keys`
become unusable and every host must be re-enrolled against a new CA. There is
no in-place master-key rotation; the compromise path is CA rotation plus a new
master key ([operations manual](operations-manual.md#ca-key-rotation)).

`secrets.ca.mode` decides where the CA private keys live:

| | `managed` (default) | `self-managed` |
|---|---|---|
| CA private keys | generated on first start, stored encrypted in the DB | mounted read-only from a Secret, never in the DB |
| Source of truth | the database (+ master key) | your Git repository (SOPS) |
| Rotation | code/DB-level today — not exposed via API or CLI | a commit: replace the key file, roll the deployment |
| DR | DB backup + master key | same key files + empty DB ⇒ same CA |

For GitOps-first operations `self-managed` is the stronger choice: rotation,
disaster recovery and environment cloning become Git operations, and the
database holds no key material at all. Full walkthrough and failure modes:
[self-managed-ca.md](self-managed-ca.md). The master key secret is required
in **both** modes (UI session key).

### Database

- `GSSH_DB_SSLMODE`: the driver default is `prefer`, which silently falls back
  to cleartext. Set `require` at minimum, `verify-full` for managed databases
  reachable beyond the cluster boundary.
- The application's DB role has **no `UPDATE`/`DELETE`/`TRUNCATE` on
  `audit_events`** (append-only trigger + grants); migrations run as the schema
  owner. Keep that role separation when provisioning users yourself
  ([audit-retention.md](audit-retention.md)).

### OIDC and role groups

- `GSSH_OIDC_ISSUER` / `GSSH_CLIENT_OIDC_CLIENT_ID`: humans authenticate with
  ID tokens whose audience must match the clients' public client ID; an issuer
  without that client ID is a startup error (fail-fast). An empty issuer
  disables the user sign endpoint entirely (503).
- **CI is a strictly separate issuer** (`GSSH_CI_ISSUER`, GitLab). User and CI
  tokens are never interchangeable — separate verifiers, and if both point at
  the same issuer the server refuses to start with identical audiences
  (`checkAudienceSeparation`,
  [security-review-token-exchange.md](security-review-token-exchange.md)).
- `GSSH_ADMIN_GROUP`, `GSSH_AUDITOR_GROUP`: role mapping is fail-closed — an
  empty group grants the role to nobody, no admin group means no admin
  mutations, both empty disables the admin API, and the web-UI login rejects
  users without any role. Set both to dedicated IdP groups and manage
  membership in the IdP, not ad hoc.
- Give the **server its own confidential OIDC client** for the web-UI login
  (`GSSH_SERVER_OIDC_CLIENT_ID`, secret via `config.oidc.server.existingSecret`,
  redirect URI `<config.publicURL>/v1/auth/callback`). The UI is a BFF:
  server-side code flow, HttpOnly session cookie, tokens never reach the
  browser. Reusing the CLIs' public client (`GSSH_CLIENT_OIDC_CLIENT_ID`) is a
  startup error — one IdP client cannot be public and confidential at once.
- Enable **group sync** (`GSSH_KC_*`, Keycloak) so removing a user from a
  group offboards them within ~10 minutes even while their certificate is
  still valid (see [lifetimes and revocation](#certificate-lifetimes-and-revocation)).

### Agent API (mTLS)

The agent API authenticates hosts by mTLS client certificate; identity is
resolved per request against the host record, so a deleted host is void
immediately. `agent.tlsNames` (`GSSH_AGENT_TLS_NAMES`) must contain the
public DNS name agents dial — a mismatch surfaces as TLS failures on every
host. Expose the port with TLS passthrough only (see reference architecture).

### Rate limiting

Token bucket per client IP on the sign/enroll endpoints: request budget
(default 60/min, burst 20) plus a separate failure budget (default 10/min —
only 401/403 consume it; exhaustion returns 429). Defaults are sane for
production; tune with the metrics, not preemptively. Details:
[operations manual](operations-manual.md#rate-limiting-operations).

### Host rollout (one-command install)

Optional and off by default. If you enable it: HTTPS-only URLs, mandatory SPKI
pinning (three fail-closed sources — prefer `dial`, use `file` for
hairpin/split-horizon DNS, `static` only as a last resort), one-time
short-lived tokens, rate-limited public downloads. Read the full
[security model and residual risks](host-rollout.md) before enabling, and the
[pin-source guide](../deploy/helm/guided-ssh/README.md#which-pin-source-hostrolloutpinsource)
when choosing a source.

### Audit

The audit log is the platform's core promise: every issued certificate and
every admin decision, append-only at the database level. In production:

- `GSSH_AUDIT_STREAM=true` and/or `GSSH_AUDIT_WEBHOOK_URL` — an external SIEM
  copy makes after-the-fact tampering with the DB detectable and reduces the
  pressure for long in-DB retention.
- Retention via monthly partitions (`DETACH`/`DROP`, never row-wise), archive
  detached partitions before dropping: [audit-retention.md](audit-retention.md).

## Certificate lifetimes and revocation

Revocation is designed around **short lifetimes plus fast policy
enforcement**, not CRLs ([ADR-022](adr/022-revocation-short-lifetimes.md)):

- User certificates ≤ 16 h, CI ≤ 1 h (and capped at the job token's `exp`),
  host certificates 30 days — host and agent mTLS certificates renew
  automatically.
- Revoking a grant, deactivating a user, or removing an IdP group takes effect
  on the hosts within roughly **cache TTL (5 min) + sync interval (5 min)** —
  independent of the remaining certificate lifetime, because sshd asks the
  agent's principals lookup on every login. If the API is unreachable, hosts
  **fail closed** after the cache TTL.
- The emergency path for CA compromise is CA rotation ("nuclear option"):
  new key, agents pick up the bundle within an hour, retire the old key ⇒ all
  previously issued certificates become invalid. Note that in `managed` mode
  rotation is currently a code/DB-level intervention (no API/CLI); in
  `self-managed` mode it is a Git commit
  ([operations manual](operations-manual.md#ca-key-rotation)).

## Backup & disaster recovery

Short version — the full procedure is in the
[operations manual](operations-manual.md#backup--restore):

- Everything stateful is in PostgreSQL; back up the database and you have the
  platform. **But**: in `managed` mode the CA keys in that backup are
  encrypted — store `GSSH_CA_MASTER_KEY` separately from the backup *and* from
  the database (that separation is the point of the encryption).
- In `self-managed` mode the CA depends on the GitOps repo and the SOPS/age
  key instead — back those up offline; the DB backup then covers inventory,
  grants and audit only.
- Restore = restore DB, provide the same secrets, start the deployment.
  Migrations run idempotently; agents and CLIs need nothing as long as
  `ca_keys` and `hosts` are intact.

## Upgrades

- Staging tracks a chart version range, production pins exactly; bumps go
  through merge requests and Flux rolls them out.
- `replicaCount ≥ 2` + PDB keep the sign endpoints available during rolling
  updates. Migrations run in an init container serialized by an advisory
  lock and must stay backward-compatible with the previous version
  (forward-only; a Helm rollback rolls back the app, not the schema).
- Host agents are versioned independently and update via package management —
  no re-enrollment ([operations manual](operations-manual.md#upgrades)).

## Pre-go-live checklist

- [ ] External PostgreSQL with tested restore (not `internalDatabase`)
- [ ] `GSSH_CA_MASTER_KEY` stored redundantly, separate from DB and backups
- [ ] CA mode decided; if `self-managed`: key files generated, SOPS key backed up offline
- [ ] `GSSH_DB_SSLMODE=require` (or stricter) for out-of-cluster databases
- [ ] OIDC issuer + client ID set; separate UI client with secret; CI issuer separate
- [ ] Admin/auditor groups mapped to dedicated IdP groups
- [ ] Group sync enabled (offboarding without manual steps)
- [ ] Agent API exposed via TLS passthrough/LB; `agent.tlsNames` = public DNS name
- [ ] `networkPolicy.enabled=true`, `podDisruptionBudget.enabled=true`, `replicaCount ≥ 2`
- [ ] ServiceMonitor + alerts (error rate, 401/403 spike, 429, heartbeats, no issuances)
- [ ] Audit stream to SIEM; retention/partitioning scheduled
- [ ] If host rollout enabled: pin source chosen and tested, HTTPS everywhere
- [ ] Break-glass procedure understood: CA rotation path and its current limits
