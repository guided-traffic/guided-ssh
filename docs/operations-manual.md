# Operations Manual

Audience: operators of the guided-ssh platform (Kubernetes/GitOps).
Related documents: [Architecture](architecture.md),
[Enrollment Guide](enrollment-guide.md), [Troubleshooting](troubleshooting.md),
[GitLab CI Integration](gitlab-ci.md), [Audit Retention](audit-retention.md),
[Self-managed CA Keys](self-managed-ca.md), [ADR Index](adr/README.md).

## Architecture overview

A single Go binary (`gssh-server`) bundles the REST API, certificate
authority (CA), embedded web UI, agent API (mTLS, dedicated port), and
metrics endpoint (dedicated port). Persistence is exclusively in PostgreSQL;
the CA private keys are stored AES-256-GCM encrypted in the `ca_keys` table
(ADR-014) — except in `self-managed` mode, where they come from files
mounted from a secret and are never written to the database
([self-managed-ca.md](self-managed-ca.md)). Three strictly separated auth
paths: OIDC for humans, GitLab OIDC for CI, mTLS for host agents (ADR-008).
Details and diagrams: [architecture.md](architecture.md).

## Deployment

- **Helm chart** `deploy/helm/guided-ssh` — installation, secrets,
  PostgreSQL connectivity (external/CloudNativePG), agent service (TLS
  passthrough), ServiceMonitor: see [chart README](../deploy/helm/guided-ssh/README.md).
- **GitOps (FluxCD)** — HelmRelease from the GitHub Pages Helm repo,
  Kustomize overlays per environment, SOPS secrets, declarative grants via
  a sync CronJob: see [deploy/flux-example/README.md](../deploy/flux-example/README.md).

The server starts with `-listen :8080` (HTTP API + UI); optionally
`-agent-listen :8443` (agent API, mTLS) and `-metrics-listen :9090`
(Prometheus). Subcommands: `gssh-server migrate` (migrations only,
init container) and `gssh-server enroll-token` (host enrollment token,
see [enrollment-guide.md](enrollment-guide.md)).

## Configuration reference (environment variables)

All values from `cmd/gssh-server/main.go`; mapped 1:1 in the Helm chart via
`config.*`/`secrets.*`.

| Variable | Default | Effect |
|---|---|---|
| `GSSH_DB_HOST` | — (required) | PostgreSQL host |
| `GSSH_DB_PORT` | `5432` | PostgreSQL port |
| `GSSH_DB_USER` | — (required) | database user |
| `GSSH_DB_PASSWORD` | — (required) | database password (special characters are fine, URL-escaped) |
| `GSSH_DB_NAME` | — (required) | database name |
| `GSSH_DB_SSLMODE` | `prefer` | connection `sslmode` (`disable`, `require`, `verify-full`, …) |
| `GSSH_CA_MASTER_KEY` | — (required in both CA modes) | master key for CA key encryption: 32 bytes, base64 |
| `GSSH_CA_MODE` | `managed` | `managed` = CA keys are generated and stored encrypted in `ca_keys`; `self-managed` = all three CAs come as files from a secret ([self-managed-ca.md](self-managed-ca.md)) |
| `GSSH_CA_USER_KEY_FILE` | empty | user CA: OpenSSH private key PEM; `self-managed` only (required there, forbidden in `managed`) |
| `GSSH_CA_HOST_KEY_FILE` | empty | host CA: OpenSSH private key PEM; as above |
| `GSSH_CA_MTLS_KEY_FILE` | empty | agent mTLS CA: PKCS#8 PEM (Ed25519); as above |
| `GSSH_CA_MTLS_CERT_FILE` | empty | agent mTLS CA: X.509 CA certificate (PEM, `CA:TRUE`, `keyCertSign`); as above |
| `GSSH_OIDC_ISSUER` | empty | issuer URL of the IdP (shared by both OIDC clients); empty ⇒ `/v1/sign/user` disabled (503) |
| `GSSH_CLIENT_OIDC_CLIENT_ID` | empty | public OIDC client of the gssh/gssh-admin CLIs (no secret); expected audience of bearer ID tokens; missing while issuer is set ⇒ startup error (fail-fast) |
| `GSSH_CI_ISSUER` | empty | GitLab base URL (OIDC issuer); empty ⇒ `/v1/sign/ci` disabled (503) |
| `GSSH_CI_AUDIENCE` | `guided-ssh` | expected audience of the GitLab job tokens |
| `GSSH_KC_BASE_URL` | empty | Keycloak base URL for group sync |
| `GSSH_KC_REALM` | empty | Keycloak realm |
| `GSSH_KC_CLIENT_ID` | empty | service-account client of the sync; empty ⇒ group sync disabled |
| `GSSH_KC_CLIENT_SECRET` | empty | client secret of the sync client |
| `GSSH_KC_SYNC_INTERVAL` | `5m` | sync interval (Go duration) |
| `GSSH_AGENT_TLS_NAMES` | `localhost,127.0.0.1` | SANs of the agent API's mTLS server certificate (comma-separated) |
| `GSSH_AGENT_PROXY_PROTOCOL` | empty | `true` ⇒ PROXY protocol (v1/v2) on the agent listener, so the audit log records the agent's real IP instead of the proxy's. Must be enabled **before** the proxy starts sending the header (and disabled after it stops) — otherwise the endpoint breaks |
| `GSSH_AGENT_PROXY_TRUSTED` | empty | who may send a PROXY header: comma-separated CIDRs, IPs, or DNS names (headless Service of the proxy pods; re-resolved every 15s, unresolvable at startup ⇒ startup error). Empty with the feature on ⇒ the header is required from **every** connection |
| `GSSH_ADMIN_GROUP` | empty | IdP group of admins; empty ⇒ no admin mutations (fail-closed) |
| `GSSH_AUDITOR_GROUP` | empty | IdP group of auditors: all read views plus audit log read/export; admin includes this role. Both groups empty ⇒ admin API fully disabled; an empty group grants the role to nobody, and the web-UI login rejects users without any role |
| `GSSH_SERVER_OIDC_CLIENT_ID` | empty | confidential OIDC client of the server itself (server-side UI login/BFF); set together with the secret, must differ from `GSSH_CLIENT_OIDC_CLIENT_ID` (startup error otherwise) |
| `GSSH_SERVER_OIDC_CLIENT_SECRET` | empty | client secret of the server's OIDC client; ID and secret both empty ⇒ `/v1/auth` (UI login) disabled |
| `GSSH_SERVER_OIDC_SCOPES` | `openid,profile,email,groups` | scopes of the server-side UI login (comma-separated) |
| `GSSH_UI_SESSION_TTL` | `12h` | lifetime of the UI session cookie (Go duration) |
| `GSSH_PUBLIC_URL` | empty | external public base URL (UI login redirect, `install_command`, client install gate, pin self-dial) |
| `GSSH_DEV_UI_AUTH` | empty | **insecure dev mode**: the exact value `insecure` makes every request act as a logged-in admin without any IdP; any other non-empty value is a startup error |
| `GSSH_AUDIT_STREAM` | empty | `true` ⇒ committed audit events as JSON logs on stdout (SIEM) |
| `GSSH_AUDIT_WEBHOOK_URL` | empty | audit events additionally sent as a JSON array to this webhook |
| `GSSH_AUDIT_STREAM_INTERVAL` | `10s` | poll interval of the audit streamer (Go duration) |
| `GSSH_SIGN_RATE_PER_MINUTE` | `60` | request budget per client IP on the sign/enroll endpoints; `0` disables rate limiting entirely |
| `GSSH_SIGN_FAIL_PER_MINUTE` | `10` | failure budget per client IP (401/403 responses) |
| `GSSH_RATE_TRUST_PROXY` | empty | `true` ⇒ client IP taken from the last `X-Forwarded-For` entry (only behind a trusted proxy/ingress) |

## Secrets

Two required secrets (in the chart: `secrets.db.existingSecret` with the
individual Postgres connection data, `secrets.ca.existingSecret` with the CA
master key; key names customizable via `secrets.*.keys`, details in the
chart README):

- **`GSSH_DB_*`** — database access (host, port, user, password, name,
  SSL mode as individual keys, no DSN). Rotation: set a new DB password,
  update the secret, roll out; no data loss.
- **`GSSH_CA_MASTER_KEY`** — generation: `head -c 32 /dev/urandom | base64`
  (or `openssl rand -base64 32`). Encrypts all CA private keys
  (user, host, and mTLS CA) at rest. **Loss of the master key means total
  loss of the CA** — the encrypted keys in `ca_keys` become unusable, and
  all hosts would need to be re-enrolled against a new CA. Store it
  securely and redundantly (SOPS/Vault + offline copy). Rotating the
  master key itself is not implemented (re-encrypting `ca_keys` would be
  a manual DB intervention); the intended path in case of compromise is
  CA rotation (below) combined with a new master key and re-enrollment.

Both statements about the master key apply to the default `managed` mode.
With `GSSH_CA_MODE=self-managed` the CA private keys instead live as four
files in a dedicated secret (`secrets.ca.selfManaged.existingSecret`,
mounted read-only); the master key is still required because the web UI's
session key is derived from it. Generation, rotation via commit, and
failure modes: [self-managed-ca.md](self-managed-ca.md).

Optional: `GSSH_KC_CLIENT_SECRET` (group sync) and the client secret of the
GitOps sync service account (`GSSH_CLIENT_SECRET` for `gssh-admin`, see the
Flux README).

## Database operations

- **Migrations**: goose, embedded (ADR-012). In the Kubernetes deployment
  as an init container `gssh-server migrate` before every pod start; a
  Postgres advisory session lock serializes concurrent replicas — rollouts
  with multiple replicas are safe. The server also migrates idempotently
  at startup anyway (likewise with a lock). Migrations are forward-only and
  must remain backward-compatible with the previous version (Helm rollback
  via Flux).
- **Audit retention**: `audit_events` is append-only (trigger + DB grants)
  and partitionable by month; retention proceeds via `DETACH`/`DROP` of
  entire partitions, never row by row. Procedure, role scheme, and
  recommendation (18 months): [audit-retention.md](audit-retention.md).
- **DB roles**: the application role has no `UPDATE`/`DELETE`/`TRUNCATE` on
  `audit_events`; migrations run as the schema owner (see audit-retention.md).

## Monitoring

Prometheus metrics on a dedicated listener (`-metrics-listen`, chart port
9090, not exposed via ingress; `metrics.serviceMonitor.enabled=true` for
the Prometheus Operator):

| Metric | Labels | Meaning |
|---|---|---|
| `gssh_certificates_issued_total` | `requester` (user/ci/host), `cert_type` (user/host) | successfully issued SSH certificates |
| `gssh_http_responses_total` | `code` | HTTP responses by status code (API and agent endpoints) |
| `gssh_agent_heartbeats_total` | — | agent contacts (successful mTLS requests, stamp `last_seen_at`) |

`GET /healthz` is the liveness/readiness probe (chart default).

Useful alerts:

- **Error rate**: `rate(gssh_http_responses_total{code=~"5.."}[5m])` > 0
  sustained ⇒ server/DB problem.
- **Auth error spike**: rising `code="401"`/`code="403"` rate ⇒
  IdP problem, stale configuration, or an attack attempt (the failure
  budget throttles to 429).
- **Rate limit engaged**: `code="429"` persistently > 0 ⇒ check limits
  (`GSSH_SIGN_RATE_PER_MINUTE`) or investigate abuse.
- **Agent heartbeats stop**:
  `rate(gssh_agent_heartbeats_total[15m]) == 0` for enrolled hosts ⇒
  agent API unreachable (service/load balancer/mTLS); hosts then run on
  the fail-closed cache (logins fail after `cache_ttl`).
- **No issuances**: `rate(gssh_certificates_issued_total[1h]) == 0`
  during normal working hours ⇒ check the sign path.

In addition: structured JSON logs on stdout (`kubectl logs`), audit events
to the SIEM via `GSSH_AUDIT_STREAM=true`/`GSSH_AUDIT_WEBHOOK_URL`
([web-ui.md](web-ui.md)).

## CA key rotation

The CA supports multiple keys per purpose with lifecycle
`active → retiring → retired` (`CA.Rotate`/`CA.RetireKey` in `internal/ca`):
`Rotate` creates a new active key and moves the previous ones to `retiring`;
the bundles (`GET /v1/ca/bundle/{user|host}`, fetched hourly by the agent)
contain both active **and** retiring keys — the transition window during
which old certificates remain valid. `RetireKey` permanently removes a key
from the bundle (audited as `ca.key_rotated`/`ca.key_retired`).

**As of today, rotation is not exposed via the admin API or CLI** —
there is no endpoint and no `gssh-server` subcommand for it. Triggering it
currently means intervening at the code/DB level (the state transitions
are plain `ca_keys` updates; a new key requires encryption with the
master key, i.e. the `CA.Rotate` code path). For the emergency case
(CA compromise), the procedure is described in
[ADR-022](adr/022-revocation-short-lifetimes.md) as the "nuclear option":
roll out a new key, agents pick up the bundle within an hour, retire the
old key ⇒ all old certificates become invalid; all active users need
re-issuance.

In `self-managed` mode, in-app rotation is locked (`CA.Rotate` returns an
error): there, rotation is a commit in the GitOps repo — deploy the new
key, the deployment rolls out, the old key automatically moves to
`retiring` and stays in the bundle until manually set to `retired`
([self-managed-ca.md](self-managed-ca.md#rotation)).

The agents' **mTLS client certificates**, on the other hand, rotate
automatically (at 2/3 of their 1-year lifetime, via
`POST /v1/agent/renew-mtls`), as do the **host certificates** (at 2/3 of
their 30-day lifetime) — no operational action needed.

## Rate-limiting operations

Token bucket per client IP on `POST /v1/sign/user`, `POST /v1/sign/ci`, and
`POST /v1/enroll` (`internal/api/ratelimit.go`):

- **Request budget**: default 60/min, burst 20 (with a configured rate:
  burst = max(10, rate/3)).
- **Failure budget**: default 10/min — only 401/403 responses consume it;
  once exhausted, 429 is returned (`Retry-After: 60`). Brute-force protection.
- Behind an ingress/proxy, set `GSSH_RATE_TRUST_PROXY=true` (chart default
  `config.rateLimit.trustProxy: true`), otherwise the proxy IP counts as a
  single client and throttles all users together. Leave it off without a
  trusted proxy — the header can be forged.
- `GSSH_SIGN_RATE_PER_MINUTE=0` disables rate limiting entirely (load tests).
- Memory protection: max. 65,536 tracked IPs; inactive entries (> 5 min)
  are evicted. Body limit of the exchange endpoints: 64 KiB.

## Revocation

Summary of [ADR-022](adr/022-revocation-short-lifetimes.md):

1. **Short lifetimes as the primary mechanism**: user certificates ≤ 16 h,
   CI ≤ 1 h (additionally capped at the token `exp`, i.e. the job timeout),
   host 30 days.
2. **Fast revocation via the principals lookup**: revoking a grant,
   deactivating a user, or removing an IdP group takes effect independently
   of the remaining lifetime of issued certificates — on the host side
   within the cache TTL (default 5 min) + sync interval (5 min), i.e.
   ~10 min; fails closed if the API is unreachable.
3. **mTLS agents**: identity is resolved against the host record on every
   request — a deleted host means the certificate is immediately void.
4. **KRL/`RevokedKeys` distribution**: deliberately not yet implemented
   (planned future enhancement).
5. **Nuclear option**: CA rotation (above).

## Backup & restore

- **All stateful data lives in PostgreSQL** — regular Postgres backups
  (pg_dump/PITR or CloudNativePG backup) cover the entire platform: hosts,
  grants, certificate metadata, audit log, `ca_keys`.
- The CA keys in the backup are AES-256-GCM encrypted — **a DB backup
  without the corresponding `GSSH_CA_MASTER_KEY` is worthless for the CA**.
  Store the master key separately from the backup (and separately from
  the DB — that is the point of the encryption).
- In `self-managed` mode, no key material lives in the database: the CA
  then depends on the GitOps repo and the SOPS key, not on the DB backup.
  An empty database plus the same mounted keys yields the same CA again
  ([self-managed-ca.md](self-managed-ca.md)) — for that, the offline state
  of the key files and the age/PGP key must be backed up.
- Restore: restore the database, provide the secrets (DSN, master key)
  unchanged, start the deployment — migrations run idempotently. Agents and
  CLIs need nothing new as long as `ca_keys` and `hosts` are intact.
- Audit long-term archive: export detached monthly partitions before the
  `DROP` (audit-retention.md); SIEM streaming reduces the dependency on
  long DB retention.

## Upgrades

- **Helm/Flux**: staging follows a version range, production pins exactly;
  bump via merge request, Flux rolls it out (Flux README). The Docker tag
  follows the chart's `appVersion`.
- **Zero downtime**: `replicaCount ≥ 2` (or HPA `minReplicas: 2`),
  `podDisruptionBudget.enabled=true` (`minAvailable: 1`); a rolling update
  of the deployment keeps the sign endpoints available.
- **Migrations during rollout**: init container `migrate` with an advisory
  lock — new and old replicas run against the same schema during the
  rollout, so migrations must remain backward-compatible with the previous
  version (forward-only; rollback via `upgrade.remediation.retries` only
  rolls back the application, not the schema).
- The full path is automated and testable: `hack/flux-upgrade-test.sh`
  (kind + Flux, install → bump → upgrade including the migration run).
- Host agents are versioned independently (deb/rpm); the agent API must be
  treated as backward-compatible — agent updates via package management,
  no re-enrollment needed.
