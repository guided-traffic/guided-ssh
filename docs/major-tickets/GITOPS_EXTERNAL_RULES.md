# GitOps-owned rules — ConfigMap provisioning & manual-edit switch

Status: **draft / planned**

Goal: access rules (host grants) and CI rules (CI grants) are managed
declaratively via GitOps. In-app editing (web UI / CRUD API) becomes an
opt-in feature that is **off by default**, and the Helm chart can point each
rule domain at a separately maintained ConfigMap that the server reconciles
from continuously.

---

## Motivation

1. Rules can currently be edited in the web UI (and via the CRUD API) at any
   time. In a GitOps-managed deployment this creates a second writer: manual
   edits drift from the Git state and are silently overwritten on the next
   `gssh-admin apply` run.
2. The existing GitOps path is an out-of-process CronJob
   ([grants-sync-cronjob.yaml](../../deploy/flux-example/apps/base/guided-ssh/grants-sync-cronjob.yaml))
   that needs its own OIDC client credentials and a 15-minute schedule. The
   Helm chart itself has no way to feed rules to the server.
3. There is no way to declare "rules are owned by Git" — the UI happily offers
   Add/Edit/Delete to every admin.

Precedent in this codebase: `secrets.ca.mode: managed | self-managed` is the
existing "who owns this data — the app or GitOps?" switch, enforced by hard
errors on in-app mutation ([SELF_MANAGED_CA.md](SELF_MANAGED_CA.md)). This
ticket applies the same philosophy to rules.

---

## Design decisions

### D1 — Two independent switches: manual provisioning (global) and file source (per domain)

- **`GSSH_MANUAL_RULES`** (bool, `"true"` enables; anything else = off,
  following the [`envAuditStream` pattern](../../cmd/gssh-server/main.go#L115)):
  gates the *interactive* CRUD endpoints (`POST`/`PUT`/`DELETE` on
  `/v1/admin/grants…` and `/v1/admin/ci-grants…`) for both domains.
  **Default off** — in-app editing is an opt-in.
- **`GSSH_HOST_RULES_FILE`** / **`GSSH_CI_RULES_FILE`** (paths, optional,
  independent per domain): when set, the server reconciles that domain from
  the file. A file-owned domain rejects **all** API writes — CRUD *and*
  `…/apply` — regardless of `GSSH_MANUAL_RULES`. One writer per domain, ever.

The `…/apply` endpoints stay available for domains **without** a file source:
that is the existing CronJob/`gssh-admin apply` GitOps path, which keeps
working unchanged. Matrix:

| `GSSH_MANUAL_RULES` | file source for domain | CRUD API | apply API | UI editing |
|---|---|---|---|---|
| off (default) | unset | 403 | allowed | hidden |
| on | unset | allowed | allowed | shown (today's behavior) |
| any | set | 403 | 403 | hidden |

### D2 — Default flip is a breaking change, on purpose

Today every admin can edit rules in the UI. After this change the chart
default (`config.rules.manualProvision: false` → `GSSH_MANUAL_RULES` unset)
disables that. Existing users who want UI editing must set
`config.rules.manualProvision: true`. Gets a migration section in the chart
README, next to the existing "Migration: server/client OIDC split" section.

### D3 — File format: the existing declarative YAML, split per domain

Reuse the schema already defined for `gssh-admin apply`
([apply.go:13-59](../../internal/admincli/apply.go#L13)) so examples,
docs and muscle memory transfer 1:1 — but each file carries only its own
domain:

- host rules file: top-level `grants:` (list of `grantEntry`)
- CI rules file: top-level `ci_grants:` (list of `ciGrantEntry`)

Parsing rules (strict, because the file is fully authoritative):

- Decode with `yaml.KnownFields(true)` — unknown/misspelled keys are errors,
  not silently ignored. A typo must never be interpreted as "empty file →
  delete everything".
- The expected top-level key **must be present**. `grants: []` explicitly
  deletes all host grants; a file without the `grants:` key is a validation
  error. Same for `ci_grants:`.
- A `ci_grants:` key in the host file (and vice versa) is an error.

The parsing code moves from `internal/admincli` into a small shared package
`internal/rulespec` (entry types, `cli.Duration` handling, strict loaders);
`gssh-admin apply` keeps its combined-file semantics on top of it.

### D4 — Reconcile loop: apply every 30 s, no watch dependency

The server applies the file(s) through the existing transactional
declarative-apply store methods
([`ApplyGrants`](../../internal/store/grants.go#L222),
[`ApplyCIGrants`](../../internal/store/ci_grants.go#L293)):

- **Startup**: file missing or invalid → **fail fast** (exit with a clear
  error). A wrong path or broken ConfigMap is a deployment bug and should be
  visible as a crash loop in GitOps, consistent with the fail-closed
  philosophy of [`checkLegacyEnv`](../../cmd/gssh-server/main.go#L264).
- **Runtime loop**: every 30 s, parse + apply. `ApplyGrants` is idempotent
  and only writes audit events on actual changes, so no hashing/fsnotify is
  needed (no new dependency) — and the loop doubles as drift correction: any
  out-of-band DB change is reverted on the next tick, which is exactly the
  GitOps contract. Kubernetes propagates ConfigMap volume updates within
  ~1 min anyway, so 30 s polling loses nothing over inotify.
- **Runtime errors** (file transiently invalid mid-update): keep the last
  applied state, log the error, increment
  `gssh_rules_file_sync_errors_total{domain}` in
  [internal/metrics](../../internal/metrics/metrics.go), retry next tick.
  The server stays up — a bad rules push must not take down certificate
  signing.
- Log one info line per tick **only when** Created+Updated+Deleted > 0
  (the `ApplyResult` counts).

### D5 — Audit actor

File-driven applies write the same audit events as API applies, with actor
`system:rules-file` (host) / `system:rules-file` (ci) — distinguishable from
human/CI actors in the audit log.

### D6 — API error semantics

Blocked writes return **403** with a machine-readable code in the error body:

- `manual_rules_disabled` — CRUD blocked because `GSSH_MANUAL_RULES` is off.
  Message points at `gssh-admin apply` / the chart value.
- `rules_file_managed` — domain is owned by a rules file; message names the
  env var that owns it.

Documented in [openapi.yaml](../../api/openapi.yaml) for the affected paths.
`gssh-admin` needs no change — it already prints server error messages.

### D7 — UI learns editability from `/v1/ui/config`

Extend [`UIConfig`](../../internal/api/server.go#L109) (unauthenticated
bootstrap — these flags are not sensitive):

```json
{ "grants_editable": false, "ci_grants_editable": false }
```

Computed server-side: `editable = manualRules && no file source for domain`.
The UI keeps its role gate and **additionally** requires the flag:
Add/Edit/Delete in [grants.ts](../../web/src/app/features/grants.ts) and
[ci.ts](../../web/src/app/features/ci.ts) render only for
`session.isAdmin() && config.grants_editable` (resp. `ci_grants_editable`).
When not editable, the page shows a passive hint instead of the buttons:
*"Rules are managed declaratively (GitOps) — in-app editing is disabled."*
Pages stay visible for auditors/admins (read-only), routes unchanged.

### D8 — Helm values shape

```yaml
config:
  rules:
    # In-app rule editing (web UI / CRUD API). Off by default: rules are
    # expected to be managed declaratively.
    manualProvision: false            # default
    host:
      existingConfigMap: ""           # name of a ConfigMap in the release namespace
      key: host-rules.yaml            # key inside that ConfigMap; default
    ci:
      existingConfigMap: ""
      key: ci-rules.yaml              # default
```

- Each configured ConfigMap is mounted as its own volume using an `items:`
  projection (`key: <key>` → `path: rules.yaml`), mount path
  `/etc/guided-ssh/rules/host/` resp. `/etc/guided-ssh/rules/ci/`, read-only.
  **No `subPath`** — subPath mounts never receive ConfigMap updates; `items:`
  projections do. Env vars then point at the fixed target file name:
  `GSSH_HOST_RULES_FILE=/etc/guided-ssh/rules/host/rules.yaml`.
- Follows the existing optional-mount pattern
  ([deployment.yaml:216-270](../../deploy/helm/guided-ssh/templates/deployment.yaml#L216)).
- [`guided-ssh.validateValues`](../../deploy/helm/guided-ssh/templates/_helpers.tpl#L97)
  **fails the render** when `manualProvision: true` is combined with any
  `existingConfigMap` — mixed mode (one domain Git-owned, the other
  hand-edited) is deliberately not offered by the chart; the file owner
  wins server-side anyway (D1). Anyone who truly needs mixed mode can set
  the env vars directly via `config.extraEnv`.
- The chart does **not** template the rules ConfigMaps themselves — they are
  "separately maintained" by design (kustomize `configMapGenerator`, Flux,
  plain manifests). README shows examples.

### D9 — New environment variables

| Variable | Meaning | Default |
|---|---|---|
| `GSSH_MANUAL_RULES` | `"true"` enables in-app rule CRUD (UI + API) | off |
| `GSSH_HOST_RULES_FILE` | path to declarative host-rules YAML; sets host domain to file-owned | unset |
| `GSSH_CI_RULES_FILE` | path to declarative CI-rules YAML; sets CI domain to file-owned | unset |

Registered in the [env const block](../../cmd/gssh-server/main.go#L49) with
the usual comments.

---

## Implementation plan

### Phase 1 — shared spec package `internal/rulespec` ✅

- [x] Extract `grantEntry`, `ciGrantEntry` and the YAML mapping from
      [apply.go](../../internal/admincli/apply.go) into `internal/rulespec`
      (exported as `GrantEntry` / `CIGrantEntry` with a `Spec()` mapper each).
- [x] Strict loaders `LoadHostRules(path)` / `LoadCIRules(path)`:
      `KnownFields(true)`, required top-level key, wrong-domain key = error
      (D3). Return `[]store.GrantSpec` / `[]store.CIGrantSpec`.
      `CIGrantEntry.Spec()` resolves the `protected_only` default (absent ⇒
      true) exactly like the admin API does.
- [x] Rewire `internal/admincli` onto the shared package via
      `LoadCombined(path)`; combined-file semantics (`ci_grants` missing ⇒
      untouched) unchanged.
- [x] Unit tests: happy path, empty list, missing key, unknown key,
      wrong-domain key, bad duration. Existing admincli tests stay green.

**Behavior changes in `gssh-admin apply` (combined file), deliberate:**
strict decoding now rejects unknown/misspelled keys, and a file without a
top-level `grants:` key is an error instead of silently deleting all host
rules. Both follow D3's rationale; the flux-example files are unaffected.

### Phase 2 — server: gates + reconcile loop ✅

- [x] Env parsing for the three new vars in `serve()`
      ([main.go](../../cmd/gssh-server/main.go), `rulesConfigFromEnv`); the
      names live in [rulespec](../../internal/rulespec/rulespec.go) so
      server, API gates and reconciler spell them identically. Passed into
      `api.Deps.Rules`.
- [x] Write-gate in [admin_rules.go](../../internal/api/admin_rules.go),
      applied at route registration in
      [admin.go](../../internal/api/admin.go): CRUD handlers check manual
      flag + file ownership, apply handlers check file ownership; 403 with
      `manual_rules_disabled` / `rules_file_managed` in a JSON body (D1, D6).
      Reads stay open in every mode.
- [x] Reconciler [internal/rulesync](../../internal/rulesync/rulesync.go):
      startup apply with fail-fast, 30 s ticker, actor `system:rules-file`,
      per-domain error handling + `gssh_rules_file_sync_errors_total{domain}`
      metric, change-only info log (D4, D5). Started from `serve()` via
      `startRulesSync` alongside the other background loops.
- [x] Tests: API gate matrix (D1 table,
      [admin_rules_test.go](../../internal/api/admin_rules_test.go)),
      reconciler unit tests against a fake applier
      ([rulesync_test.go](../../internal/rulesync/rulesync_test.go)):
      both domains, empty list, per-domain isolation, invalid/missing file
      keeps state, loop recovery. The transactional apply semantics stay
      covered by the store integration tests.

**Decisions made while implementing:**

- Host entries without an explicit `issuer:` need a default issuer, which
  the API path takes from the admin's token. The reconciler has no token, so
  it uses `GSSH_OIDC_ISSUER`. Without that variable, such a file fails the
  startup apply with the store's "issuer is missing" error.
- `GSSH_MANUAL_RULES=true` together with a rules file logs a warning at
  startup and the file still wins (D1); the chart forbids the combination
  (Phase 4), the env path allows it.
- Local frontend development needs `GSSH_MANUAL_RULES=true` next to
  `GSSH_DEV_UI_AUTH=insecure` — noted in [docs/web-ui.md](../web-ui.md).

### Phase 3 — UI config + frontend ✅

- [x] `UIConfig` + handler: `grants_editable`, `ci_grants_editable`,
      computed per request from `Deps.Rules` via `RulesConfig.editable`
      ([server.go](../../internal/api/server.go),
      [admin_rules.go](../../internal/api/admin_rules.go)) (D7);
      [openapi.yaml](../../api/openapi.yaml) carries the UiConfig fields and
      a `RulesWriteForbidden` 403 (schema `RulesWriteError` with the two D6
      codes) on all eight rule write operations; API client regenerated
      (`make web-api`).
- [x] [grants.ts](../../web/src/app/features/grants.ts) /
      [ci.ts](../../web/src/app/features/ci.ts): Add/Edit/Delete require
      `session.isAdmin() && <domain>Editable()`, read-only hint under the
      page subtitle. Flags come from the new
      [ConfigService](../../web/src/app/core/config.service.ts) (loads
      `/v1/ui/config` once, defaults to *not* editable).
- [x] Mock mode: `mockUiConfig` carries both flags,
      [mock-api.interceptor.ts](../../web/src/app/core/mock/mock-api.interceptor.ts)
      serves `gitops` / `gitops-host` / `gitops-ci` variants via
      `localStorage['gssh-mock-rules']` (documented in
      [docs/web-ui.md](../web-ui.md)).
- [x] Tests: [grants.spec.ts](../../web/src/app/features/grants.spec.ts) /
      [ci.spec.ts](../../web/src/app/features/ci.spec.ts) for both flag
      states, `TestUIConfigEditableFlags`
      ([admin_ui_test.go](../../internal/api/admin_ui_test.go)) for the
      server-side matrix.

**Decisions made while implementing:**

- The **CI service-account toggle stays ungated**, deviating from the
  Phase-3 bullet above. Service accounts are not part of the declarative
  rule files (no `service_accounts:` key), Phase 2 does not gate
  `PATCH /v1/admin/service-accounts/{id}` server-side, and the toggle is the
  per-project kill switch. Hiding a control the server still accepts would
  remove an incident-response path from the UI without making anything more
  declarative. The CI page's hint says so explicitly.
- The hint renders only once `/v1/ui/config` has been loaded
  (`ConfigService.loaded()`), so the read-only text does not flash while the
  page boots. If the config request fails, neither buttons nor hint appear —
  fail-closed.
- `createGrant`'s existing plain-text `403` in the OpenAPI spec now points
  at `RulesWriteForbidden`; its description names the role case (text/plain)
  so the role gate stays documented.

### Phase 4 — Helm chart

- [ ] `values.yaml`: `config.rules` block (D8) with doc comments.
- [ ] `deployment.yaml`: env wiring via `guided-ssh.env`, conditional
      volumes/mounts with `items:` projection, no subPath (D8).
- [ ] `validateValues`: fail on `manualProvision: true` + any
      `existingConfigMap` (D8).
- [ ] Chart tests (`templates/tests/`) + `helm template` golden checks for:
      defaults, manualProvision on, host-only ConfigMap, both ConfigMaps,
      custom key, invalid combination fails.
- [ ] Chart README: new "Rules provisioning (GitOps)" section + migration
      note for the default flip (D2).

### Phase 5 — docs & examples

- [ ] Repo [README.md](../../README.md): extend the GitOps pointer at the end
      of "Production deployment" with a worked example — see sketch below.
- [ ] [docs/grants.md](../../docs/grants.md): extend "Declarative management
      (GitOps)" with the ConfigMap-mount variant and the ownership matrix
      (D1).
- [ ] [deploy/flux-example](../../deploy/flux-example/): short note that the
      ConfigMap mount is the successor of the sync CronJob for chart-based
      installs (full rewrite of the example: see Out of scope).

### README example (target content, Phase 5)

Two separately maintained ConfigMaps plus values:

```yaml
# host-rules ConfigMap — maintained outside the chart, e.g. via kustomize
# configMapGenerator or a plain manifest in your GitOps repo
apiVersion: v1
kind: ConfigMap
metadata:
  name: gssh-host-rules
data:
  host-rules.yaml: |
    grants:
      - group: deployers
        tags:
          env: prod
        principals: [deploy]
        sudo: false
        max_validity: 8h
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: gssh-ci-rules
data:
  ci-rules.yaml: |
    ci_grants:
      - project: infra/ansible
        ref: main
        protected_only: true
        tags:
          env: prod
        principals: [deploy]
        max_validity: 1h
```

```yaml
# values.yaml
config:
  rules:
    manualProvision: false   # default; shown for clarity
    host:
      existingConfigMap: gssh-host-rules
      key: host-rules.yaml   # default key; set if your ConfigMap uses another
    ci:
      existingConfigMap: gssh-ci-rules
      key: ci-rules.yaml
```

Plus one sentence each on: empty list deletes all rules of that domain;
changes propagate within ~1–2 min (kubelet ConfigMap sync + 30 s reconcile);
UI editing is disabled while a domain is file-owned.

---

## Success criteria

- [ ] Fresh install with defaults: rules pages are read-only in the UI, CRUD
      API returns 403 `manual_rules_disabled`, `…/apply` works.
- [ ] `config.rules.manualProvision: true` restores today's behavior 1:1.
- [ ] With `existingConfigMap` set: rules appear after install without any
      CronJob; editing a ConfigMap propagates within ~2 min; removing an
      entry deletes the grant; all API writes for that domain return 403
      `rules_file_managed`.
- [ ] Broken ConfigMap content at runtime: last state stays active, error
      metric increments, server keeps signing.
- [ ] Broken path/content at startup: pod crash-loops with a clear message.
- [ ] `helm template` fails on `manualProvision: true` + `existingConfigMap`.
- [ ] Existing flux-example CronJob flow still works unmodified.

---

## Open points

### O1 — Ticket history

This file was empty when planning started (2026-07-27), although it was
referred to as containing prior work. If prior context exists elsewhere,
merge it here.

### O2 — Apply endpoint stays open by default — confirm

D1 keeps `…/apply` usable when no file source is set, so the existing
CronJob GitOps path works with `manualProvision: false`. If instead *all*
writes should require an explicit opt-in, the matrix needs a third switch —
current design says no. Confirm before Phase 2.

### O3 — Default flip communication

D2 changes behavior for every existing install on upgrade. Needs a
`feat!:`/BREAKING CHANGE marker in the release commit and a prominent chart
README note.

---

## Out of scope (deliberately)

- `gssh-admin rules validate -f <file>` offline-lint subcommand (cheap once
  `internal/rulespec` exists — nice CI pre-merge check; separate ticket).
- Per-domain manual flags (host manual, CI file-owned) in the chart — the
  server env vars technically allow it via `config.extraEnv`, the chart
  does not advertise it.
- Rewriting `deploy/flux-example/` from CronJob to ConfigMap mounts.
- fsnotify-based instant reload — 30 s polling is within ConfigMap
  propagation latency anyway (D4).
- Templating the rules ConfigMaps inside the chart — they are separately
  maintained by requirement.
