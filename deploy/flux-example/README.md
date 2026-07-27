# GitOps with FluxCD — reference setup for guided-ssh

This directory is the template for a standalone GitOps repo that runs
guided-ssh with FluxCD: Helm release from the GitHub Pages Helm repo,
Kustomize overlays per environment, SOPS-encrypted secrets, and declarative
access rules (`grants.yaml`) with periodic reconciliation. All images come
from `docker.io/guidedtraffic`.

## Repo structure

```
.
├── .sops.yaml                      # SOPS rule: secrets.yaml → age-encrypted
├── clusters/
│   ├── production/guided-ssh.yaml  # Flux Kustomization → apps/overlays/production
│   └── staging/guided-ssh.yaml     # Flux Kustomization → apps/overlays/staging
└── apps/
    ├── base/guided-ssh/
    │   ├── namespace.yaml
    │   ├── helmrepository.yaml     # https://guided-traffic.github.io/guided-ssh
    │   ├── helmrelease.yaml        # Chart guided-ssh, version pinned
    │   ├── sync-config.yaml        # gssh-admin configuration (api_url, issuer)
    │   └── grants-sync-cronjob.yaml# gssh-admin apply every 15 min
    └── overlays/
        ├── staging/                # version range, staging IdP/ingress
        │   ├── grants.yaml         # target state of the access rules
        │   └── secrets.yaml        # commit SOPS-encrypted!
        └── production/             # exact pin, prod values, 2 replicas
```

`HelmRepository` points to the GitHub Pages Helm repo that the
`chart-release` workflow updates on every chart version bump
(see `deploy/helm/guided-ssh/README.md`). `HelmRelease` references
it; environment differences are pure Kustomize patches on `values`.

## Bootstrap

Bootstrap Flux into the cluster and point it at the GitOps repo — this
creates the `GitRepository` `flux-system` that the cluster Kustomizations
reference:

```sh
flux bootstrap github \
  --owner=<org> --repository=<gitops-repo> \
  --branch=main --path=clusters/production
```

The file `clusters/production/guided-ssh.yaml` sits in the bootstrap path and
is therefore applied automatically; it syncs `apps/overlays/production` with
`prune: true` (deleted manifests also disappear from the cluster) and
`wait: true` (the Kustomization only becomes ready once the HelmRelease is
ready).

## Secrets with SOPS (age)

Generate an age key once and put the **private** key into the cluster as a
secret — only Flux (kustomize-controller) can decrypt with it:

```sh
age-keygen -o age.agekey            # note the public key, secure the private key
kubectl -n flux-system create secret generic sops-age \
  --from-file=age.agekey=age.agekey
```

Enter the public key in `.sops.yaml` (the value checked in there is a
placeholder). After that, every `secrets.yaml` gets encrypted before commit:

```sh
sops --encrypt --in-place apps/overlays/production/secrets.yaml
```

`encrypted_regex: ^(data|stringData)$` leaves metadata readable — diffs stay
reviewable. The cluster Kustomization decrypts on apply
(`decryption.provider: sops`, `secretRef: sops-age`). The `secrets.yaml`
files checked in here are placeholder examples; never commit plaintext in
the real repo. The chart itself never creates secrets, it only references
existing secrets (`secrets.db.existingSecret` with the individual Postgres
connection data, `secrets.ca.existingSecret` with the CA master key,
optionally `secrets.ca.selfManaged.existingSecret` with the CA keys)
— SOPS and external-secrets are therefore equally interchangeable.

## Self-managed CA keys

In the default mode (`secrets.ca.mode: managed`), the server generates the
CA private keys on first start and stores them encrypted in the database —
the database is therefore the trust anchor and cannot be managed via Git.
With `self-managed`, all three CAs (user CA, host CA, agent mTLS CA) come
from a mounted secret; the database only holds the public metadata, and
**this repo becomes the source of truth for the CA**. Background, failure
modes, and startup error messages:
[docs/self-managed-ca.md](../../docs/self-managed-ca.md).

### One-time generation

```sh
ssh-keygen -t ed25519 -f user-ca -N '' -C 'guided-ssh user ca'
ssh-keygen -t ed25519 -f host-ca -N '' -C 'guided-ssh host ca'
gssh-server gen-mtls-ca -out mtls-ca      # generates mtls-ca.key (0600) + mtls-ca.crt
```

Only the **private** files (`user-ca`, `host-ca`, `mtls-ca.key`) plus the
certificate `mtls-ca.crt` belong in the secret — **not** the `.pub` files;
the server derives the public keys itself. The keys must be unencrypted (no
passphrase protection), otherwise the server refuses to start.

Enter the four files as `stringData` in
`apps/overlays/<env>/secrets.yaml` (template: secret
`guided-ssh-ca-keys` in `apps/overlays/production/secrets.yaml` — the keys
checked in there are publicly known throwaway examples and **must** be
replaced) and then encrypt:

```sh
sops --encrypt --in-place apps/overlays/production/secrets.yaml
```

### Activation

The mode is a chart value, so it belongs in the environment's HelmRelease
patch (`apps/overlays/<env>/helmrelease-patch.yaml`):

```yaml
  values:
    secrets:
      ca:
        mode: self-managed
        # Master key remains mandatory: it derives the web UI's session key.
        existingSecret: guided-ssh-ca
        selfManaged:
          existingSecret: guided-ssh-ca-keys
```

On start, the server picks up the mounted keys into the `ca_keys` table
(without the private key, state `active`) — an empty database plus this repo
therefore reproduces the same CA.

### Rotation

Rotation is a commit, not an intervention on the running system:

1. Generate a new key pair (commands above, into an empty directory).
2. Replace the file content in the SOPS-encrypted secret (`sops
   apps/overlays/production/secrets.yaml`), commit, merge — Flux rolls out
   the deployment again.
3. On start, the server adopts the new key as `active` and sets the
   previous one to `retiring`. Its **public key stays in the CA bundle**
   (`GET /v1/ca/bundle/{user|host}`), so hosts keep trusting already-issued
   certificates; agents fetch the bundle hourly.
4. Once all certificates signed with the old key have expired
   (user certificates ≤ 16 h, host certificates 30 days), retire the old key
   for good — currently via SQL, an admin command is still missing:

   ```sql
   UPDATE ca_keys SET state = 'retired', retired_at = now()
    WHERE purpose = 'user' AND state = 'retiring';
   ```

A key already set to `retired` must not be mounted again — the server then
aborts on start with a corresponding message.

The transition window only applies to the SSH CAs: the server checks the
agents' client certificates exclusively against the **active** mTLS CA.
Rotating `mtls-ca.key`/`mtls-ca.crt` invalidates all issued agent
certificates and requires re-enrollment of the hosts — so don't "co-rotate"
these three files when only the user CA is meant to be swapped.

## Declarative grants (GitOps)

`apps/overlays/<env>/grants.yaml` is the versioned target state of the
access rules (format: `docs/grants.md`). The CronJob
`guided-ssh-grants-sync` calls `gssh-admin apply -f grants.yaml` against the
admin API every 15 minutes — changes to access rules thus run as a
reviewable merge request; whatever is missing from the file gets deleted.
Immediately instead of waiting for the next tick:

```sh
kubectl -n guided-ssh create job --from=cronjob/guided-ssh-grants-sync sync-now
```

The `…/apply` endpoint the CronJob uses stays open with the chart defaults,
so this flow works unmodified. What the defaults do change: in-app rule
editing is off (`config.rules.manualProvision: false`) — the rules pages stay
readable in the web UI, but Add/Edit/Delete are gone. That is the intended
state here, since this repo is the writer.

### Successor for chart-based installs: mounted rules ConfigMaps

The server can also reconcile the rules from mounted ConfigMaps itself
(`config.rules.host.existingConfigMap` /
`config.rules.ci.existingConfigMap`): no CronJob, no `gssh-admin` image, and
above all **no IdP service account** — the client-credentials setup below
becomes unnecessary. A file-owned domain rejects every API write, so Git is
provably the only writer, and the 30 s reconcile loop also reverts out-of-band
database changes.

This example still uses the CronJob (it also works against non-chart
installs); rewriting it is a separate step. For a new chart-based setup,
prefer the ConfigMap mount: keep generating the ConfigMaps with the
`configMapGenerator` above — one file per domain (`grants:` for host rules,
`ci_grants:` for CI rules) and `disableNameSuffixHash: true`, so the name the
HelmRelease values reference stays stable. Details:
[docs/grants.md](../../docs/grants.md#declarative-management-gitops),
[chart README](../helm/guided-ssh/README.md#rules-provisioning-gitops).

### IdP service account for the sync

`gssh-admin` authenticates non-interactively in the CronJob via the
client-credentials flow (`GSSH_CLIENT_ID`/`GSSH_CLIENT_SECRET`). The issued
ID token must be verifiable by the server like a user token: issuer =
`GSSH_OIDC_ISSUER`, audience contains `GSSH_CLIENT_OIDC_CLIENT_ID`, the
`groups` claim contains the admin group. Setup in Keycloak:

1. Create client `gssh-grants-sync`: confidential ("Client authentication"
   on), enable **Service accounts roles**, standard/direct flows off.
2. Dedicated client scope mappers on the client:
   - **Audience** mapper: add `GSSH_CLIENT_OIDC_CLIENT_ID` (e.g. `gssh-cli`)
     to the token audience ("Add to ID token" on).
   - **Group Membership** mapper: claim `groups` ("Full group path" off,
     "Add to ID token" on).
3. Add the service account user `service-account-gssh-grants-sync` to the
   admin group (`GSSH_ADMIN_GROUP`, e.g. `gssh-admins`).
4. Enter the client secret in `secrets.yaml`
   (`guided-ssh-sync-oidc/client-secret`) and encrypt it with SOPS.

The scope `openid` must be assigned to the client so the token response
contains an `id_token`.

## Upgrade path

Chart releases originate in the product repo (chart version bump → tag
`guided-ssh-x.y.z` → GitHub Pages `index.yaml`). Rollout via Flux:

- **staging** follows `>=0.1.0 <0.2.0` automatically: Flux checks the Helm
  repo on `chart.spec.interval` and rolls out new patch/minor versions
  without a commit — an early warning ahead of production.
- **production** pins exactly. Upgrade = bump `version:` in
  `apps/overlays/production/helmrelease-patch.yaml`, merge request,
  merge; Flux runs the `helm upgrade`.

DB migrations run automatically on every rollout: init container `migrate`
(goose) before the server, a Postgres advisory lock serializes parallel
replicas. If the upgrade fails, `upgrade.remediation.retries` kicks in
(Helm rollback via Flux); migrations are forward-only and must therefore be
backward-compatible with the previous version.

The complete path (bump → Flux reconcile → migration → ready) is
automatically testable: `hack/flux-upgrade-test.sh` builds a kind cluster
with Flux, installs chart version A from a local Helm repo, bumps to
version B, and verifies the rollout and migration run.

## Operational notes

- Keep the sync CronJob's image (`docker.io/guidedtraffic/guided-ssh:<tag>`)
  matching the rolled-out `appVersion` — `gssh-admin` lives in the server
  image (distroless, command gets overridden).
- `grants.yaml` is generated as a ConfigMap without a hash suffix: job pods
  start fresh and always read the current state; a rolling update like for
  deployments is not needed.
- Agent mTLS needs TLS passthrough: the agent API runs through the separate
  service (production: `type: LoadBalancer`), not through the HTTP ingress.
