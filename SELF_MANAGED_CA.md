# Self-Managed CA Keys (GitOps / SOPS)

Status: **draft / planned** — software is not in production yet, no data
migration path required.

## Motivation

Today all CA private keys (SSH user CA, SSH host CA, agent mTLS CA) are
generated at first server start and stored AES-256-GCM-encrypted in the
`ca_keys` table ([internal/ca/ca.go](internal/ca/ca.go#L75),
[internal/ca/mtls.go](internal/ca/mtls.go#L36),
[internal/ca/keycrypt.go](internal/ca/keycrypt.go#L32)). That has two
drawbacks:

1. **The database is the single source of truth for the trust anchors.**
   Losing the DB (or the `GSSH_CA_MASTER_KEY`) means losing the CA — every
   issued certificate and every host's `TrustedUserCAKeys` becomes worthless.
   Backup/restore of the CA is coupled to DB backup/restore.
2. **Not GitOps-manageable.** The keys cannot be declared in a Git repository
   (SOPS-encrypted) and reconciled by Flux like every other secret in
   `deploy/flux-example/`. Rotation, disaster recovery, and environment
   cloning all require imperative access to a running system instead of a
   `git commit`.

Goal: an operator can set `self-managed` mode, provide all CA private keys
via Kubernetes Secrets (SOPS-encrypted in Git), and the application **never
writes private key material to the database**. The DB keeps only public
metadata; the Git repository becomes the source of truth for the CA.

## Design decisions

### D1 — A `ca_keys` row still exists, but without the private key

`certificates.ca_key_id` is a `NOT NULL` FK onto `ca_keys`
([0001_initial_schema.sql](internal/store/migrations/0001_initial_schema.sql#L97)),
and `Bundle()` builds the `TrustedUserCAKeys` content from
`ca_keys.public_key` ([internal/ca/ca.go](internal/ca/ca.go#L196)). The
schema already anticipates external keys: `encrypted_private_key` is nullable
("NULL when the key lives in a KMS/HSM", Phase 10 comment).

In self-managed mode the row contains only purpose, algorithm, public key,
and state — no secret. The row is **derived state**: it can always be
recreated from the mounted key (adopt-on-start, see D4), so the DB is no
longer something the CA depends on for its identity. DB compromise (even
together with the master key) no longer allows forging certificates.

### D2 — Mode is explicit and exclusive

`GSSH_CA_MODE=managed|self-managed`, default `managed` (today's behavior).
No mixed mode per purpose in the first iteration: self-managed means *all
three* CAs (user, host, mtls) come from files. Missing file in self-managed
mode = startup error, never silent auto-generation. Conversely, in managed
mode the key-file variables must be unset (startup error otherwise) so a
half-configured deployment fails loudly.

### D3 — Keys are mounted as files, not env vars

Private keys must not live in the process environment (visible in
`/proc/<pid>/environ`, crash dumps, `kubectl describe`). The Secret is
mounted as a volume:

```
GSSH_CA_MODE=self-managed
GSSH_CA_USER_KEY_FILE=/etc/gssh/ca/user-ca        # OpenSSH private key PEM
GSSH_CA_HOST_KEY_FILE=/etc/gssh/ca/host-ca        # OpenSSH private key PEM
GSSH_CA_MTLS_KEY_FILE=/etc/gssh/ca/mtls-ca.key    # PKCS#8 PEM
GSSH_CA_MTLS_CERT_FILE=/etc/gssh/ca/mtls-ca.crt   # X.509 CA certificate PEM
```

Operator generates the material once, encrypts with SOPS, commits:

```sh
ssh-keygen -t ed25519 -f user-ca -N '' -C 'guided-ssh user ca'
ssh-keygen -t ed25519 -f host-ca -N '' -C 'guided-ssh host ca'
# mTLS CA (10y, CA:TRUE, keyCertSign) — helper command, see Phase 4
gssh-server gen-mtls-ca --out mtls-ca
```

### D4 — Adopt-on-start instead of Ensure

Startup in self-managed mode, per purpose:

1. Read + parse the key file; derive the public key.
2. Look up the `ca_keys` row with the same `(purpose, public_key)`.
   - Found → adopt its ID (state must not be `retired` → startup error).
   - Not found → insert a row with `encrypted_private_key = NULL`, state
     `active`, and demote any other `active` row of that purpose to
     `retiring` (this is how file-based rotation works, see D6).
3. Build the signer from the file material and cache it; the DB decrypt path
   (`NewSoftwareSigner`) is never used in this mode.

Requires a unique index on `(purpose, public_key)` so concurrent replicas
adopting the same key race safely (`ON CONFLICT DO NOTHING` + re-select).
This index also mitigates the existing bootstrap race in `EnsureCAKeys`
(no advisory lock today — two replicas can each create an active key).

For the mTLS CA the certificate PEM is stored in `public_key` (as today) and
validated on load: `IsCA`, `KeyUsageCertSign`, key matches certificate.

### D5 — In-app rotation is disabled in self-managed mode

`CA.Rotate()` and all key-creating paths return a clear error in
self-managed mode (they currently have no callers outside tests, so nothing
breaks). Rotation is a Git operation — see D6.

### D6 — Rotation = commit new key; old key stays trusted via its DB row

Rollover must keep the old public key in the bundle while hosts still trust
certificates signed by it. Flow:

1. Operator generates a new key, replaces the file content in the
   SOPS-encrypted Secret, commits, Flux rolls the Deployment.
2. On start, adopt-on-start (D4) inserts the new key as `active` and demotes
   the previous one to `retiring` — its public key remains in `Bundle()`
   output, so hosts keep trusting both during the transition.
3. After all certificates signed by the old key have expired (user cert
   validity is short), the operator retires the old row (admin action /
   SQL for now, see Phase 5).

No multi-key directory mount needed in the first iteration; the DB carries
the public-key history, and that history is reconstructible (old public keys
are also recoverable from issued certificates and old Git revisions).

### D7 — Master key stays, but only for sessions (follow-up: decouple)

`GSSH_CA_MASTER_KEY` is still required in self-managed mode because the UI
session cookie key is HKDF-derived from it
([internal/auth/session.go](internal/auth/session.go#L31)). Follow-up
(Phase 5): optional `GSSH_UI_SESSION_KEY` so that self-managed deployments
need no CA-relevant master secret at all; `GSSH_CA_MASTER_KEY` then becomes
optional when the mode is self-managed.

## Implementation plan

### Phase 1 — Config & key loading

- [x] `GSSH_CA_MODE` parsing (+ validation matrix from D2) in
      `cmd/gssh-server/main.go` (`caModeFromEnv()`, wired into `setup()`)
- [x] Loader for the three key files: parse OpenSSH PEM (user/host) and
      PKCS#8 + X.509 cert (mtls), with precise error messages (file, reason)
      — `internal/ca/keyfiles.go`
- [x] mTLS cert validation: `IsCA`, `KeyUsageCertSign`, pubkey matches cert

### Phase 2 — CA core

- [x] Migration `0005`: unique index on `ca_keys (purpose, public_key)`
- [x] Store: `AdoptCAKey(ctx, purpose, algorithm, publicKey) (*CAKey, bool, error)`
      (transactional select-or-insert with NULL private key; demotes other
      active keys of the purpose to `retiring`; the bool reports the first
      adoption)
- [x] `ca.New` option `WithExternalKeys(...)` plus `AdoptExternalKeys()`;
      `activeSigner()` uses only the adopted signer and never touches
      `encrypted_private_key` in self-managed mode
- [x] `FileSigner` (ssh.Signer from the loader + adopted CAKeyID — same shape
      as `SoftwareSigner` minus decrypt)
- [x] `mtlsCA()` file-based branch (cert + key from loader)
- [x] `EnsureCAKeys` / `EnsureMTLSCA` / `Rotate` / `createKey`: hard error in
      self-managed mode (`ErrSelfManaged`)
- [x] Audit event `ca.key_adopted` on first adoption of a key

### Phase 3 — Tests

- [x] Unit: loader (good/bad PEM, wrong key type, cert/key mismatch, missing
      `IsCA`), mode validation matrix, Rotate refusal
- [x] Unit: adopt logic (fresh DB, re-adopt same key, rotation demotes old
      key, retired key → startup error)
- [x] Integration: full issue path (user cert, host cert, agent mTLS cert,
      bundle endpoints, enrollment) in self-managed mode — mirror of the
      existing managed-mode tests
- [x] Integration: managed → self-managed switchover on an existing DB
      (old managed key demoted to `retiring`, bundle contains both)

### Phase 4 — Tooling & deployment

- [x] `gssh-server gen-mtls-ca -out <prefix>` helper (emits `.key`/`.crt`;
      operators shouldn't hand-craft a CA:TRUE cert with openssl flags)
- [x] Helm chart: `secrets.ca.mode`, `secrets.ca.selfManaged.existingSecret`
      (+ key-name mapping), volume mount, env wiring; `ca-master-key` stays
- [x] `deploy/flux-example`: example Secret with the four files + README
      section (generation and rotation walkthrough per D6). Plaintext
      placeholder material like the other example secrets in that file —
      operators re-encrypt with their own age key.
- [x] Docs: `docs/self-managed-ca.md` "Self-managed CA keys" (English)
- [x] Keep READMEs up to date: root `README.md` (mode + secret handling),
      `deploy/helm/guided-ssh/README.md` (new values, secret layout),
      `deploy/flux-example/README.md` (SOPS secret + rotation walkthrough) —
      update in the same PR as the feature, not afterwards

### Phase 5 — Follow-up (separate PR)

- [ ] `GSSH_UI_SESSION_KEY` decoupling (D7); `GSSH_CA_MASTER_KEY` optional in
      self-managed mode
- [ ] Admin surface to retire a `retiring` key (API/CLI) — today SQL-only

## Success criteria

All four are met; how each one is verified:

- In self-managed mode, `ca_keys.encrypted_private_key IS NULL` for every
  row — asserted as `SELECT count(*) … WHERE encrypted_private_key IS NOT NULL`
  = 0 at the end of `TestSelfManagedCAFullIssuePath`.
- A fresh DB plus the same mounted keys reproduces identical bundles and can
  verify previously issued certificates (DB is derived state, Git is the
  source of truth) — `TestSelfManagedCADatabaseIsDerivedState` wipes `ca_keys`,
  re-adopts the same files and asserts byte-identical bundles.
- Managed mode behaves exactly as today (default unchanged) — the unit and
  integration suites pass unchanged, and `helm template` output for managed
  mode is byte-identical to `HEAD` (defaults, full feature set, and an
  explicit `secrets.ca.mode=managed`).
- Misconfiguration (missing file, key files set in managed mode, retired key
  re-mounted) fails at startup with an actionable message — `TestCAModeFromEnv`
  (9 cases), `TestLoadExternalKeysRejectsBrokenMaterial` (18 cases),
  `TestAdoptExternalKeysRetiredKeyRefused`. **Exception:** an expired mounted
  mTLS CA certificate is not caught at startup — see O2.

## Implementation decisions (as built)

Decisions taken while implementing that refine or deviate from D1–D7. The
design above is unchanged in substance; these are the concrete choices.

### I1 — `AdoptCAKey` reports whether it created the row

Signature is `AdoptCAKey(ctx, purpose, algorithm, publicKey) (*CAKey, bool, error)`.
The bool is needed for "audit event `ca.key_adopted` **on first adoption**"
— without it, every restart would re-emit the event.

### I2 — A `retiring` row is adopted as-is, never promoted back to `active`

D4 only specified the error-on-`retired` case. Decision: if the mounted key
matches a `retiring` row, return it unchanged. Promoting it would let a stale
mount silently reverse a completed rotation, and with two replicas mounting
different keys the state would flap.

**Consequence:** in self-managed mode signer selection keys off the *adopted
CA key ID*, never off `state = 'active'`. A replica that still has the
superseded key file mounted keeps signing with it until it is restarted —
that is the intended rolling-update behavior. Regression-guarded by
`TestSelfManagedRetiringKeyStillSigns`.

### I3 — API shape: `WithExternalKeys` + explicit `AdoptExternalKeys`

Named `WithExternalKeys` rather than the plan's `WithExternalSigners`, since
the option carries the whole loaded material (including the mTLS certificate),
not just signers. Adoption is an explicit startup step
(`AdoptExternalKeys(ctx)`) that replaces `EnsureCAKeys` and covers **all
three** purposes including mTLS.

`CA.SelfManaged()` exists so `serve()` can skip its `EnsureMTLSCA` bootstrap
call — that path now returns `ErrSelfManaged` and would otherwise abort startup.

### I4 — `invalidateSigner` is a no-op in self-managed mode

Found during testing: `RetireKey` evicts the cached signer, but in
self-managed mode the cache holds signers built from the mounted **files**,
which cannot be rebuilt from the DB. Retiring the old row — D6 step 3, the
documented cleanup — therefore left the purpose unsignable until restart,
with the misleading error `no external ca key adopted for purpose …`.
External signers are the source of truth, so no DB state change invalidates
them. See O3 for the remaining sharp edge.

### I5 — `ca_keys.algorithm` is derived from the mounted material

Not hardcoded to `ed25519`. `strings.TrimPrefix(pub.Type(), "ssh-")`, so an
ed25519 key records `ed25519` in both modes and stays comparable with what
managed mode's `NewCAKey` writes. The mTLS loader enforces ed25519 outright;
the SSH loaders accept whatever `ssh.ParsePrivateKey` understands (see O6).

### I6 — One x509 template for both mTLS CA producers

`GenerateMTLSCA()` was extracted from `EnsureMTLSCA`; the `gen-mtls-ca`
subcommand uses the same function. Operators and the bootstrap path cannot
drift apart.

### I7 — The helper flag is `-out`, not `--out`

Go's `flag` package accepts both, but `-out` matches the binary's own usage
text and the existing `gssh-server enroll-token -tags … -ttl …` style. The
plan's `--out` spelling was not adopted; docs use `-out`.

### I8 — The Secret is projected item-by-item, not mounted whole

The volume lists the four keys explicitly, so `selfManaged.existingSecret`
may point at the *same* Secret as `secrets.ca.existingSecret` without
`ca-master-key` landing on disk. `defaultMode: 0440` plus the chart's default
`podSecurityContext.fsGroup` (65532) makes the files readable only by the
server process. Side effect: a missing key leaves the pod in
`ContainerCreating` instead of crash-looping.

Chart-level `fail` guards reject an invalid `secrets.ca.mode` and a
self-managed mode without `selfManaged.existingSecret` — a render error is
friendlier than a CrashLoop.

### I9 — The Flux example ships plaintext placeholder keys, not SOPS ciphertext

Phase 4 asked for a SOPS-encrypted example Secret. It cannot be encrypted
here without a real cluster age key, and the other example secrets in that
file already use plaintext `REPLACE_ME` values. The example therefore carries
real but disposable keys labelled `EXAMPLE — DO NOT USE`, with a banner
stating that the material is public and must be replaced and re-encrypted.
The production overlay deliberately stays on `managed`, so a copied template
never runs on keys whose private material is in this repo.

### I10 — New code is English, existing German code stays German

Explicit decision for this PR: new Go comments, error messages and tests are
English; existing German comments are not translated. New user-facing docs
are English (`docs/self-managed-ca.md`); sections added to the existing German
docs keep those files' language.

### I11 — Integration tests live in `internal/store`

`internal/store` owns the only testcontainers harness. The self-managed
end-to-end tests drive a real `httptest` server built from `internal/api`
against a real `*store.Store` from there, rather than building a second
container bootstrap path under `internal/api`.

## Open points

Findings from implementation and testing that are **not** fixed in this PR,
each with a proposal. None of them block the feature.

### O1 — D4's claim about the bootstrap race is wrong (doc correction)

D4 states the unique index "also mitigates the existing bootstrap race in
`EnsureCAKeys`". It does not. Two replicas bootstrapping managed mode
concurrently each *generate a fresh random key*, so their `public_key` values
differ and both inserts succeed — the index only collides on identical key
material, which is exactly the self-managed case it was added for.

*Proposal:* keep the index as is (it does its job for adoption), and fix the
managed-mode race separately with a Postgres advisory lock around
`EnsureCAKeys`. Small, independent, worth its own issue.

### O2 — No validity-window check on the mounted mTLS CA certificate

`LoadExternalKeys` checks `IsCA`, `KeyUsageCertSign` and key/cert match, but
not `NotBefore`/`NotAfter`. An expired mounted CA starts cleanly and only
fails later at agent enrollment — the one gap against the "misconfiguration
fails at startup" success criterion.

*Proposal:* reject an expired or not-yet-valid certificate in the loader, and
log a warning when it expires within, say, 90 days. Cheap; a good candidate to
still add to this PR if wanted.

### O3 — `RetireKey` does not protect the currently mounted key

After I4, retiring a superseded row is safe. Retiring the row of the key that
is *currently mounted* still succeeds: the running process keeps signing (its
signer is file-based), but the next start fails with the retired-key error.

*Proposal:* have `RetireKey` refuse when the ID equals an adopted key ID in
self-managed mode. Naturally belongs with the Phase 5 admin retire surface,
which is when a caller first exists.

### O4 — The adoption audit event is written outside the adopt transaction

If `AppendAuditEvent` fails after `AdoptCAKey` committed, the row exists but
the adoption is never audited — and never will be, since the next start
reports `created == false`. Same shape as the existing `createKey`, so this
is a carry-over rather than a regression.

*Proposal:* extend `AdoptCAKey` to take the audit event and write both in one
transaction, mirroring `CreateCertificateWithAudit`. Fixes `createKey` too.

### O5 — `AdoptExternalKeys` is not atomic across the three purposes

A failure on the host key after the user key was adopted leaves a rotation
half-applied (user key B already active, A already demoted). Startup aborts
and a retry converges, so the window is short and self-healing.

*Proposal:* accept it, or adopt all three purposes in one store-level
transaction if the half-applied state ever proves confusing in practice.

### O6 — Non-ed25519 SSH CA keys are accepted

The loader takes anything `ssh.ParsePrivateKey` understands. Since I5 the
recorded algorithm is truthful, so nothing lies anymore — but the project
otherwise only ever produces ed25519 CAs.

*Proposal:* decide explicitly. Either keep it permissive (an operator with an
existing RSA CA can migrate onto guided-ssh) or reject non-ed25519 in the
loader for one uniform key type. Leaning permissive; no code change needed.

### O7 — mTLS CA rotation has no transition window

D6's rollover reasoning covers the SSH CAs: the old public key stays in the
bundle via its `retiring` row. The mTLS CA has no such bundle —
`MTLSCAPool` builds the pool from the active certificate only — so swapping
the mTLS files invalidates every agent certificate at once and forces
re-enrollment. Documented as a caveat in `docs/self-managed-ca.md`.

*Proposal:* make `MTLSCAPool` include `retiring` mTLS rows so agents keep
authenticating across a rollover. That is the same trust-window shape the SSH
bundle already has, and it is a prerequisite for calling mTLS rotation
operationally safe.

### O8 — The Flux example was not rendered in this environment

`kubectl`/`kustomize` are unavailable here, so the added example Secret was
verified by reading and by key material round-trip, not by an actual
`kubectl kustomize` build.

*Proposal:* render it once in CI or locally before merging.

## Out of scope

- KMS/HSM signers (project plan Phase 10) — same `Signer` interface, later.
- Per-purpose mixed mode (managed user CA + self-managed mTLS CA).
- Automatic retirement of old keys.
- Enrollment tokens via Secret (single-use by design; GitOps-friendly path
  would be a token-creation API endpoint, separate topic).
