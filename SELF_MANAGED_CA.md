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
("NULL, wenn der Key in einem KMS/HSM liegt", Phase 10 comment).

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

- In self-managed mode, `ca_keys.encrypted_private_key IS NULL` for every
  row — asserted in the integration test.
- A fresh DB plus the same mounted keys reproduces identical bundles and can
  verify previously issued certificates (DB is derived state, Git is the
  source of truth).
- Managed mode behaves exactly as today (default unchanged).
- Misconfiguration (missing file, key files set in managed mode, retired key
  re-mounted) fails at startup with an actionable message.

## Out of scope

- KMS/HSM signers (project plan Phase 10) — same `Signer` interface, later.
- Per-purpose mixed mode (managed user CA + self-managed mTLS CA).
- Automatic retirement of old keys.
- Enrollment tokens via Secret (single-use by design; GitOps-friendly path
  would be a token-creation API endpoint, separate topic).
