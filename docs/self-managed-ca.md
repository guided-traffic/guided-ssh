# Self-managed CA keys

By default guided-ssh generates its three CA private keys (SSH user CA, SSH
host CA, agent mTLS CA) on first start and stores them AES-256-GCM-encrypted
in the `ca_keys` table. In **self-managed** mode you generate the keys
yourself, hand them to the server as mounted files, and the application never
writes private key material to the database.

Related documents: [Operations manual](betriebshandbuch.md),
[Helm chart README](../deploy/helm/guided-ssh/README.md),
[GitOps reference setup](../deploy/flux-example/README.md).

## Why

- **The database stops being the trust anchor.** In managed mode, losing the
  database *or* the master key means losing the CA: every issued certificate
  and every host's `TrustedUserCAKeys` becomes worthless. Backup and restore
  of the CA are coupled to database backup and restore.
- **The CA becomes GitOps-manageable.** The keys can be declared in a Git
  repository (SOPS-encrypted) and reconciled by Flux like every other secret.
  Rotation, disaster recovery, and cloning an environment become a
  `git commit` instead of imperative access to a running system.
- **DB compromise no longer forges certificates.** Even together with the
  master key, the database holds no signing key.

## Modes

| | `managed` (default) | `self-managed` |
|---|---|---|
| CA private keys | generated on first start, stored encrypted in `ca_keys` | read from mounted files, never stored |
| `ca_keys.encrypted_private_key` | ciphertext | `NULL` |
| Source of truth | the database | your Git repository |
| Rotation | in-app (`CA.Rotate`, not exposed today) | commit a new key file, restart |
| `GSSH_CA_MASTER_KEY` | required | required (see [Master key](#master-key)) |

Self-managed mode covers **all three** CAs at once — there is no per-purpose
mixed mode. A missing key file is a startup error, never silent
auto-generation.

## Configuration

| Variable | Meaning |
|---|---|
| `GSSH_CA_MODE` | `managed` (default, also when unset) or `self-managed` |
| `GSSH_CA_USER_KEY_FILE` | Path to the SSH user CA private key — OpenSSH private key PEM |
| `GSSH_CA_HOST_KEY_FILE` | Path to the SSH host CA private key — OpenSSH private key PEM |
| `GSSH_CA_MTLS_KEY_FILE` | Path to the agent mTLS CA key — PKCS#8 PEM, Ed25519 |
| `GSSH_CA_MTLS_CERT_FILE` | Path to the agent mTLS CA certificate — X.509 PEM, `CA:TRUE`, `keyCertSign` |

The four file variables are **required in `self-managed` mode and forbidden in
`managed` mode** — both violations abort the start, so a half-configured
deployment fails loudly instead of quietly running on a different CA than
intended.

Keys are passed as **files, not environment variables**: private key material
must not end up in `/proc/<pid>/environ`, crash dumps, or
`kubectl describe pod`.

### Master key

`GSSH_CA_MASTER_KEY` stays required in both modes. In self-managed mode it no
longer protects any CA key, but the session key of the web UI is still
HKDF-derived from it. Decoupling it (`GSSH_UI_SESSION_KEY`, master key
optional in self-managed mode) is a planned follow-up.

## Generating the key material

Run once on an operator workstation, in an empty directory:

```sh
ssh-keygen -t ed25519 -f user-ca -N '' -C 'guided-ssh user ca'
ssh-keygen -t ed25519 -f host-ca -N '' -C 'guided-ssh host ca'
gssh-server gen-mtls-ca -out mtls-ca      # writes mtls-ca.key (0600) and mtls-ca.crt
```

`gen-mtls-ca` exists so nobody has to hand-craft a `CA:TRUE` certificate with
`openssl` flags; the server validates the result on every start.

What goes into the Secret:

| File | Into the Secret? |
|---|---|
| `user-ca`, `host-ca` | yes — the private keys |
| `user-ca.pub`, `host-ca.pub` | **no** — the server derives the public keys itself |
| `mtls-ca.key` | yes — the private key |
| `mtls-ca.crt` | yes — the CA certificate is served to agents |

The keys must be **unencrypted** (`-N ''`). A passphrase-protected key is
rejected at startup — there is no prompt and no passphrase variable.

Keep an offline copy: the Git repository is now the source of truth for the
CA, and a SOPS-encrypted file is only as recoverable as the age/PGP key that
decrypts it.

## Kubernetes

The Helm chart mounts the Secret read-only and wires the five variables:

```yaml
secrets:
  ca:
    mode: self-managed
    existingSecret: guided-ssh-ca         # master key — still required
    selfManaged:
      existingSecret: guided-ssh-ca-keys  # the four files
```

Key names inside the Secret are configurable and double as file names below
`secrets.ca.selfManaged.mountPath` (default `/etc/gssh/ca`); defaults are
`user-ca`, `host-ca`, `mtls-ca.key`, `mtls-ca.crt`. Details:
[chart README](../deploy/helm/guided-ssh/README.md#ca-mode-managed-vs-self-managed-secretscamode).
The SOPS/Flux walkthrough with a ready-made example Secret:
[deploy/flux-example/README.md](../deploy/flux-example/README.md#self-managed-ca-keys).

## How adoption works

On every start, per purpose:

1. The key file is read and parsed, and the public key derived from it.
2. The `ca_keys` row with the same `(purpose, public_key)` is selected or
   inserted — without private key material, state `active`. Inserting demotes
   a previously active key of that purpose to `retiring`.
3. The signer is built from the file; the database decrypt path is never used.

The row is therefore **derived state**: a fresh database plus the same mounted
keys reproduces identical bundles and still verifies previously issued
certificates. The first adoption of a key is audited as `ca.key_adopted`.

A unique index on `(purpose, public_key)` makes concurrent replicas adopting
the same key race-safe.

## Rotation

In-app rotation is refused in self-managed mode — rotation is a Git operation:

1. Generate a new key pair, replace the file content in the SOPS-encrypted
   Secret, commit. Flux rolls the Deployment.
2. On start the new key is adopted as `active` and the previous one is demoted
   to `retiring`. The old **public** key stays in the CA bundle
   (`GET /v1/ca/bundle/{user|host}`), so hosts keep trusting certificates
   signed by it during the transition; agents refresh the bundle hourly.
3. Once all certificates signed by the old key have expired (user
   certificates ≤ 16 h, host certificates 30 days), retire the old row. There
   is no admin surface for this yet — today it is SQL:

   ```sql
   UPDATE ca_keys SET state = 'retired', retired_at = now()
    WHERE purpose = 'user' AND state = 'retiring';
   ```

Only the SSH CAs get that transition window. Agent client certificates are
verified against the **active** mTLS CA only, so replacing
`mtls-ca.key`/`mtls-ca.crt` invalidates every agent certificate and requires
re-enrolling the hosts. Rotate the SSH CAs without touching the mTLS files
unless that is exactly what you want.

## Failure modes

All of these abort the start; the message names the offending file and the
reason.

| Situation | Startup error |
|---|---|
| File missing or unreadable | `ca: read user ca key file "/etc/gssh/ca/user-ca": no such file or directory` |
| Key protected by a passphrase | `ca: user ca key file … is passphrase-protected, self-managed ca keys must be unencrypted` |
| Not a valid private key (e.g. a `.pub` file was mounted) | `ca: parse user ca key file …` |
| mTLS key not PKCS#8 | `ca: parse mtls ca key file … (pkcs#8 expected)` |
| mTLS key not Ed25519 | `ca: mtls ca key file …: unexpected key type …, ed25519 required` |
| mTLS certificate is not a CA | `ca: mtls ca cert file …: not a ca certificate (basic constraints ca:false)` |
| mTLS certificate cannot sign | `ca: mtls ca cert file …: key usage does not contain keyCertSign` |
| Certificate and key do not belong together | `ca: mtls ca cert file … does not belong to key file …` |
| A retired key is mounted again | `ca: the mounted user ca key was retired and must not be used again — mount the current key or un-retire its ca_keys row` |
| Key files set while `GSSH_CA_MODE` is `managed` | configuration error, server refuses to start |
| A key file variable missing in `self-managed` mode | configuration error, server refuses to start |

Anything that tries to create or rotate CA key material in this mode fails
with: `ca: self-managed mode: ca keys are managed in git (mounted key files),
the application must not create or rotate them`.

In Kubernetes, a key missing **inside** the Secret is not a startup error but
leaves the pod in `ContainerCreating` — the volume cannot be projected. Check
`kubectl describe pod`.

## Switching an existing installation

Switching from `managed` to `self-managed` on an existing database is
supported: the mounted keys are adopted, and the previously active
database-managed key is demoted to `retiring`, so its public key stays in the
bundle and existing certificates remain valid until they expire. The old key's
encrypted private key stays in the row but is never used again.

## Out of scope

- KMS/HSM signers (same `Signer` interface, planned separately).
- Per-purpose mixed mode (e.g. managed user CA plus self-managed mTLS CA).
- Automatic retirement of old keys.
- Enrollment tokens via Secret — single-use by design.
