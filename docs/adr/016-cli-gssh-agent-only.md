# ADR-016: CLI `gssh` — agent-only keys, stdlib subcommands, SPKI pinning, Match-exec integration

- Status: accepted
- Date: 2026-07-19

## Context

Phase 4 delivers the user CLI: `gssh login` (SSO flow, ephemeral key pair,
certificate loaded into the `ssh-agent`), transparent integration with native
`ssh`, `status`/`logout`, a configuration file with fingerprint pinning, and
cross-platform builds. The plan explicitly requires: no persistence of keys
or certificates to disk.

## Decision

- **Command structure**: subcommands (`login`, `ssh`, `status`, `logout`,
  `integrate`, `version`) with stdlib `flag` per subcommand — no
  cobra/urfave (no new dependency; five commands don't justify a framework).
  Logic lives testably in `internal/cli`; `cmd/gssh` is a one-liner.
- **Agent-only**: each login generates a fresh Ed25519 key pair in memory;
  the private key + certificate go exclusively via `SSH_AUTH_SOCK` into the
  agent (`AddedKey` with `LifetimeSecs` = remaining certificate validity —
  the agent cleans up on its own). Entries carry the comment prefix
  `guided-ssh`, which is how `status`, `logout`, and auto-login find their
  own entries. Losing the agent ⇒ simply log in again.
- **Transparent `ssh`**: `Match exec` integration instead of ProxyCommand.
  `gssh integrate` prints the snippet
  (`Match host "<pattern>" exec "gssh login --if-needed"`); the login is a
  side effect of config evaluation, while native `ssh` remains the
  transport. ProxyCommand would have to provide the channel itself
  (stdio proxy, breaks ControlMaster, more code). Additionally, `gssh ssh
  <args…>` as a wrapper (auto-login, then `exec ssh` with unmodified
  arguments).
- **Renewal**: auto-login renews when the remaining validity is < 5 minutes
  (clock skew, connection setup).
- **Configuration**: `~/.config/guided-ssh/config.yaml` (XDG), yaml.v3
  (already a transitive dependency in the module). Fields: `api_url`,
  `issuer`, `client_id`, optionally `scopes`, `pin_sha256`, `validity`. Path
  override: `--config` or `GSSH_CONFIG` (the latter needed because `gssh ssh`
  passes all arguments through to ssh unchanged).
- **Fingerprint pinning**: `pin_sha256` = base64-encoded SHA-256 over the
  SubjectPublicKeyInfo of the API server certificate (like HPKP /
  `curl --pinnedpubkey`). When set, the pin fully replaces CA/hostname
  verification (`VerifyPeerCertificate`) — covering self-signed deployments.
  Applies only to the gssh API; the IdP is validated normally via system CAs.

## Consequences

- No new direct dependencies besides yaml.v3 (already transitive).
- `ssh-add -l` shows the entries as `guided-ssh user:<sub>@<issuer>`;
  foreign agent entries are never touched.
- ssh suppresses the Match-exec output; the browser flow still works,
  while headless environments use `gssh login --device` beforehand.
- `gssh status` returns exit code 1 without a valid certificate (scriptable).
- Windows (named-pipe agent) is deliberately out of scope; target platforms
  per the plan: linux/amd64, linux/arm64, darwin/arm64 (`make cross`, runs
  in CI).
