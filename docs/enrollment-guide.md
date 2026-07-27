# Host Enrollment — Step by Step

Registers a Linux host with the platform: the host receives an SSH host
certificate and an mTLS client certificate, sshd is configured for
certificate authentication, and the `gssh-agentd` agent keeps everything
up to date (ADR-017). Operations view: [operations-manual.md](operations-manual.md);
failure modes: [troubleshooting.md](troubleshooting.md).

## 1. Prerequisites

- A running **sshd** with existing host keys — if missing:
  `ssh-keygen -A`. The agent uses
  `/etc/ssh/ssh_host_ed25519_key.pub` by default (override: `--ssh-key`).
- The main `sshd_config` must include the configuration directory:

  ```
  Include /etc/ssh/sshd_config.d/*.conf
  ```

  (the default on most distributions). Enrollment checks this **before**
  the first network call and aborts naming the exact line if it is missing
  — without the include the generated snippet has no effect, and the token
  stays unused. An `Include` inside a `Match` block does not count: it
  would not apply to every login. The file is never edited automatically.
- Network access to the gssh server: the public API (`POST /v1/enroll`) and
  the agent API (mTLS, port 8443 — TLS passthrough/LoadBalancer, see the
  chart README).
- Root privileges on the host (writes to `/etc/ssh` and `/var/lib/guided-ssh`).

## 2. Install the package

**deb/rpm** (built with nfpm, `make packages`; contents: binary
`/usr/bin/gssh-agentd`, systemd unit `/lib/systemd/system/gssh-agentd.service`):

```sh
dpkg -i gssh-agentd_<version>_amd64.deb     # or rpm -i …
```

The postinstall script creates `/var/lib/guided-ssh` (0700) and reloads systemd;
the service is deliberately **not** started — only after enrollment.

**Without a package manager** — the install script downloads the binary from the
GitHub release:

```sh
curl -fsSL https://raw.githubusercontent.com/guided-traffic/guided-ssh/main/deploy/packaging/install.sh \
  | sh -s -- v0.3.0
```

## 3. Generate an enrollment token (on the server)

```sh
gssh-server enroll-token -name web01.example.com -tags env=prod,role=web -ttl 24h
```

| Flag | Default | Meaning |
|---|---|---|
| `-name` | empty | Bind the token to exactly this hostname (recommended); a different hostname at enroll time ⇒ 403 |
| `-tags` | empty | Host tags (`k=v,…`); token tags take precedence over `--tags` at enroll time |
| `-ttl` | `24h` | Token validity period |

The plaintext value (`gssh-et-…`, 256 bits of randomness) is printed to stdout
once — only its SHA-256 hash is stored in the database. The token is
**single-use**: consumption is transactional, a second attempt returns 403.
The command needs the `GSSH_DB_*` connection settings (e.g. run it via
`kubectl exec` in the server pod).

## 4. Register the host

```sh
gssh-agentd enroll \
  --server https://gssh.example.com \
  --agent-url https://gssh-agent.example.com:8443 \
  --token gssh-et-…
```

All flags:

| Flag | Default | Meaning |
|---|---|---|
| `--server` | — (required) | public API of the gssh server (`POST /v1/enroll`) |
| `--agent-url` | — (required) | mTLS agent API for subsequent operation |
| `--token` | — (required) | one-time enrollment token |
| `--hostname` | `os.Hostname()` | name under which the host registers |
| `--tags` | empty | host tags `k=v,…` (token tags win server-side) |
| `--pin` | empty | SPKI SHA-256 pin (base64) of the enroll endpoint — for self-signed deployments |
| `--state-dir` | `/var/lib/guided-ssh` | agent state directory |
| `--ssh-dir` | `/etc/ssh` | sshd configuration directory |
| `--ssh-key` | `<ssh-dir>/ssh_host_ed25519_key.pub` | SSH host public key whose certificate is maintained |
| `--session-audit` | off | enable host session/sudo audit (pam_exec hooks, opt-in, ADR-021) |
| `--reload-command` | detected | command that reloads sshd; persisted as `reload_command` for renewals |
| `--no-reload` | off | don't reload sshd — the configuration stays inactive until you do |

What enrollment writes (idempotent; a re-enrollment with a new token
overwrites it):

**State directory** (`/var/lib/guided-ssh`, 0700):

| File | Content |
|---|---|
| `agent.key` (0600) | private mTLS key (Ed25519, freshly generated) |
| `agent.crt` | mTLS client certificate (CN = host UUID, assigned by the server) |
| `server-ca.pem` | mTLS CA for verifying the agent API |
| `config.yaml` (0600) | agent configuration (below) |
| `socket-token` (0600) | only with `--session-audit`: token for the socket write endpoints |

**sshd** (`/etc/ssh`):

| File | Content |
|---|---|
| `ssh_host_ed25519_key-cert.pub` | host certificate (path = public key path with `-cert.pub`) |
| `guided-ssh-user-ca.pub` | `TrustedUserCAKeys` bundle of the user CA |
| `sshd_config.d/guided-ssh.conf` | generated snippet (do not edit manually) |

The snippet:

```
TrustedUserCAKeys /etc/ssh/guided-ssh-user-ca.pub
HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub
AuthorizedPrincipalsCommand /usr/bin/gssh-agentd principals -state-dir /var/lib/guided-ssh -user %u
AuthorizedPrincipalsCommandUser root
```

With `--session-audit`, `LogLevel VERBOSE` is added, the helper additionally
receives `-serial %s -keyid %i` (correlating session ↔ certificate), and a
hook is idempotently appended to `/etc/pam.d/sshd` and `/etc/pam.d/sudo`
(marker `# guided-ssh session audit (managed)`):

```
session optional pam_exec.so quiet /usr/bin/gssh-agentd pam-session -state-dir /var/lib/guided-ssh
```

`optional` + helper exit code 0 ⇒ fail-open: the hook never blocks login
or sudo.

### Activating the configuration

sshd parses its configuration exactly once, at startup — per-connection
children are forks of the listener and inherit what was already parsed.
Writing the snippet therefore changes nothing for a daemon that is already
running, and `sshd -T` will not show that: it reads the files fresh from
disk. Enrollment closes that gap itself:

1. `sshd -t` over the written configuration. A rejection rolls the snippet
   back and fails enrollment — a broken snippet would take sshd down on its
   next restart.
2. The reload command runs (`--reload-command`, otherwise detected:
   `systemctl reload ssh|sshd`, `rc-service sshd reload`, or
   `kill -HUP $(cat <pidfile>)`). A failed reload fails enrollment. The
   resolved command is persisted as `reload_command` so certificate
   renewals reach the running daemon too.
3. The running daemon is asked for its host key over a local SSH
   handshake — with the snippet loaded it answers with the guided-ssh host
   certificate, without it with a plain key. This is the only check that
   tells "on disk" from "in memory"; comparing the listener's start time
   does not, because sshd re-execs on SIGHUP and keeps its start time.
   A plain key after a reload fails enrollment; an unreachable sshd (image
   build, service not started yet) is reported and accepted.

`--no-reload` skips steps 2 and 3 (including the detection) for hosts where
reloads belong to config management or the image build. The configuration
then stays inactive until *you* reload sshd. Combine it with
`--reload-command` to persist a command for certificate renewals without
running it now; otherwise `reload_command` stays empty and renewed host
certificates will not reach sshd on their own either.

An existing `reload_command` from a previous enrollment is never dropped:
if neither flag is given and detection finds nothing, the old value is
carried over.

## 5. Start the service and verify

```sh
systemctl enable --now gssh-agentd
```

Verification:

```sh
# Is the daemon running and answering principals requests?
gssh-agentd principals -user deploy
# → one line per authorized principal; error ⇒ check service/grants

journalctl -u gssh-agentd            # agent's JSON logs

# Login test from a client with a valid certificate:
gssh login && gssh ssh deploy@web01.example.com true
```

If a host-key prompt appears during the login test, the client is missing
trust in the host CA — add the `@cert-authority` line from
`GET /v1/ca/bundle/host` to `known_hosts`.

## 6. Agent operation

Systemd unit (`internal/agentdist/gssh-agentd.service`): `gssh-agentd run`,
`Restart=on-failure`, `ProtectSystem=full` with `ReadWritePaths=/var/lib/guided-ssh /etc/ssh`,
`NoNewPrivileges`.

The daemon handles:

- **Renewing the host certificate** at 2/3 of its lifetime (30-day validity;
  check interval `renew_interval`, default 5 m) via `POST /v1/agent/renew`.
  Afterwards `reload_command` runs — sshd reads the `HostCertificate` only
  at start/reload. With an empty `reload_command` sshd keeps presenting the
  old certificate from memory until someone reloads it by hand; once that
  one expires, clients hit host key verification failures.
- **Heartbeat** every `heartbeat_interval` (default 1 m) via
  `GET /v1/agent/heartbeat` — the server stamps `last_seen_at` from the mTLS
  identity, which is what makes a dead agent distinguishable from an idle
  one in the UI. The request and the response are both empty; a failing
  heartbeat is logged and otherwise ignored (it must never touch the
  authorization path).
- **Rotating the mTLS client certificate** at 2/3 of its lifetime (1 year): a
  fresh key pair + CSR over the still-valid mTLS channel
  (`POST /v1/agent/renew-mtls`), atomic file swap, switchover without
  a restart. Failed attempts are non-critical as long as the old certificate
  remains valid.
- **Maintaining the CA bundle** (`TrustedUserCAKeys` file): fetched every
  `bundle_interval` (default 1 h), written only on change — this is how
  CA rotations reach the hosts.
- **Principals cache + Unix socket** (`agentd.sock`) for the sshd helper:
  responses younger than 10 s are served directly from the cache; otherwise
  an API query with a 5 s timeout; if the API is unreachable, the cache
  (persisted across restarts) carries on until `cache_ttl` —
  **after that, fail-closed**, logins are denied.
- With `--session-audit`: session/sudo events from the local spool
  (`sessions-spool.jsonl`, loss-tolerant) are flushed via mTLS to
  `POST /v1/agent/sessions` every 15 s.

`config.yaml` in the state directory (written during enrollment, manually
adjustable; requires `systemctl restart gssh-agentd` afterwards):

| Field | Default | Meaning |
|---|---|---|
| `agent_url` | from enrollment | server's mTLS agent API |
| `host_id` | from enrollment | assigned host UUID |
| `host_name` | from enrollment | registered hostname |
| `ssh_key_path` | from enrollment | host public key whose certificate is maintained |
| `ssh_dir` | `/etc/ssh` | target for bundle/certificate/snippet |
| `socket_path` | `<state-dir>/agentd.sock` | Unix socket of the principals helper |
| `cache_ttl` | `5m` | how long cached principals remain valid during an API outage (fail-closed afterwards) |
| `bundle_interval` | `1h` | refresh interval of the CA bundle |
| `renew_interval` | `5m` | check interval for certificate/mTLS renewal |
| `heartbeat_interval` | `1m` | how often the agent reports liveness (`last_seen_at`) |
| `reload_command` | detected at enrollment | command to run after a new host certificate, e.g. `systemctl reload ssh` (empty only with `--no-reload`) |
| `session_audit` | `false` | session/sudo audit (only meaningfully set via `enroll --session-audit`) |

Note on `cache_ttl`: higher values bridge longer API outages, but also
extend the window in which revoked permissions still apply on this
host (ADR-022).

## 7. Re-enrollment

Generate a new token and run `gssh-agentd enroll` again — all files are
overwritten (new mTLS key pair, new host certificate, fresh configuration);
an existing `socket-token` is preserved. Needed e.g. when the mTLS
certificate has expired (the agent was down for a long time) or the server
URL changes. sshd is reloaded by the enrollment itself; afterwards run
`systemctl restart gssh-agentd`.

Re-enrollment is also the repair path for hosts enrolled **before**
enrollment reloaded sshd: those wrote a correct configuration that the
running daemon never read (see
[troubleshooting.md](troubleshooting.md#enrolled-grants-correct-sshd--t-looks-right--still-permission-denied-publickey)).
A plain `systemctl reload sshd` fixes the immediate symptom; re-enrolling
additionally fills in the missing `reload_command`, without which the next
certificate renewal repeats the problem.

## 8. Uninstallation

1. `systemctl disable --now gssh-agentd`
2. Remove the package (`apt remove gssh-agentd` / `rpm -e gssh-agentd`).
3. Roll back sshd: delete `/etc/ssh/sshd_config.d/guided-ssh.conf`,
   `/etc/ssh/guided-ssh-user-ca.pub`, and
   `/etc/ssh/ssh_host_ed25519_key-cert.pub`, then `systemctl reload sshd`
   — the host will no longer accept certificate logins.
4. If session audit is active: remove the lines marked by guided-ssh
   (`# guided-ssh session audit (managed)` + `session optional pam_exec.so …`)
   from `/etc/pam.d/sshd` and `/etc/pam.d/sudo`.
5. Delete the state: `rm -rf /var/lib/guided-ssh`.
6. Remove the host record on the server side (this immediately invalidates
   the mTLS certificate, ADR-022); no API/CLI endpoint for this exists
   yet — requires a DB-level intervention (`hosts`).
