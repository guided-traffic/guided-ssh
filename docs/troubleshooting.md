# Troubleshooting

Real error patterns with cause → diagnosis → fix. The quoted messages are
taken from the code (as of Phase 13). Background:
[Operations manual](operations-manual.md), [Enrollment guide](enrollment-guide.md),
[Grants](grants.md), [GitLab CI](gitlab-ci.md).

## Login/issuance fails (`gssh login` / `POST /v1/sign/user`)

### 401 — "invalid id-token" / "authorization: bearer token missing"

- **Cause**: ID token expired, wrong audience (token not issued for
  `GSSH_CLIENT_OIDC_CLIENT_ID`), wrong issuer, or a broken signature (JWKS). The
  reason is in the server-side log (`sign/user: token rejected`), the 401
  response is deliberately generic.
- **Diagnosis**: server log (`kubectl logs`) at the time of the attempt;
  check the token claims (iss/aud/exp).
- **Fix**: log the client in again (`gssh login` fetches fresh tokens);
  check in the IdP that the CLI client supplies the expected audience. If
  the server clock runs fast, go-oidc rejects fresh tokens as expired (no
  leeway on `exp`) — make sure NTP is working.

### 403 — "no access rules (grants) for this user"

- **Cause**: the user has not a single grant through their groups — no
  grant, no certificate (ADR-018).
- **Diagnosis**: `gssh-admin grant list`; compare the groups in the token
  (or in the web UI under Users & Groups) with the grant groups; the server
  log names `subject` and `groups`.
- **Fix**: create a grant for one of the user's groups, or add the user to
  the right group in the IdP (wait for the sync interval, default 5 m, or
  use a fresh token — the groups used at issuance come from the token
  claims).

### 403 — "no access grants … the token carries no groups claim"

- **Cause**: the ID token contains no `groups` at all, so no grant can
  match. Almost always the client did not request the `groups` scope: a
  `scopes:` line in `~/.config/guided-ssh/config.yaml` that omits it, or an
  IdP client that does not release the claim. Without a `scopes:` key the
  CLI asks for `openid profile email groups` on its own (it drops `groups`
  only if the issuer's discovery publishes a `scopes_supported` list
  without it, see [`internal/auth/flow.go`](../internal/auth/flow.go)).
- **Diagnosis**: server log (`sign/user: no grants`) shows an empty
  `groups`; the authorize URL printed by `gssh login` shows the requested
  `scope`; `curl -s <issuer>/.well-known/openid-configuration | jq
  .scopes_supported` shows what the IdP advertises.
- **Fix**: remove a narrowing `scopes:` line from the config (or set
  `scopes: [openid, profile, email, groups]`), and give the IdP client a
  groups mapper — Dex: `groups` is served on request; Keycloak: a `groups`
  client scope assigned to the CLI client, otherwise Keycloak answers an
  unrequestable scope with `invalid_scope`.

### 403 — "user is disabled"

- **Cause**: the group sync has marked the user as inactive (offboarding).
- **Fix**: if intentional, nothing to do. Otherwise check the IdP account;
  the user is reactivated after the next sync (5 m).

### 429 — "too many requests — please try again later"

- **Cause**: rate limit per client IP: the request budget (default 60/min,
  burst 20) is exhausted — or the **failure budget** (default 10/min): 10
  consecutive 401/403 responses already block further attempts, even if
  the request budget would still allow more.
- **Diagnosis**: metric `gssh_http_responses_total{code="429"}`; were there
  accumulated 401/403 responses from the same source beforehand? Behind an
  ingress without `GSSH_RATE_TRUST_PROXY=true`, all users count as a single
  IP (the proxy's) and throttle each other.
- **Fix**: honor `Retry-After: 60`; fix the root cause of the failed
  attempts; set `GSSH_RATE_TRUST_PROXY=true` behind a proxy; adjust the
  limits via `GSSH_SIGN_RATE_PER_MINUTE`/`GSSH_SIGN_FAIL_PER_MINUTE`.

### 503 — "oidc not configured"

- **Cause**: `GSSH_OIDC_ISSUER` is not set on the server — `/v1/sign/user`
  is deliberately disabled.
- **Fix**: set `config.oidc.issuer`/`config.oidc.client.clientID` in the
  Helm values and redeploy.

## gssh error messages (client-side)

### "SSH_AUTH_SOCK not set — is an ssh-agent running?"

- **Cause**: no ssh-agent in the session — gssh stores the key and
  certificate exclusively in the agent (ADR-016).
- **Fix**: `eval $(ssh-agent -s)` (mandatory in CI jobs before
  `gssh ci-login`), or use the desktop session's agent.

### "configuration …: required fields missing: api_url, issuer, client_id"

- **Cause**: `~/.config/guided-ssh/config.yaml` is incomplete (the three
  fields are required).
- **Fix**: complete the file; if the file is missing, gssh prints example
  content. Path override: `--config` or `GSSH_CONFIG`.

### `gssh status` returns exit code 1

- No valid guided-ssh certificate in the agent — intentionally scriptable.
  `gssh login` (or `--if-needed` in the Match-exec integration).

### Settings from config.yaml are gone after an install

- **Cause**: `client.sh` rewrites `~/.config/guided-ssh/config.yaml` with
  the values of the server it was fetched from — that is what makes a
  re-install the way to switch environments. Hand-added keys (`validity`,
  `scopes`) are not carried over.
- **Fix**: the previous file is right next to it as `config.yaml.bak`; copy
  the keys you need back. A `pin_sha256` for the *same* `api_url` survives
  the rewrite automatically; a pin belonging to another server is dropped
  with a warning (it would not match the new server anyway).

## Host login fails (certificate present, sshd rejects it)

### Enrolled, grants correct, `sshd -T` looks right — still `Permission denied (publickey)`

- **Cause**: the running sshd never read the guided-ssh snippet. sshd
  parses its configuration exactly once, at startup; per-connection children
  are forks of the listener and inherit the already-parsed configuration.
  A host enrolled while sshd was running — with a version that did not
  reload it (before the reload became part of enrollment) — has neither
  `TrustedUserCAKeys` nor `AuthorizedPrincipalsCommand` in memory. It
  rejects the user certificate as signed by an untrusted CA and falls back
  to `authorized_keys`, which a purpose-built account usually does not have.
- **Diagnosis**: every obvious check reports healthy here, so use ones that
  look at the *process*, not at the files:

  ```sh
  # What the running daemon actually serves — a plain host key type means
  # the snippet is not loaded, "…-cert-v01@openssh.com" means it is.
  ssh -o HostKeyAlgorithms=ssh-ed25519-cert-v01@openssh.com \
      -o StrictHostKeyChecking=no -o BatchMode=yes localhost true
  # ⇒ "no matching host key type found" ⇒ stale sshd

  # Listener start time vs. snippet mtime, and whether it was ever reloaded:
  systemctl show ssh --property=ExecMainStartTimestamp
  stat -c '%y' /etc/ssh/sshd_config.d/guided-ssh.conf
  journalctl -u ssh | grep -i 'received sighup'
  ```

  What does **not** help: `sshd -T -C user=…` reads the files fresh from
  disk and prints the complete, correct guided-ssh block regardless of what
  the process has loaded — the most misleading signal in the chain.
  `gssh-agentd principals -user <name>` also returns the right principals:
  that path is intact, it is simply never invoked. And the host's auth log
  showing only `Connection closed by authenticating user … [preauth]`
  without a `Failed publickey` line proves nothing about the client — sshd
  rejects at the offer stage and logs nothing there, even at
  `LogLevel VERBOSE`.
- **Fix**: `systemctl reload ssh` (or `sshd`, depending on the
  distribution). Then re-enroll the host: enrollment now validates,
  reloads, and verifies the running daemon, and it persists
  `reload_command` — without it the next certificate renewal writes a
  certificate that sshd never picks up, and the same silent failure returns
  one certificate lifetime later
  ([enrollment-guide.md](enrollment-guide.md), §7).

### AuthorizedPrincipalsCommand returns nothing — fail-closed

- **Cause**: the API is unreachable **and** the principals cache is older
  than `cache_ttl` (default 5 m) — the helper then deliberately refuses
  (daemon log: "api unreachable and cache expired" or "principals
  unavailable (fail-closed)"). Or the daemon is not running at all
  ("gssh-agentd unreachable (is the service running?)").
- **Diagnosis**: on the host, `gssh-agentd principals -user <name>`;
  `journalctl -u gssh-agentd`; server-side agent reachability
  (`gssh_agent_heartbeats_total`, LoadBalancer/mTLS service).
- **Fix**: start the service (`systemctl start gssh-agentd`); fix the
  network path to the agent API. Existing SSH sessions are unaffected —
  only new logins.

### Grant/tag selector does not match

- **Cause**: no grant exists for the local target user `%u` whose tag
  selector matches the host tags (selector ⊆ tags), or the requesting user
  is not an active member of the grant's group. The helper then returns an
  empty or unrelated principals list — sshd rejects the login.
- **Diagnosis**: `gssh-agentd principals -user <target-user>` on the host —
  is the user's identity principal (username/email) in the output? Compare
  the host tags and grants in the web UI.
- **Fix**: adjust the grant (`gssh-admin grant …`) or enroll the host with
  matching tags. Changes take effect within the cache TTL (5 m).

### Certificate expired

- **Diagnosis**: `gssh status` (shows "expired") or `ssh -vvv` (the server
  ignores the certificate).
- **Fix**: `gssh login`; for transparent renewal, `gssh integrate` (renews
  when less than 5 m of validity remain).

### TrustedUserCAKeys outdated (after CA rotation)

- **Cause**: the host does not yet have the new CA key — the bundle is
  only fetched every `bundle_interval` (default 1 h), or the agent was not
  running.
- **Diagnosis**: compare `/etc/ssh/guided-ssh-user-ca.pub` with
  `GET /v1/ca/bundle/user`; daemon log ("user-ca-bundle updated" is
  missing).
- **Fix**: `systemctl restart gssh-agentd` (fetches the bundle immediately
  on startup).

## Enrollment errors

### 403 — "enrollment token invalid, used, or expired"

- **Cause**: the token was already used (single-use, transactional), the
  TTL expired, or there is a typo.
- **Fix**: generate a new token (`gssh-server enroll-token`).

### 403 — "enrollment token is bound to a different hostname"

- **Cause**: the token was created with `-name` and the host reports a
  different hostname (`os.Hostname()` differs).
- **Fix**: set `--hostname` to match during enrollment, or generate the
  token without a name binding.

### "reading ssh host key (is sshd installed? ssh-keygen -A)"

- **Cause**: `/etc/ssh/ssh_host_ed25519_key.pub` is missing.
- **Fix**: run `ssh-keygen -A`, or point `--ssh-key` at an existing key.

### "… does not include /etc/ssh/sshd_config.d/guided-ssh.conf"

- **Cause**: the main `sshd_config` has no `Include` covering the snippet
  directory, or the only one sits inside a `Match` block (it would then not
  apply to every login). The check runs before the first network call, so
  the token is not spent.
- **Fix**: add the line from the error message as the **first** line of
  `sshd_config` (sshd keeps the first value it obtains for a keyword) and
  re-run. guided-ssh deliberately does not edit that file.

### "sshd rejected the generated configuration (rolled back …)"

- **Cause**: `sshd -t` failed over the freshly written snippet — usually a
  pre-existing error in `sshd_config` that only surfaces now, or a state
  directory path sshd cannot use.
- **Diagnosis**: the message carries sshd's own output; `sshd -t` reproduces
  it. The snippet has already been removed (restored), sshd stays usable.
- **Fix**: repair the reported line, then enroll again.

### "reloading sshd (…) failed" / "still serves a plain host key"

- **Cause**: the reload command exited non-zero, or the running daemon still
  answers with a plain host key afterwards — the configuration is on disk
  but not in memory, which is exactly the failure that used to stay silent.
  A socket-activated sshd (`ssh.socket`) is a common cause: `ssh.service` is
  inactive, so `systemctl reload` has nothing to reload.
- **Diagnosis**: run the printed reload command by hand; `systemctl status
  ssh ssh.socket`; check that the `Include` sits before every `Match` block.
- **Fix**: pass the working command via `--reload-command`, or `--no-reload`
  where reloads belong to config management or the image build (each
  connection of a socket-activated sshd reads the configuration fresh, so
  nothing needs reloading there — but then set `reload_command` yourself if
  host certificate renewals should reach a long-running daemon).

## Agent issues

### mTLS certificate expired

- **Cause**: the agent was down longer than the rotation window (rotation
  runs at 2/3 of the 1-year validity, over the still-valid channel — once
  the certificate has expired, that channel no longer exists).
- **Diagnosis**: daemon log: TLS handshake error on every API contact;
  `openssl x509 -in /var/lib/guided-ssh/agent.crt -noout -enddate`.
- **Fix**: re-enroll with a new token ([enrollment-guide.md](enrollment-guide.md), §7).

### `agentd.sock` is missing

- **Cause**: the daemon is not running (the socket is recreated on every
  start), or `socket_path`/`-state-dir` differ between the daemon and the
  sshd snippet.
- **Diagnosis**: `systemctl status gssh-agentd`; `ls -l /var/lib/guided-ssh/agentd.sock`;
  check that the snippet and `config.yaml` use the same `-state-dir`.
- **Fix**: start the service; align the paths.

## CI errors (`gssh ci-login` / `POST /v1/sign/ci`)

### 401 — "invalid job token"

- **Cause**: usually the wrong audience — the job's `id_tokens` lacks
  `aud: guided-ssh` (or differs from `GSSH_CI_AUDIENCE`); or
  `GSSH_CI_ISSUER` does not point at the job's GitLab instance.
- **Fix**: set up `.gitlab-ci.yml` according to
  [gitlab-ci.md](gitlab-ci.md) (reference pipeline section).

### 403 — "no matching CI grant for this project/ref"

- **Cause**: no CI grant matches — commonly: the ref is not protected
  (`protected_only` defaults to `true`), the project path does not match
  the grant (mismatch after the project was moved/renamed), or the
  `ref`/`environment` glob does not match.
- **Diagnosis**: the server log names `project`, `ref`, `ref_protected`,
  `environment`; `gssh-admin ci-grant list`.
- **Fix**: protect the branch or adjust the CI grant.

### 403 — "CI access for this project is disabled"

- **Cause**: the project's service account is set to `active=false` (kill
  switch, e.g. via the web UI).
- **Fix**: verify this was intentional; reactivate it in the web UI if
  needed.

### 400 — "job token expires too soon for a certificate"

- **Cause**: the token's `exp` (= job timeout) is practically now — the
  certificate lifetime is capped at `exp`, and nothing would be left.
- **Fix**: run `gssh ci-login` early in the job; check the job timeout.

### Server start fails with "same issuer and same audience …"

- **Cause**: `checkAudienceSeparation` — user OIDC and GitLab CI are
  configured with the same issuer **and** `GSSH_CI_AUDIENCE` ==
  `GSSH_CLIENT_OIDC_CLIENT_ID`. Tokens would then be interchangeable between
  both sign endpoints; the server refuses to start (security review, Phase 10).
- **Fix**: configure separate audiences (or separate issuers).

## Server startup errors

| Message | Cause → Fix |
|---|---|
| `GSSH_OIDC_ISSUER is set, but GSSH_CLIENT_OIDC_CLIENT_ID is missing` | fail-fast instead of silently rejecting all tokens → set the clients' client ID |
| `the server/client oidc split renamed these variables — set: …` | pre-split variables (`GSSH_OIDC_CLIENT_ID`, `GSSH_UI_OIDC_*`, `GSSH_UI_BASE_URL`) still set → rename per the mapping in the message ([migration notes](../deploy/helm/guided-ssh/README.md#migration-serverclient-oidc-split)) |
| `GSSH_SERVER_OIDC_CLIENT_ID is set, but GSSH_SERVER_OIDC_CLIENT_SECRET is missing` (or vice versa) | half-configured server client → set both, or neither (UI login off) |
| `GSSH_SERVER_OIDC_CLIENT_ID and GSSH_CLIENT_OIDC_CLIENT_ID must be different idp clients` | one IdP client reused for server and CLIs → create a separate confidential client for the UI login |
| `database configuration incomplete: GSSH_DB_… not set` | secret missing or key mapping wrong (`secrets.db.existingSecret`, keys via `secrets.db.keys`) |
| `GSSH_CA_MASTER_KEY decode: …` | value is not valid base64 → generate it correctly (`head -c 32 /dev/urandom \| base64`) |
| `ca: invalid master key: <n> bytes instead of 32` | value does not decode to 32 bytes → use a 32-byte key |
| `ca: invalid master key: decryption failed` | the master key does not match the already-encrypted `ca_keys` (secret swapped between environments) → deploy the correct key; **do not** "clean up" the DB — that would create a new CA |
| `migrations: …` | check DB connection details/network/DB permissions; advisory lock: is another instance stuck in migration? |

## Clock skew

- Certificates are backdated by 1 min (`signBackdate`); the policy allows a
  maximum backdating of 5 min (`maxBackdate`). Hosts whose clock runs more
  than ~1 min **ahead** of the server clock reject freshly issued
  certificates as "not yet valid" (visible in `ssh -vvv`).
- go-oidc checks `exp` without leeway — if the **server** clock runs fast,
  fresh ID tokens are rejected as expired (401).
- **Fix**: NTP on the server, hosts, and IdP (already in place in the
  Kubernetes deployment; check on bare-metal hosts with `timedatectl`).

## Diagnostic tools

| Tool | Purpose |
|---|---|
| Web UI → Audit (auditor role) or `GET /v1/admin/audit?event_type=…&actor=…&q=…` | every issuance/grant change/session; `q` matches actor + payload (host, pipeline); export as CSV/JSON |
| `gssh status` | certificates in the agent, remaining validity, principals; exit code is scriptable |
| `ssh -vvv user@host` | shows whether the certificate is offered and why it is rejected |
| `gssh-agentd principals -user <name>` (on the host) | exactly what sshd sees — empty output/errors explain every rejected login |
| `journalctl -u gssh-agentd` / `journalctl -u sshd` | agent JSON logs (renewals, fail-closed warnings); sshd with `LogLevel VERBOSE` logs the certificate serial |
| `kubectl logs deploy/guided-ssh` | server logs: rejected tokens with reason, enrollments, sync runs |
| Metrics (`/metrics`, port 9090) | `gssh_http_responses_total{code}` (error rates, 429), `gssh_agent_heartbeats_total`, `gssh_certificates_issued_total` |
| `sshd -t` | validate the sshd configuration (snippet) |
</content>
