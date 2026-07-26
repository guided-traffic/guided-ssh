# One-Command Host Install (Host Rollout)

Instead of distributing packages, `gssh-server` can serve the host agent
itself: an admin clicks **Hosts → Add host** in the web UI, gets a one-time
enrollment token and a single line to paste on the target host — the server
delivers the install script, the matching `gssh-agentd` binary, and the
systemd unit.

```sh
curl -fsSL https://gssh.example.com/install.sh | sudo sh -s -- --token gssh-et-…
```

Audience: operators deciding whether and how to enable the feature, and
anyone reviewing its security model. Enabling it with Helm and choosing a
pin source:
[chart README](../deploy/helm/guided-ssh/README.md#host-rollout-one-command-install).
Manual enrollment without this feature: [enrollment-guide.md](enrollment-guide.md).

## What the UI does

**Hosts → Add host** asks for TTL, tags, an optional hostname binding and
whether to enable session auditing, mints a one-time enrollment token and
shows the line to run on the target host.

The hostname binding is optional and matched **exactly** against the host's
own `hostname` output — bind `web-01` while the host reports
`web-01.example.com` and the enrollment fails. The token is not spent by that
failure, so a re-run with the corrected name works; leave the field empty to
mint an unbound token.

## What the script does

The script is templated by the server: public URL, agent URL, SPKI pin, the
SHA-256 of every embedded agent binary and the systemd unit are already baked
in — only the token and the flags are variable. It downloads the matching
`gssh-agentd` binary, verifies its hash, installs it to `/usr/bin`, writes the
unit, enrolls the host **pinned**, and waits (up to 10 s) for the agent socket
before reporting success. Flags: `--arch` (otherwise derived from `uname -m`),
`--session-audit`, `--no-systemd`.

## Enabling it

All four conditions must hold, otherwise the button stays disabled and the
endpoints answer `503` naming what is missing: agent binaries in the image
(they are, in released images), an SPKI pin, `GSSH_AGENT_PUBLIC_URL` and a
public base URL. Both URLs must be `https://` — plain-HTTP URLs never pass
the gate (a cleartext `curl … | sudo sh` would defeat both the hash check and
the pin). With Helm:

```sh
helm upgrade guided-ssh guided-ssh/guided-ssh -n guided-ssh --reuse-values \
  --set hostRollout.enabled=true \
  --set hostRollout.agentPublicUrl=https://gssh-agent.example.com:8443 \
  --set hostRollout.publicUrl=https://gssh.example.com
```

Pin sources (`dial`/`file`/`static`), the file-based variant for
hairpin/split-horizon setups, and the download rate limit:
[chart README](../deploy/helm/guided-ssh/README.md#host-rollout-one-command-install).

> **Do not mix script install and deb/rpm.** The script places a
> package-foreign binary in `/usr/bin/gssh-agentd` and a unit in
> `/etc/systemd/system`; a later package install would fight over the same
> files. Pick one path per host. The package route stays available
> ([deploy/packaging/](../deploy/packaging/)).

## Security model

This is `curl … | sudo sh` — the classic supply-chain surface. What protects it:

- **HTTPS only.** TLS terminates at the ingress/reverse proxy; script, manifest
  and binary are fetched over `https://` and served with `Cache-Control: no-store`
  (no stale pins, hashes or binaries from intermediate caches).
- **The binary's SHA-256 is templated into the script.** A tampered download
  fails the hash check and the script aborts before anything is installed.
- **SPKI pinning is mandatory, not opt-in.** Three fail-closed sources
  (static > certificate file > verified self-dial). Without a pin the whole
  rollout is disabled. Certificate rotation is picked up automatically (the
  file source is read uncached, the dial source refreshes in the background),
  and a pin mismatch fails the TLS handshake **before** the token is spent.
- **`--require-pin` is footgun protection, not MITM protection.** It stops an
  accidentally un-pinned enrollment (a copied `enroll` line); the actual
  transport protection is HTTPS plus the pin sources.
- **Two-step alternative** for anyone who will not pipe into a shell — the UI
  shows it next to the one-liner:

  ```sh
  curl -fsSLO https://gssh.example.com/install.sh
  less install.sh          # inspect
  sudo sh install.sh --token gssh-et-…
  ```

- **The token is a one-time, short-lived bearer secret** (UI default 1 h,
  single use enforced server-side). Its plaintext exists exactly once, in the
  mint response — never in logs, never in the audit payload.
- **Minting requires the admin role and is audited**
  (`host.enroll_token.created`, without the token).
- **The binary download is public but tightly rate-limited** (10 per client IP
  per minute by default, `hostRollout.downloadRpm`). The token gates the
  enrollment, not the download.

## Accepted residual risks

- **Token in argv and shell history.** `--token` is briefly visible in `ps` /
  `/proc/*/cmdline` on the target host and stays in the operator's shell
  history. The alternatives shift the exposure rather than remove it (an env
  var lands in the history too and `sudo` strips it; stdin is unavailable when
  the script itself arrives via a pipe). The load-bearing control is single use
  plus a short TTL — once used, the token is worthless.
- **Version disclosure.** The public manifest (`GET /v1/agents`) names the
  server version. The binary is identifiable anyway; hiding it would be
  security theatre.
- **The `systemctl` branch is untested in CI.** The end-to-end smoke test runs
  the script with `--no-systemd` in a container without systemd; enable/restart
  and the health check are exercised manually. A systemd container in CI would
  be privileged and flaky, and a `systemctl` stub would only fake the behavior.

Dual-certificate proxies (serving RSA or ECDSA depending on the client) are not
a concern: both pin consumers — the server's self-dial and the agent — are Go
TLS clients with effectively the same cipher preferences, so they see the same
leaf. With the file-based pin source the question does not arise at all.
