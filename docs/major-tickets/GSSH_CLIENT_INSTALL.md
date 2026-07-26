# Client Install via Frontend — Implementation Plan

> **As of 2026-07-26.** Initial plan, verified against the code on branch
> `feat/new-frontend`. Written in the same style as
> [ONE_CMD_INSTALL.md](ONE_CMD_INSTALL.md) (the one-command **host** install):
> every work package states **Files**, **Steps**, **Do not** (deliberately
> discarded approaches with reasons), and **Done when** (verification
> criteria). Terminology (public listener, SPKI pin, fail-closed, …) is
> defined there and not repeated here.

Goal: the web UI offers the **`gssh` client for download**, and a Linux (or
macOS) user gets from zero to an SSH connection in **as few steps as
possible**. The client binaries live **inside the server container**
(version-matched to the running server, same as the agent binaries); a
server-templated install script downloads the binary **and writes a
ready-to-use client configuration** — every value the config needs is
already known to the server.

Target UX (three steps; fewer is impossible — `gssh login` requires an
interactive browser SSO):

```sh
curl -fsSL https://gssh.example.com/client.sh | sh   # binary + ready config
gssh login                                           # SSO in the browser
gssh ssh <host>
```

No sudo, no token, no secrets: the script installs into `~/.local/bin` and
grants nothing — access is only ever granted at `gssh login` time via OIDC.

The Hosts page additionally gets a per-host **Connect** dialog (Phase D3)
that mirrors these steps — the one-time install deliberately separated from
the connect line, so a user with an installed client goes straight to step
two — plus a **pinned login-via-IP fallback** for environments with
unreliable DNS (Phase C + D3).

---

## Feasibility: YES

All building blocks exist; what's missing is wiring, not a new concept
(verified against the code):

| Building block | Status today | What's missing |
|---|---|---|
| Client cross-build | `make cross` already builds `bin/gssh-<os>-<arch>` for `linux/amd64 linux/arm64 darwin/arm64` (`Makefile`, `CROSS_PLATFORMS`) | the same loop as a Dockerfile build stage |
| Embed + manifest + hash serving | `internal/agentdist` (`Source`, `List`, `Open`, hex SHA-256, `.gitkeep` degradation) | generalizing the binary-name prefix (`gssh-agentd-` → parameter) |
| Public download endpoints | `internal/api/rollout.go` + `agents.go` (`/v1/agents`, `/v1/agents/{os}/{arch}`) | the `/v1/clients` twins |
| Templated install script | `internal/api/install_script.go` + `install.sh.tmpl` (quoting checks, fail-closed rendering) | a client variant without token/systemd/enroll |
| Config values for the client | `gssh` needs `api_url`, `issuer`, `client_id`, optional `pin_sha256` (`internal/cli/config.go`) — the server knows all of them: `PublicBaseURL`, `deps.UIConfig` (issuer/client ID, already served publicly via `GET /v1/ui/config`), `deps.Pins` | templating them into the script |
| Download rate limiting | `deps.DownloadRateLimit` (`GSSH_AGENT_DOWNLOAD_RPM`, per-IP token bucket) | reuse for the client binary route |
| Frontend patterns | `web/src/app/features/*` (standalone pages), manifest-driven gating (Add Host button), mock mode, `api/openapi.yaml` + `make web-api` | a download page |

**Version parity comes for free** (same argument as the host install): the
client binaries are produced in the **same Docker build** as the server
(same `-ldflags`, same commit). The server serves exactly the client that
matches it.

**All platforms, always:** `linux/amd64`, `linux/arm64`, `darwin/arm64` —
cross-built statically (`CGO_ENABLED=0`), embedded in full into every server
image variant. Extendable by adding an entry to the build loop.

---

## Iron Rules

Rules 5, 6, 10, 11 from [ONE_CMD_INSTALL.md](ONE_CMD_INSTALL.md) apply
unchanged (POSIX `sh` with `main()` wrapper; atomic same-directory binary
swap; `Cache-Control: no-store` on script, manifest, and binary; never
commit binaries). Additionally:

1. **No sudo, no root.** The script installs into `~/.local/bin` and
   `~/.config/guided-ssh/` and **aborts when run as root** (`id -u` = 0):
   run via sudo it would install into root's home — a footgun, not a
   feature. This is the key difference from the host install and the reason
   the client path needs no token and a much smaller security surface.
2. **Never overwrite an existing client config.** If
   `${XDG_CONFIG_HOME:-~/.config}/guided-ssh/config.yaml` exists, the script
   keeps it, says so, and continues (binary update still happens). No
   `--force` flag — editing the file is the explicit path.
3. **No URL derivation.** The templated `api_url` is `PublicBaseURL`
   (`GSSH_PUBLIC_URL` → `GSSH_UI_BASE_URL`), verbatim. Missing or non-https
   ⇒ gate closed (503), reusing `isHTTPSURL` — plaintext HTTP would void
   the hash check exactly as described in `rollout.go`.
4. **Fail-closed config, no partial writes.** If issuer or client ID is
   unset on the server, the gate closes — the script never writes a
   config.yaml that `gssh` would then reject (`LoadConfig` requires all
   three fields; a half-written config is strictly worse than a clear 503).
5. **Host-rollout routes stay untouched.** `/v1/agents/…`, `/install.sh`,
   the rollout gate, and the enrollment flow are not modified — the client
   path is an **additional**, independent feature with its own (smaller)
   gate.
6. **No pin in the config by default** — see the decision log. `--pin` is
   an explicit opt-in.

---

## New Environment Variables

**None.** The feature reuses `GSSH_PUBLIC_URL`/`GSSH_UI_BASE_URL` (base
URL), the existing UI config values (issuer, client ID), the pin provider
(only for the `--pin` opt-in), and the existing download limiter instance.
Documentation duty instead: `GSSH_AGENT_DOWNLOAD_RPM` now throttles client
binary downloads too (per client IP, shared bucket) — one doc line in the
README env-var table, no rename (a rename would break existing
deployments for zero gain).

---

## Implementation Order

**A → B → C → D → E.** B (endpoints) needs A (binaries + generic source).
C (CLI login overrides) is independent of A/B and can run in parallel.
D (frontend) needs B; the connect dialog's IP variant (D3) needs C.
E (docs, E2E) comes last.

---

## Phase A — Client Binaries in the Container

### A1 — Generalize the binary source: `internal/bindist`

**Files:** `internal/bindist/bindist.go` (new, extracted),
`internal/agentdist/agentdist.go` (shrinks), `internal/clientdist/`
(new: `clientdist.go`, `bin/.gitkeep`), `.gitignore`.

**Steps:**

1. Extract the generic parts of `internal/agentdist` — `Info`, `Source`,
   `List`, `Open`, `scan`, `hashFile`, `parseName` — into a new package
   `internal/bindist`, with the name prefix as a constructor parameter
   instead of the package constant `binPrefix`:
   ```go
   func NewFromFS(fsys fs.FS, prefix string) *Source
   ```
   `ErrNotFound` moves along. Behavior is unchanged: `.gitkeep` and
   non-matching names are skipped, size/SHA-256 computed once
   (`sync.Once`), stable sort.
2. `internal/agentdist` keeps its path, embed, and public API unchanged
   (the `api` package and the Dockerfile `COPY` target keep working):
   `New()` returns `bindist.NewFromFS(sub, "gssh-agentd-")`; re-export via
   aliases so call sites don't churn:
   ```go
   type Info = bindist.Info
   type Source = bindist.Source
   var ErrNotFound = bindist.ErrNotFound
   func NewFromFS(fsys fs.FS) *Source // keeps the agent prefix, for tests
   ```
   `UnitFile` stays here (agent-only concern, single source — rule 7 of the
   host plan).
3. New package `internal/clientdist`, mirroring the agentdist shape:
   `bin/.gitkeep`, `//go:embed all:bin`, and
   ```go
   func New() *bindist.Source        // prefix "gssh-"
   func NewFromFS(fsys fs.FS) *bindist.Source
   ```
   `.gitignore` gains:
   ```
   internal/clientdist/bin/*
   !internal/clientdist/bin/.gitkeep
   ```
   Note on the prefix: `"gssh-"` would also match agent binary names — but
   the directories are separate embeds, and `parseName` rejects an arch
   containing `-` anyway (`gssh-agentd-linux-amd64` → arch
   `"linux-amd64"` → skipped). Safe by construction, still: don't mix the
   directories.

**Do not:**
- Rename or move `internal/agentdist` (Dockerfile `COPY` path,
  `nfpm.yaml`, and every import would churn for zero functional gain).
- Share one `bin/` directory for both artifact families (muddies the two
  gates' "binaries" conditions and the build stages).
- Duplicate `agentdist.go` wholesale into `clientdist` — the prefix is the
  only difference; duplication would drift.

**Done when:** existing `agentdist` tests pass unchanged; new
`bindist`/`clientdist` unit tests (fstest.MapFS) show: client names parse
(`gssh-linux-amd64` → linux/amd64, `gssh-darwin-arm64` → darwin/arm64),
agent-named files in a client FS are skipped, empty FS ⇒ empty `List()`;
`make build` succeeds without any binaries present.

### A2 — Dockerfile: extend the cross-build stage

**Files:** `Dockerfile`.

**Steps:**

1. In the existing `agentbuild` stage (already `--platform=$BUILDPLATFORM`,
   same `-ldflags` ARGs as the server stage), add a second loop after the
   agent loop:
   ```dockerfile
   RUN for platform in linux/amd64 linux/arm64 darwin/arm64; do \
         CGO_ENABLED=0 GOOS=${platform%/*} GOARCH=${platform#*/} go build -trimpath \
           -ldflags "…same as agent loop…" \
           -o /out-client/gssh-${platform%/*}-${platform#*/} ./cmd/gssh || exit 1; \
       done
   ```
   (Separate output directory — the agent loop's `/out/` is COPY'd in full
   into `internal/agentdist/bin/`; mixing would embed clients into the
   agent source.)
2. In the server build stage, next to the existing agent COPY:
   ```dockerfile
   COPY --from=agentbuild /out-client/ ./internal/clientdist/bin/
   ```

Image growth: three static binaries ≈ +24 MB (~8 MB each, `bin/` of a
current `make cross` run) — same tradeoff as the agent embed, accepted.

**Do not:** create a separate build stage for the client (the agent stage
is already platform-invariant and BuildKit-deduplicated; a second stage
would re-download modules for nothing).

**Done when:** `docker build` log shows all three client `go build` runs;
in the running image, `GET /v1/clients` (after Phase B) lists all three
platforms with correct hashes.

### A3 — Local dev parity: `make cross` output naming

Nothing to do — `make cross` already produces exactly the embed names
(`bin/gssh-<os>-<arch>`). For local testing, copy them into
`internal/clientdist/bin/` (documented in DEVELOPER.md, Phase E).

---

## Phase B — Public Endpoints

New routes on the public mux, registered analogously to
`registerRolloutRoutes` (`internal/api/rollout.go:104`). All
unauthenticated: the binary is a public artifact and the config values are
already public via `GET /v1/ui/config` — access to hosts is gated by
`gssh login` (OIDC + grants), not by binary possession.

`Deps` gains one field: `Clients ClientSource` (interface over
`bindist.Source`, mirroring `AgentSource`).

### B1 — Client gate

**Files:** `internal/api/clients.go` (new).

A small gate, deliberately separate from `rolloutGate` (different, smaller
conditions — reusing the host gate would couple the client download to
`GSSH_AGENT_PUBLIC_URL` and the mandatory pin for no reason):

| Condition | `missing` entry |
|---|---|
| Client binaries embedded (`Clients.List()` not empty) | `"binaries"` |
| Public base URL set and https (`isHTTPSURL`, reused) | `"public_url"` / `"public_url_https"` |
| OIDC issuer set (`deps.UIConfig.OIDCIssuer`) | `"oidc_issuer"` |
| OIDC client ID set (`deps.UIConfig.OIDCClientID`) | `"oidc_client_id"` |

The pin is **not** a condition (see iron rule 6). 503 body: same
`{error, missing}` shape as `rolloutUnavailable`.

### B2 — Manifest `GET /v1/clients`

Mirror of `handleAgentManifest` (`internal/api/agents.go`): always 200
(diagnostic function), `Cache-Control: no-store`, regular limiter
(`deps.RateLimit`). Response:

```json
{
  "version": "v2.1.1",
  "ready": true,
  "missing": [],
  "pin": "9nPmyR…=",
  "pin_source": "static",
  "clients": [
    { "os": "darwin", "arch": "arm64", "size": 8178000, "sha256": "<hex>" },
    { "os": "linux", "arch": "amd64", "size": 8599000, "sha256": "<hex>" },
    { "os": "linux", "arch": "arm64", "size": 7968000, "sha256": "<hex>" }
  ]
}
```

`pin_source` is always set to the active pin source (`static` | `file` |
`dial` | `""`), exactly like the agent manifest (`PinStatus.Source`,
already exposed in `agents.go`) — diagnostic value.

`pin` is populated **only when the pin source is operator-controlled**
(`pin_source` ∈ {`static`, `file`}); with the `dial` source it stays
empty. Rationale: a dial pin is auto-derived from whatever certificate the
server currently presents and rotates with it — as a stored long-term
anchor for the DNS fallback it would break mid-outage or on the next
renewal, and clients must never be offered it (see the security model).
Consumers are the connect dialog's login-via-IP variant (D3) and the
`--pin` path of the script; both keep their existing fail-closed "no pin ⇒
no command" logic unchanged — this server-side rule is the single
enforcement point. Public value: it fingerprints the certificate the
server presents to every TLS client anyway.

Version disclosure: accepted for the same reason as the agent manifest
(K13 there — the binary is version-identifiable anyway; `gssh version`).

### B3 — Binary download `GET /v1/clients/{os}/{arch}`

Mirror of `handleAgentDownload`: gate closed ⇒ 503; unknown platform ⇒
404 plain text; otherwise stream with `application/octet-stream`,
`Content-Length`, `no-store`. Hangs off the **existing**
`deps.DownloadRateLimit` (shared bucket with the agent download — both are
"a person installs once" flows; a third limiter instance would be a third
knob with no distinct threat).

### B4 — Install script `GET /client.sh`

**Files:** `internal/api/client_script.go` + `client.sh.tmpl` (new),
following the `install_script.go` pattern including its fail-closed
rendering checks (quote/newline guard on every templated string, strict
`[a-z0-9]+` / 64-hex validation on arch and hash — same reasoning: never
ship a broken or injectable script to N machines).

**Behavior:** gate closed ⇒ 503 with `missing`; otherwise
`text/x-shellscript`, `no-store`. Template values: base URL, version,
issuer, client ID, per-platform SHA-256 (hex) for **all** embedded
platforms (linux *and* darwin — the script is portable), platform list for
error messages, and the current pin — templated **only from an
operator-controlled source** (`static`/`file`, same rule as the manifest;
`dial` ⇒ empty; empty allowed, only used with `--pin`).

**Script specification** (POSIX `sh`; host-plan rules 5 + 6 apply):

Structure: `set -eu` (no `pipefail`), everything in `main() { … }` with
`main "$@"` as the last line, `trap 'rm -f "$tmp"' EXIT`.

Flags (all optional): `--os <linux|darwin>`, `--arch <amd64|arm64>`
(override detection, for provisioning another machine's home via NFS etc.),
`--bin-dir <dir>` (default `$HOME/.local/bin`), `--pin` (write
`pin_sha256` into the config — opt-in, see decision log).

Flow:

1. **Preconditions:** abort if `id -u` = 0 ("run as your normal user, not
   root/sudo"); `command -v curl` or abort.
2. **Platform detection:** `uname -s` → `Linux`→linux, `Darwin`→darwin;
   `uname -m` → `x86_64`→amd64, `aarch64`/`arm64`→arm64. Unknown or
   not-embedded combination ⇒ abort naming the available platforms
   (templated list).
3. **Fetch the binary (atomically):** `mkdir -p "$bindir"`; temp file
   **in the target directory** (`mktemp "$bindir/.gssh.XXXXXX"` — same
   partition, atomic `mv`, replaces a currently running `gssh` without
   ETXTBSY); `curl -fsSL "<base>/v1/clients/$os/$arch" -o "$tmp"`; verify:
   `sha256sum -c` where available, else `shasum -a 256` (macOS has no
   sha256sum — the check must not silently be skipped: neither tool
   present ⇒ abort); `chmod 0755`, `mv -f "$tmp" "$bindir/gssh"`.
4. **Config:** target `${XDG_CONFIG_HOME:-$HOME/.config}/guided-ssh/config.yaml`
   (exactly `DefaultConfigPath()` in `internal/cli/config.go`). If it
   exists ⇒ keep + print "existing configuration kept" (iron rule 2).
   Else write (directory `mkdir -p`, file mode 0600):
   ```yaml
   api_url: <base>
   issuer: <issuer>
   client_id: <client-id>
   ```
   plus `pin_sha256: <pin>` only with `--pin`. `--pin` given but the
   templated pin is empty ⇒ abort (fail-closed, never a silent downgrade);
   the message names the cause: "server pin source is auto-derived (dial)
   — set `GSSH_PUBLIC_PIN` or `GSSH_PUBLIC_PIN_CERT_FILE` to enable
   `--pin`" (or "no pin source configured" when there is none at all).
5. **PATH check:** `case ":$PATH:" in *":$bindir:"*)` — if missing, print
   the export line to add; not an error.
6. **Next steps** (the whole point — printed, not documented somewhere
   else):
   ```
   gssh login          # sign in via SSO
   gssh ssh <host>     # connect
   gssh integrate      # optional: snippet for native ssh/scp/IDEs
   ```

**Do not:**
- Require or even tolerate sudo (iron rule 1).
- Auto-exec `gssh login` at the end of the script — stdin is the curl pipe,
  the browser handoff and the agent environment belong to the user's
  shell, not to a piped script.
- Install to `/usr/local/bin` as a fallback — that path needs root and
  reintroduces exactly the surface this feature avoids.
- Self-check the script's own hash (bootstrapping circularity, same as the
  host plan).
- Add config-management flags (`--force`, `--api-url` overrides …) — the
  config file is plain YAML with four documented keys; editing it is the
  interface.

**Done when:** handler tests mirror the rollout ones: content types,
`no-store` on all three routes, each gate condition individually produces
its 503 `missing` entry, 404 for unknown platform, rendered script
contains base URL/issuer/client ID/hashes and — only with an
operator-controlled pin present — the pin value; a `dial`-source pin
renders **no** pin into the script and the manifest carries `pin: ""` +
`pin_source: "dial"`; a test runs `sh -n` over the rendered script; a
rendering test proves `--pin` data with an empty pin cannot render a
config line.

---

## Phase C — CLI Login Overrides

### C1 — `gssh login --api-url` / `--pin-sha256`

**Files:** `internal/cli/cli.go` (`runLoginCmd`, usage text), tests.

**Steps:**

1. Add `--api-url` and `--pin-sha256` to the `gssh login` flag set —
   exactly the flags `gssh ci-login` already has
   (`internal/cli/cilogin.go`); reuse its validation. After `LoadConfig`,
   the flags override `cfg.APIURL` / `cfg.PinSHA256` for this run.
2. `--pin-sha256` is validated with `pintls.DecodePin` **before any
   network call** (fail fast on a mangled copy-paste).
3. The overrides are **ephemeral** — the config file is never touched.
   Purpose (and the reason this phase exists): DNS-fallback login via IP.
   `pintls.Transport` verifies solely against the pin (chain **and
   hostname** verification are replaced, see `pintls.go`) — so
   `--api-url https://203.0.113.7 --pin-sha256 <pin>` is fully verified
   TLS, no trust downgrade involved.
4. Usage text: document both flags and the pairing rule (an IP `api_url`
   without a pin will simply fail TLS verification against WebPKI — the
   error message should hint at `--pin-sha256`).

**Interplay worth stating in the docs (E1):** a via-IP login puts a
certificate into the ssh-agent; `gssh ssh` then needs no API contact until
that certificate expires — the IP login is a **bridge across a DNS
outage**, not a persistent switch. The next auto-login (`gssh ssh` with an
expired certificate) uses the config values again. Persistently IP-based
setups edit `config.yaml` (`api_url` + `pin_sha256`) deliberately.

**Do not:**
- Write the overrides back to the config file (silent config mutation from
  a one-off flag; iron rule 2 applies to the CLI too).
- Add any `--insecure`/skip-verify flag — the client has no unverified
  TLS code path, and this feature does not introduce one. The pin **is**
  the verified path for IP connections.

**Done when:** tests show: overrides reach the sign request (api_url and
pin actually used), invalid pin aborts before any network I/O, config file
byte-identical after a run with overrides; ci-login behavior unchanged.

---

## Phase D — Frontend

**Files:** `web/src/app/features/client-setup.ts` (new),
`web/src/app/features/hosts.ts`,
`web/src/app/features/host-connect-dialog.ts` (new),
`web/src/app/app.routes.ts`, `web/src/app/app.html` (nav),
`web/src/app/core/mock/…` (mock handlers), `api/openapi.yaml` +
`make web-api` (generated client).

### D1 — "Client setup" page

New standalone page (pattern: existing `features/*.ts`), nav entry after
Hosts. Content, top to bottom:

1. **The three steps**, with the copy-paste one-liner
   `curl -fsSL <base>/client.sh | sh` (base URL from the manifest request
   URL/origin), then `gssh login`, `gssh ssh <host>` — the page mirrors
   what the script prints.
2. **Two-step alternative** (no forced pipe-to-shell, same courtesy as the
   host dialog): download `client.sh`, inspect, run.
3. **Direct downloads:** one row per manifest entry (OS, arch,
   human-readable size, SHA-256 with copy button, download link to
   `/v1/clients/{os}/{arch}`) — covers macOS users and anyone who prefers a
   manual install; next to it the minimal manual config.yaml
   (values rendered from `/v1/ui/config` + origin).
4. **Gate handling** (pattern: Add Host button, D1 of the host plan): if
   `ready: false`, show the `missing` entries in human-readable form
   instead of the instructions — never hide the page silently.

### D2 — OpenAPI + mock

Extend `api/openapi.yaml` with `/v1/clients`, `/v1/clients/{os}/{arch}`,
`/client.sh`; regenerate (`make web-api`). Extend the mock layer
(`core/mock`) with a static manifest so the default `ng serve` design mode
renders the page.

**Done when:** `npm test` and `ng build` pass; mock mode shows the page
with three platforms; against a dev server without embedded binaries the
page shows the "binaries" missing state (dev degradation visible, not
broken).

---

### D3 — Connect dialog on the Hosts page

**Files:** `web/src/app/features/hosts.ts`,
`web/src/app/features/host-connect-dialog.ts` (new).

**Steps:**

1. New last column `actions` in the hosts table: a per-row **Connect**
   icon button. Host-specific action ⇒ row level, not the page header (the
   header holds only global actions: Refresh, Add Host). Disabled for
   hosts that are not enrolled — nothing to connect to yet — with a
   tooltip saying so.
2. Dialog (pattern: `host-add-dialog.ts`), three sections:
   - **"One-time setup"** — the `client.sh` one-liner plus a link to the
     Client setup page, collapsed/de-emphasized: a user with an installed
     client goes straight to the next section (requirement: install and
     connect are separate steps, not one blob).
   - **"Connect"** — copy line `gssh ssh <name>`.
   - **"DNS fallback (login via IP)"** — expandable, command rendered
     **only when the manifest `pin` is non-empty**: an IP input field and
     the live-rendered copy line
     `gssh login --api-url https://<input> --pin-sha256 <pin>`, followed
     by `gssh ssh <name>`. Short hint text: bridges the CLI→API leg only
     (browser→IdP and host name resolution keep their own DNS
     dependency); the certificate then carries until expiry, so `gssh
     ssh` needs no further API contact. Without a pin the section shows
     **why** it is unavailable instead of hiding (same
     visible-degradation principle as the Add Host button), using
     `pin_source` for a precise message: `dial` ⇒ "the pin is
     auto-derived and rotates with the certificate — the DNS fallback
     requires an operator-supplied pin (`GSSH_PUBLIC_PIN` or
     `GSSH_PUBLIC_PIN_CERT_FILE`)"; no source at all ⇒ "no pin source
     configured".
3. The dialog makes no access claims: whether the user may actually enter
   the host is decided by the grants at sign time — the UI does not
   pretend to pre-check it.

**Do not:**
- Render any IP command without a pin (fail-closed — see the security
  model; an unpinned IP command fails TLS and invites
  verification-disabling workarounds we refuse to enable).
- Derive or guess the IP server-side or from `window.location` — the
  operator/user enters it. A guessed value would be exactly the silent
  wrong URL that iron rule 3 exists to prevent.
- Build a browser-based terminal — different feature, entirely different
  security surface, its own ticket if ever.

**Done when:** component tests: button disabled for non-enrolled hosts;
the dialog renders all three sections with correct commands for a host
name; the IP input live-updates the login line; a manifest without a pin
⇒ the fallback section shows the explanation and **no** command, with
the `dial`-specific text when `pin_source` is `"dial"`; mock mode covers
all three states (operator pin, dial source, no source).

---

## Phase E — Docs & E2E

### E1 — Docs

- **README:** the client section of the TL;DR switches to the three-step
  flow; the full-reference section gains the three routes; the env-var
  table notes that `GSSH_AGENT_DOWNLOAD_RPM` covers both download routes;
  a short security paragraph (model below) linking to
  [docs/host-rollout.md](../host-rollout.md) for the shared
  `curl | sh` discussion; the login-via-IP bridge semantics (C1 —
  ephemeral, certificate carries until expiry, persistent setups edit
  `config.yaml`); a note that the IP fallback needs an operator-supplied
  pin (`GSSH_PUBLIC_PIN`/`GSSH_PUBLIC_PIN_CERT_FILE`) and that a file pin
  is only as stable as the deployment's key-rotation policy (a renewal
  that rotates the private key changes the SPKI and thus the pin).
- **DEVELOPER.md:** `internal/bindist`/`clientdist` in the package table;
  dev degradation (empty embed ⇒ manifest `missing: ["binaries"]`); local
  embed via `make cross` + copy.
- **docs/web-ui.md:** the new page.

### E2 — E2E smoke test

**Files:** new integration test (build tag `integration`,
testcontainers-go; pattern: the host-install E2E, Phase E4 there).

Flow: API server with `clientdist.NewFromFS(os.DirFS(dir))` over a real
linux-built `gssh` (built by the test via `go build`, like the agent E2E);
in an alpine container (curl present since the host E2E): fetch
`/client.sh`, run it as a **non-root** user, assert: exit 0; `gssh` binary
installed and `gssh version` prints the expected version; `config.yaml`
exists with the expected `api_url`/`issuer`/`client_id` and mode 0600;
`gssh status` exits 1 (no certificate — correct) while printing the
configured API URL; a second run keeps the existing config (iron rule 2)
and still replaces the binary; run as root ⇒ abort before any download.

**Done when:** the test passes locally and runs in CI next to the existing
integration tests.

---

## Security Model (Summary)

Shared ground with the host install is documented there
([ONE_CMD_INSTALL.md](ONE_CMD_INSTALL.md) security section,
[docs/host-rollout.md](../host-rollout.md)); differences and decisions:

- **Same `curl | sh` residual risk, strictly smaller blast radius.** The
  script and the hashes come from the same origin — the hash check guards
  the download against corruption, not against a compromised server (same
  accepted residual risk as the host path). But: **no sudo, no token, no
  enrollment** — the script writes only to the invoking user's home and
  confers zero access; authorization happens exclusively at `gssh login`
  (OIDC + server-side grants).
- **HTTPS is the trust anchor, WebPKI by default.** The gate refuses to
  serve over a non-https public URL (reused `isHTTPSURL`, same rationale
  as the host gate).
- **No pin in the generated config by default.** The client talks to the
  public API over WebPKI — the same trust model as the browser SSO flow
  the login depends on anyway (the browser does not pin either). A pinned
  default would hard-break every installed client at the next server key
  rotation (Let's Encrypt rotates keys on renewal) — a fleet-wide
  operational footgun bought with marginal gain. `--pin` remains as an
  explicit opt-in for private-CA or hardened setups where the operator
  controls rotation (static/file pin sources). Documented tradeoff, not a
  silent choice.
- **Login via IP is pin-gated, never unpinned — and only with an
  operator-controlled pin.** The connect dialog's DNS fallback renders
  `gssh login --api-url https://<ip> --pin-sha256 <pin>` only when the
  manifest carries a pin; without one, the UI explains the gap instead of
  offering a command that would fail TLS and invite
  verification-disabling workarounds. The server populates that pin only
  from the `static`/`file` sources — an auto-derived `dial` pin rotates
  with the certificate and would break mid-outage or on renewal, so it is
  never offered to clients (enforced server-side in one place, B2; the
  host-rollout path is untouched — there the agent consumes the pin
  immediately at enrollment, not as a stored anchor). The pin replaces
  chain **and hostname** verification (`pintls.Transport`) — a via-IP
  connection is fully verified, there is no insecure code path and none
  is added.
  Honest limits: this bridges the CLI→API leg only; the browser→IdP leg
  and host name resolution keep their own DNS dependency. Residual risk
  (documented): a user who loads the web UI itself via IP, past a browser
  certificate warning, could be served an attacker's pin — the pin's
  trust anchor is the DNS-validated UI origin.
- **Config file mode 0600, never overwritten.** No secrets in it today,
  but pinning and future keys belong to the user alone; overwriting could
  silently redirect an existing client to another server.
- **Public, rate-limited binary endpoints.** Public artifact (identical
  rationale to the agent download); shared per-IP download limiter.
- **Version disclosure in the manifest accepted** (same as the agent
  manifest).
- **`no-store` on script, manifest, binary** — stale hash/binary pairs
  after a server upgrade would produce phantom mismatch aborts.

---

## Roadmap (checklist)

### Phase A — Client Binaries in the Container
- [x] A1: extract `internal/bindist` (prefix-parameterized `Source`),
      `agentdist` delegates with unchanged API, new `internal/clientdist`
      (embed `all:bin`, prefix `gssh-`, `.gitkeep`/`.gitignore`) + tests
- [x] A2: Dockerfile — client loop (`linux/amd64 linux/arm64 darwin/arm64`)
      in the `agentbuild` stage, separate `/out-client/`, `COPY` into
      `internal/clientdist/bin/`

### Phase B — Public Endpoints
- [ ] B1: client gate (binaries, public_url(+https), oidc_issuer,
      oidc_client_id; pin deliberately not a condition) + 503 body
- [ ] B2: `GET /v1/clients` (manifest: version/ready/missing/pin/
      pin_source/clients, regular limiter, `no-store`; pin populated only
      from `static`/`file` sources — never `dial`)
- [ ] B3: `GET /v1/clients/{os}/{arch}` (stream, 404/503, `no-store`,
      shared `DownloadRateLimit`)
- [ ] B4: `GET /client.sh` — template (base URL, issuer, client ID,
      per-platform hashes, optional pin — operator sources only) + script
      per specification
      (root refusal, os/arch detect incl. darwin, sha256sum/shasum, atomic
      same-dir swap into `~/.local/bin`, config only-if-absent 0600, PATH
      hint, next-steps output, flags `--os/--arch/--bin-dir/--pin`) +
      handler/`sh -n` tests

### Phase C — CLI Login Overrides
- [ ] C1: `gssh login --api-url` + `--pin-sha256` (ephemeral overrides,
      ci-login flag pattern, `DecodePin` fail-fast before network I/O,
      config file untouched) + tests

### Phase D — Frontend
- [ ] D1: "Client setup" page (three steps + one-liner, two-step
      alternative, direct downloads with SHA-256, manual config snippet,
      missing-state display) + route + nav
- [ ] D2: `api/openapi.yaml` + `make web-api`, mock-mode manifest
- [ ] D3: Hosts `actions` column + connect dialog (install step separated
      from connect line, enrolled-only, pinned login-via-IP fallback with
      live-rendered command, fail-closed without pin incl.
      `pin_source`-specific explanation, mock covers operator-pin/dial/
      no-source states)

### Phase E — Docs & E2E
- [ ] E1: README (TL;DR flow, routes, shared download limiter note,
      security paragraph, IP-bridge semantics), DEVELOPER.md,
      docs/web-ui.md
- [ ] E2: E2E smoke test (alpine, non-root, `client.sh` → installed binary
      + valid config → `gssh version`/`gssh status`; re-run keeps config;
      root aborts)

---

## Decision Log

| # | Topic | Decision |
|---|---|---|
| 1 | Bundling | **Embed** in the server image, same Docker build stage as the agents — hard version lockstep; ~+24 MB image accepted (three static ~8 MB binaries) |
| 2 | Pin default | **No `pin_sha256` in the generated config**; `--pin` opt-in. WebPKI is the trust anchor of the SSO flow anyway; a pinned default breaks the whole fleet on server key rotation. Hardened/private-CA setups opt in |
| 3 | Privileges | Script refuses root; installs to `~/.local/bin` + `~/.config`. `/usr/local/bin` fallback rejected (reintroduces sudo) |
| 4 | Access control on downloads | Public endpoints; binary possession grants nothing — `gssh login` (OIDC + grants) is the control. Same rationale as the agent download |
| 5 | Gate | Own small gate (binaries, https public URL, issuer, client ID); host rollout gate deliberately not reused (would drag in agent URL + mandatory pin). Manifest always 200 with `missing` diagnostics; no feature flag |
| 6 | Rate limiting | Shared `DownloadRateLimit` instance and env var (`GSSH_AGENT_DOWNLOAD_RPM`); rename rejected (breaks deployments), third instance rejected (no distinct threat) |
| 7 | Existing config | Never overwritten, no `--force`; message + binary still updated. Editing the YAML is the interface |
| 8 | Code reuse | Extract `internal/bindist` with prefix parameter; `agentdist` path/API unchanged (Dockerfile, nfpm, imports stable); duplication and agentdist rename rejected |
| 9 | macOS | Served from the same script (`uname -s`, `shasum -a 256` fallback) and as direct downloads on the page; no separate installer |
| 10 | Steps floor | Three steps is the floor: `login` needs an interactive browser; auto-exec from the piped script rejected (stdin is the pipe) |
| 11 | Connect entry point | Row-level action on the Hosts page (host-specific ⇒ at the host; the page header holds only global actions); dialog separates one-time install from the connect step; enrolled hosts only; no access pre-check faked in the UI (grants decide at sign time) |
| 12 | Login via IP | Pin-mandatory pair `--api-url https://<ip>` + `--pin-sha256 <pin>` (the pin replaces chain+hostname verification, `pintls.Transport`); no pin ⇒ no IP command rendered (fail-closed), no insecure-skip path anywhere; the IP is always user-entered, never derived; declared limits: bridges the CLI→API leg only — IdP (browser) and host name resolution keep their DNS dependency. IP fallback and `--pin` require an **operator-controlled pin source** (`static`/`file`); auto-derived `dial` pins are never offered to clients — they rotate with the certificate and would break mid-outage or on renewal. Enforced server-side in B2 (single point); `pin_source` exposed in the manifest for diagnosis. Host-rollout path untouched: `dial` stays legitimate there (pin consumed once at enrollment) |
| 13 | IP login is a bridge | Ephemeral flag overrides on `gssh login` (ci-login pattern), config file untouched; the signed certificate carries until expiry, so no API contact is needed meanwhile; persistently IP-based setups edit `config.yaml` (`api_url` + `pin_sha256`) deliberately |

## Future Notes (deliberately out of scope)

- **deb/rpm for the client** — the nfpm setup exists for the agent; add a
  client package if package-manager-based fleets ask for it. The script
  path stays the primary UX.
- **Homebrew tap / winget, Windows binaries** — `CROSS_PLATFORMS` and the
  Dockerfile loop are the only extension points; the manifest, script
  error messages, and UI page follow automatically (windows needs script
  work: no POSIX sh).
- **Client self-update** (`gssh update` against `/v1/clients`) — the
  manifest already carries version + hashes; re-running `client.sh` covers
  the need until then.
- **Config drift repair** (server URL moved, pin rotated with `--pin`) —
  currently manual YAML edit or config delete + re-run; a
  `gssh configure --from <url>` could reuse the manifest later.
