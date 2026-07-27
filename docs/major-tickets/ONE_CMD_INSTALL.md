# One-Command Host Install — Implementation Plan

> **Superseded detail (server/client OIDC split):** `GSSH_UI_BASE_URL` and
> the `GSSH_PUBLIC_URL` fallback chain described below were merged into a
> single `GSSH_PUBLIC_URL` (chart: `config.publicURL`; `hostRollout.publicUrl`
> was removed). The historical text below is unchanged.

> **As of 2026-07-25.** The review feedback from 2026-07-25 (K1–K17) has been
> **fully incorporated** into this version — each point is resolved at the
> location where it needs to be addressed. The former separate review
> section has thus been folded in; the earlier version remains in the git
> history. The decision log at the end summarizes all review decisions in a
> traceable way.
>
> This plan is written so it can be implemented without prior knowledge of
> the review discussion. Every work package states **Files**, **Steps**,
> **Do not** (deliberately discarded approaches — please really don't do
> these; the reasons are given alongside), and **Done when** (verification
> criteria).

Goal: an **"Add Host"** button on the **Hosts** web page. Clicking it shows a
one-time enrollment token plus **a single command line** that you paste onto
a Linux host, which **fully installs** the agent — binary, systemd unit,
enrollment, service start. The agent binaries live **inside the server
container** (version-matched to the running server); the download happens
purely internally — no detour via GitHub releases, air-gap capable.

---

## Terminology (for newcomers)

| Term | Meaning |
|---|---|
| **Public listener** | The server's regular HTTP listener (UI, admin API, `/v1/enroll`, `/v1/sign/*`). Set up in `internal/api/server.go` → `New(deps)`. TLS terminates **upstream**, at the reverse proxy/ingress, not in the server. |
| **Agent listener** | Separate mTLS listener for enrolled agents (`/v1/agent/…`, singular!). Set up via `NewAgent`. **Not touched in this plan.** |
| **Enrollment token** | One-time bearer secret `gssh-et-…` (32 random bytes, base64url). Only the SHA-256 hash is stored in the DB (`store.EnrollmentToken`); the plaintext exists exactly once, in the response. |
| **SPKI pin** | Base64(SHA-256(SubjectPublicKeyInfo)) of the TLS certificate the host sees during enrollment. The agent (`gssh-agentd enroll --pin`) then refuses any other peer. Tooling: `internal/pintls`. |
| **fail-closed** | If a precondition is missing or an error occurs, the system **aborts or shuts the path down** — it never silently continues with an insecure fallback. Guiding principle of this plan. |
| **Hairpin** | The server calls its **own external** URL (looping back to itself through the reverse proxy). Fails in some environments (cloud LB without hairpin NAT, network policies, split-horizon DNS) — hence the alternative pin sources. |
| **Split-horizon DNS** | The same DNS name resolves differently internally than externally. Consequence: the server may see a **different** certificate during self-dial than hosts see from outside. |

---

## Feasibility: YES

All building blocks already exist; what's missing is wiring, not a new
concept (verified against the code):

| Building block | Status today | What's missing |
|---|---|---|
| Web bundling into the server binary | `web/embed.go` → `//go:embed all:dist` | a second embed for agent binaries |
| Cross-build agent (linux/amd64+arm64) | `make cross` builds `bin/gssh-agentd-linux-<arch>` with `LDFLAGS` | as its own build stage in the Dockerfile |
| Token creation | `gssh-server enroll-token` (`cmd/gssh-server/main.go: runEnrollToken`) + `store.CreateEnrollmentToken` | an admin API endpoint instead of CLI-only |
| Host enrollment | `gssh-agentd enroll --server --agent-url --token [--pin] [--session-audit]` (flags in `internal/agentd/cli.go`, idempotent) | new flag `--require-pin` |
| Manual install script | `deploy/packaging/install.sh` (GitHub release variant) | a server-templated variant, downloaded from the server |
| Separate listeners | Public mux (`New`) and mTLS agent mux (`NewAgent`) already separated | new public routes under `/v1/agents/` (plural — no conflict with `/v1/agent/`) |
| Rate limiting | `internal/api/ratelimit.go` (`RateLimiter`, token bucket per client IP, `TrustProxyHeader`) | a second instance for downloads |
| Pin tooling | `internal/pintls` (`DecodePin`, `Transport`, `Verifier`) | helper `FromCertificate` |
| External URL | `GSSH_UI_BASE_URL` | additionally `GSSH_PUBLIC_URL`, `GSSH_AGENT_PUBLIC_URL` |

**Version parity comes for free:** agent binaries are produced in the
**same Docker build** as the server (same `-ldflags`, same commit) and live
in the server image. The server serves exactly the binary that matches it.

**All architectures, always, independent of the server's architecture.** The
target host can have a different architecture than the server (amd64 server,
arm64 host, or vice versa). That's why the agent binaries are **cross-built
for all supported target architectures and embedded in full**. Cross-builds
are static (`CGO_ENABLED=0`), so they work from any build environment.
Target architectures (the agent is Linux-only, systemd-based): currently
**linux/amd64, linux/arm64**; extendable by adding an entry to the build
loop.

---

## Target Flow (UX)

1. Admin opens **Hosts** → clicks the **"Add Host"** button.
2. Dialog: optional hostname binding, tags (`env=prod,role=web`), TTL
   (default 1 h), session-audit checkbox (default off).
3. Click **"Generate Token"** → the server mints a one-time token; the
   response contains the token plaintext (one-time only!), `expires_at`, and
   the finished `install_command`.
4. The dialog shows the **copy line** plus an **architecture selector**
   (dropdown):
   - Default **"auto (script detects)"** — one line for all architectures;
     the script runs `uname -m`:
     ```
     curl -fsSL https://gssh.example.com/install.sh | sudo sh -s -- --token gssh-et-XXXXXXXX
     ```
   - Explicit choice **amd64 / arm64** — pins the architecture (needed for
     cross-provisioning, where `uname` on the executing machine doesn't
     report the target architecture):
     ```
     curl -fsSL https://gssh.example.com/install.sh | sudo sh -s -- --token gssh-et-XXXXXXXX --arch arm64
     ```
   The architecture list in the dropdown comes from the manifest
   (`GET /v1/agents`) — only architectures that are actually embedded appear.
5. The operator pastes the line onto the Linux host. **One command**, done:
   binary installed, unit active, host enrolled, sshd configured.

The server-served `install.sh` is templated at runtime and already contains
the server URL, agent URL, version, per-architecture SHA-256, systemd unit
content, and the (mandatory) SPKI pin. The only variables are the token and
optional flags.

---

## Iron Rules (what not to do)

These rules apply to **all** work packages. They distill the review
decisions — each one is backed by a concrete failure scenario. When in
doubt: follow the rule, don't deviate "pragmatically".

1. **Never `InsecureSkipVerify`** — nowhere, not even "just to read the
   certificate". An unverified pin dial would template an MITM attacker's
   pin into every `install.sh`, defeating the entire pinning mechanism
   outright. This feature has **no** `InsecureSkipVerify` code path,
   anywhere.
2. **No URL derivation.** `GSSH_AGENT_PUBLIC_URL` is never "guessed" from
   other values (host + internal port ≠ external port behind an LB/ingress).
   If the env var is missing ⇒ the rollout gate closes (503). Otherwise a
   wrong agent URL would silently end up in the `config.yaml` of N hosts and
   only blow up at the first certificate renewal — fixing it would mean
   touching N hosts.
3. **No unpinned code path in the rollout.** If no pin can be determined ⇒
   endpoints return 503, the UI button is grayed out, and the script aborts
   on an empty pin. Never silently enroll without a pin.
4. **Never log or store the token plaintext.** Only the SHA-256 hash is
   stored in the DB; the audit event contains tags/TTL/actor, **not** the
   token.
5. **`install.sh` is POSIX `sh`.** No bash, no `set -o pipefail` (unreliable
   in dash/busybox sh) — pipe failures are checked explicitly via exit
   codes. The entire script lives in `main() { … }`, with `main "$@"` as the
   last line (protection against a truncated transfer that would otherwise
   execute half a script).
6. **Swap the binary atomically, without stopping.** Download into a temp
   file **in the same directory** (`/usr/bin/.gssh-agentd.XXXXXX`, same
   partition — not `/tmp`!), verify the hash, `chmod`, then `mv -f`.
   `rename(2)` replaces even a running binary without "text file busy". No
   `systemctl stop` before copying. Also: `systemctl enable --now` does not
   restart a unit that is **already active** — for an active unit, use
   `systemctl restart` instead.
7. **One single source for the systemd unit.** The file moves via `git mv`
   to `internal/agentdist/gssh-agentd.service` and is embedded from there
   (`go:embed` cannot reach outside its package directory — hence a move
   rather than a reference). `nfpm.yaml` points at the new path. **No**
   second here-doc duplicate anywhere in the repo — that would inevitably
   drift.
8. **`/v1/agents/…` (plural) only on the public listener.** `/v1/agent/…`
   (singular) is the mTLS listener — do not touch it, do not hang anything
   off it.
9. **One single source of truth for the client IP.** The new download
   limiter inherits `TrustProxyHeader` from the same env var as the regular
   limiter (`GSSH_RATE_TRUST_PROXY`). Do not invent a second XFF
   configuration.
   (Note: the env var really is named `GSSH_RATE_TRUST_PROXY` — not
   `…_TRUST_XFF`, as an earlier version of this plan stated.)
10. **`Cache-Control: no-store` on all three endpoints** — `install.sh`, the
    manifest, **and** the binary download. A cache that serves the old
    binary alongside a new `install.sh` after a server upgrade produces
    phantom hash mismatches. One rule instead of three; caching the binary
    would provide no benefit anyway (one download per host lifetime).
11. **Never commit agent binaries.** `internal/agentdist/bin/` stays empty
    in the repo (`.gitkeep`), with a matching `.gitignore` entry. The
    directory is only populated during the Docker build (and locally for
    tests).
12. **Leave existing install paths unchanged.** deb/rpm and the manual route
    keep their existing behavior (pin remains optional there, no
    `--require-pin` default). This feature is an **additional** path.

---

## New Environment Variables (Overview)

All new env vars at a glance; details are in the work packages.

| Env var | Purpose | Default |
|---|---|---|
| `GSSH_PUBLIC_URL` | External public URL (basis for `install_command` and the target of the pin self-dial) | empty → falls back to `GSSH_UI_BASE_URL` |
| `GSSH_PUBLIC_PIN` | Pin source 1: static base64 SPKI pin (operator-managed) | empty |
| `GSSH_PUBLIC_PIN_CERT_FILE` | Pin source 2: path to a PEM certificate (first block = leaf) | empty |
| `GSSH_PUBLIC_PIN_REFRESH` | Refresh interval for the pin self-dial (Go duration) | `5m` |
| `GSSH_AGENT_PUBLIC_URL` | External mTLS agent URL for `enroll --agent-url` | empty ⇒ **gate closed** |
| `GSSH_AGENT_DOWNLOAD_RPM` | Download limit per client IP per minute (`0` = off) | `10` (burst 5) |

Existing env vars relevant here: `GSSH_UI_BASE_URL` (external UI base),
`GSSH_RATE_TRUST_PROXY` (client IP from `X-Forwarded-For` — applies to
**both** limiters).

---

## Implementation Order

**A → P → B → C → D → E.** A (binaries) and P (pin/gate) are independent of
each other and can run in parallel. B (endpoints) needs A **and** P.
C (mint API) needs P (gate). D (frontend) needs B + C. E (docs, Helm, E2E)
comes last.

---

## Phase A — Agent Binaries in the Container

### A1 — Package `internal/agentdist`

**Files:** `internal/agentdist/agentdist.go` (new),
`internal/agentdist/bin/.gitkeep` (new), `.gitignore`.

**Steps:**

1. Create the directory `internal/agentdist/bin/` with an empty `.gitkeep`.
   Add to `.gitignore`:
   ```
   internal/agentdist/bin/*
   !internal/agentdist/bin/.gitkeep
   ```
2. `agentdist.go` with the embed and an access API:
   ```go
   //go:embed all:bin
   var binFS embed.FS
   ```
   The `all:` prefix is mandatory: without binaries, `bin/` contains only
   the hidden `.gitkeep`, and a plain `//go:embed bin` fails with "no
   embeddable files". `.gitkeep` is filtered out in the API.
3. Public API (consumed by the `api` package in Phase B as an interface —
   **do not** access `embed.FS` directly, or the handlers won't be
   testable):
   ```go
   type Info struct {
       OS     string // "linux"
       Arch   string // "amd64" | "arm64"
       Size   int64
       SHA256 string // hex, sha256sum-compatible
   }

   type Source struct { /* fs.FS + info computed once */ }

   func New() *Source                       // via the embed
   func NewFromFS(fsys fs.FS) *Source       // for tests/E2E (fstest.MapFS, os.DirFS)
   func (s *Source) List() []Info           // stably sorted; empty in dev builds
   func (s *Source) Open(osName, arch string) (io.ReadCloser, Info, error)
   ```
   Filename convention in the embed: `bin/gssh-agentd-linux-<arch>` —
   exactly the names `make cross` produces. `List()` parses the names and
   ignores everything else (in particular `.gitkeep`). SHA-256 (hex!) and
   size are computed **once** on first access (`sync.Once`) and cached.
4. The systemd unit moves (single source, rule 7):
   ```
   git mv deploy/packaging/gssh-agentd.service internal/agentdist/gssh-agentd.service
   ```
   In `agentdist.go`: `//go:embed gssh-agentd.service` → `var UnitFile string`.
   In `deploy/packaging/nfpm.yaml`, change the `src:` path of the unit entry
   to `internal/agentdist/gssh-agentd.service` (the deb/rpm target
   `/lib/systemd/system/…` stays unchanged).

**Do not:**
- Place binaries via `COPY` at an image path and read them via `os.DirFS`
  (two artifacts, version lockstep no longer guaranteed). Decision:
  **embed**, accepting the tradeoff of a ~30–40 MB larger server binary.
- Copy the unit file via `go:generate` (a committed duplicate would drift)
  or offer it as its own download endpoint (a round trip with no benefit).

**Done when:** unit tests (with `NewFromFS` + `fstest.MapFS`) demonstrate:
`List()` returns the correct arch/size/hex hash for each fake binary;
`Open()` streams the content; an unknown arch ⇒ error; an empty FS ⇒
`List()` empty. `make build` succeeds without binaries present (dev build
degrades cleanly). The deb/rpm build (`make packages`) works with the new
unit path.

### A2 — Dockerfile: Cross-Build Stage

**Files:** `Dockerfile`.

**Steps:**

1. New stage **before** the server build stage, mandatorily with
   `--platform=$BUILDPLATFORM`:
   ```dockerfile
   FROM --platform=$BUILDPLATFORM golang:1.26 AS agentbuild
   WORKDIR /src
   COPY go.* ./
   RUN go mod download
   COPY . .
   ARG VERSION=dev
   ARG COMMIT=none
   ARG DATE=unknown
   RUN for arch in amd64 arm64; do \
         CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath \
           -ldflags "-s -w \
             -X github.com/guided-traffic/guided-ssh/internal/version.version=${VERSION} \
             -X github.com/guided-traffic/guided-ssh/internal/version.commit=${COMMIT} \
             -X github.com/guided-traffic/guided-ssh/internal/version.date=${DATE}" \
           -o /out/gssh-agentd-linux-$arch ./cmd/gssh-agentd || exit 1; \
       done
   ```
   Why `--platform=$BUILDPLATFORM`: in a buildx multi-arch build, the stage
   would otherwise run under QEMU emulation for each target platform — Go
   compilation gets several times slower. This way the compiler runs
   natively and cross-compiles via GOOS/GOARCH; the stage is
   platform-invariant, BuildKit deduplicates it, and the agents are
   effectively built **once** per multi-arch build. Every server platform
   variant embeds the **complete** set of agent binaries (an amd64 server
   also contains the arm64 agent binary and vice versa).
2. In the existing `build` stage, before the server's `go build`:
   ```dockerfile
   COPY --from=agentbuild /out/ ./internal/agentdist/bin/
   ```
   The agent stage's `-ldflags` are **identical** to the server stage's
   (passing through the same `ARG`s) — that's what establishes the version
   lockstep.

**Do not:**
- Build agent binaries as a CI artifact and `COPY` them into the image —
  this breaks the single-build lockstep (server and agent could come from
  different commits).
- Also switch the existing server build stage to `$BUILDPLATFORM` right
  now — worthwhile, but a **separate topic**, not part of this plan (see
  Future Notes).

**Done when:** `docker build` produces an image in which `GET /v1/agents`
(after Phase B) lists both architectures with correct hashes. Until then, an
intermediate check suffices: both `go build` runs appear in the build log,
and a `docker run --entrypoint=` look confirms the server binary grew by
~30–40 MB.

---

## Phase P — Mandatory Pinning & Rollout Gate

The only part that is invented from scratch rather than wiring up something
existing — implement it accordingly precisely. Principle: the SPKI pin is
**mandatory**; no code path ever emits an unpinned install command. If no
pin can be determined, the entire host rollout is **disabled** (fail-closed)
instead of proceeding unpinned.

### P1 — `pintls.FromCertificate`

**Files:** `internal/pintls/pintls.go`, `internal/cli/client_test.go`.

**Steps:**

1. Add a helper (the package has `DecodePin`/`Transport`/`Verifier`, but no
   computation helper):
   ```go
   // FromCertificate returns the base64 SPKI SHA-256 pin of a certificate.
   func FromCertificate(cert *x509.Certificate) string {
       sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
       return base64.StdEncoding.EncodeToString(sum[:])
   }
   ```
2. Migrate the hand-rolled test helper `spkiPin()` in
   `internal/cli/client_test.go:16` to use `pintls.FromCertificate`.

**Do not:** duplicate the computation inline in three places (dial source,
file source, tests) — that's exactly what the helper is for.

**Done when:** a unit test with a known certificate → the expected pin;
`internal/cli` tests continue to pass unchanged.

### P2 — Pin Provider with Three Sources

**Files:** `internal/api/pinprovider.go` (new) + test,
`cmd/gssh-server/main.go` (env parsing, construction).

Three sources with a fixed precedence, **all fail-closed**; the active
source is logged and reported in the manifest. If several are set, the
highest precedence wins, with a warning in the log.

**Source 1 — `GSSH_PUBLIC_PIN` (static, highest precedence).**
The operator supplies the pin themselves; auto-dial and refresh are off,
rotation is in the operator's hands. Last resort for cases where neither the
file nor the dial approach works (e.g. the certificate sits at a CDN).
Validated at startup with `pintls.DecodePin`; an invalid value ⇒ **startup
aborts with a clear error message** (fail-fast, same as
`GSSH_HOST_CERT_VALIDITY`).
Doc snippet for operators (goes into the README/Helm chart in Phase E):
```
openssl s_client -connect gssh.example.com:443 </dev/null 2>/dev/null \
  | openssl x509 -pubkey -noout \
  | openssl pkey -pubin -outform DER \
  | openssl dgst -sha256 -binary | base64
```

**Source 2 — `GSSH_PUBLIC_PIN_CERT_FILE` (file).**
Path to a PEM certificate; the **first** `CERTIFICATE` block is the leaf
(cert-manager's convention for `tls.crt`). The file is read fresh on
**every** serve — **no caching** (parsing costs microseconds; the stale
window thus shrinks to the kubelet's sync of the secret mount, ≤ ~1 min).
Read/parse errors ⇒ no pin ⇒ gate closed, reason logged.
Solves hairpin and split-horizon deployments without manual rotation
effort: in K8s the ingress's TLS secret is mounted as a **volume** — no K8s
API access, no RBAC; kubelet updates the mount on secret rotation. Also
works without K8s (bind-mounting `fullchain.pem`).

**Source 3 — Auto-dial (default).**
The server dials its own external public URL over TLS (`GSSH_PUBLIC_URL`,
falling back to `GSSH_UI_BASE_URL`), reads the leaf certificate
(`ConnectionState().PeerCertificates[0]`), and computes the pin via
`pintls.FromCertificate` — exactly the value a real host sees during
enrollment. **Mandatory:** the dial verifies the certificate chain
fail-closed with a **standard `tls.Config` against the system roots** — no
special handling whatsoever, no `InsecureSkipVerify` code path (rule 1).
Verification failure ⇒ no pin ⇒ gate closed; reason logged and in the
manifest. The `distroless/static` runtime image already contains the CA
bundle — no image rebuild needed. For a corporate/private CA: mount a CA
bundle and set `SSL_CERT_FILE`/`SSL_CERT_DIR` (Go reads both; note:
`SSL_CERT_FILE` **replaces** the default bundle — concatenate them for mixed
setups). Self-signed without a CA ⇒ use source 1 or 2.

**Refresh behavior (dial source only):**
- Background loop, interval `GSSH_PUBLIC_PIN_REFRESH` (Go duration, default
  `5m`; invalid value ⇒ startup aborts).
- **Plus a lazy refresh on serve:** if the cache is older than the interval
  when serving `install.sh` or minting a token, it's refreshed
  synchronously. Reason: Let's Encrypt renewals generate new keys by
  default — without the lazy refresh, a script would routinely carry a
  stale pin during the rotation window every ~60–90 days.
- If a refresh fails, the **last successfully read** pin stays active (with
  a warning log). Only "never read a pin yet" keeps the gate closed.
- A mitigating fact worth knowing: a pin mismatch fails at the agent during
  the TLS handshake **before** the request — the token is **not** consumed
  in that case, so a retry is free (also covered by B3 regardless).

**API sketch:**
```go
type PinStatus struct {
    Pin    string // empty = no pin
    Source string // "static" | "file" | "dial" | ""
    Err    string // last error, for log/manifest
}
func NewPinProvider(cfg PinProviderConfig, logger *slog.Logger) *PinProvider
func (p *PinProvider) Status(ctx context.Context) PinStatus // applies lazy refresh
```
Construction and env parsing in `cmd/gssh-server/main.go`, analogous to the
existing env vars; passed to `api.New` via a new `Deps` field.

**Do not:**
- Multi-pin (`--pin a,b` during rotation) — deferred, YAGNI: the remaining
  window is seconds to ~1 min every ~60–90 days; can be retrofitted later
  as a backward-compatible comma list (future note).
- Cache the file source — deliberately uncached (see above).
- "Let through" an unpinned state on dial failures.

**Done when:** tests demonstrate: precedence (static beats file beats dial,
with a warning on multiple settings); the file source picks up changes
immediately; dialing an `httptest` server with an untrusted CA ⇒ no pin (no
insecure fallback); an invalid static pin ⇒ startup error.

### P3 — Rollout Gate (server, authoritative)

**Files:** `internal/api/server.go` (+ new handler files in Phase B/C).

The gate checks **four** conditions; as long as one is missing, the binary
download, `install.sh`, and token mint respond with **503** and the UI grays
out the button. The manifest (`GET /v1/agents`) remains **reachable (200)**
throughout and lists the missing conditions **individually** — unambiguous
diagnosis instead of guesswork:

| Condition | `missing` entry |
|---|---|
| Agent binaries embedded (`Source.List()` not empty) | `"binaries"` |
| Pin available (`PinStatus.Pin != ""`) | `"pin"` |
| `GSSH_AGENT_PUBLIC_URL` set | `"agent_public_url"` |
| Public base URL known (`GSSH_PUBLIC_URL` or `GSSH_UI_BASE_URL`) | `"public_url"` |

The 503 responses name the missing conditions in the body (same list). No
dedicated server feature flag: **the gate conditions are the switch.**

**Do not:** introduce an additional `GSSH_HOST_ROLLOUT_ENABLED` flag —
duplicated state that can drift from the actual conditions.

**Done when:** handler tests: each individually missing condition produces
a 503 with the correct `missing` entry on download/script/mint; the
manifest stays 200 and lists the same entries.

### P4 — Client: `--require-pin`

**Files:** `internal/agentd/cli.go` (enroll flag set, line 77 ff.),
`internal/agentd/enroll.go` (only if needed), tests.

**Steps:**

1. New flag `--require-pin` (bool) in the `gssh-agentd enroll` flag set,
   plus the env-var equivalent `GSSH_ENROLL_REQUIRE_PIN=1` (setting the env
   var behaves like the flag).
2. Behavior: if require-pin is active and `--pin` is empty/missing ⇒ abort
   with a clear message **before** any network call.
3. The templated `install.sh` sets the flag **always** (Phase B3). The
   manual and deb/rpm paths remain unchanged (default false).

**Honest framing (phrase it the same way in docs and code comments):** this
is **protection against operator error, not MITM protection.** It prevents
an operator from copying the enroll line out of the script, dropping
`--pin`, and silently enrolling unpinned. Anyone who can tamper with the
piped script can remove this flag too — what protects against that is the
HTTPS fetch and the pin sources (P2), not this flag. Phrasing such as
"client enforcement" or "enforces pinning" is incorrect and will not be
used.

**Done when:** test: `enroll --require-pin` without `--pin` aborts (no
request sent); with `--pin` it behaves as before; the env-var variant the
same.

---

## Phase B — Public Endpoints

All new routes live in the public mux (`internal/api/server.go`, function
`New`), registered in the Go 1.22 pattern (`mux.HandleFunc("GET /v1/agents",
…)`). `Deps` gains: `Agents` (an interface over `agentdist.Source`), `Pins
*PinProvider`, `AgentPublicURL string`, `PublicBaseURL string`,
`DownloadRateLimit *RateLimiter`.

### B1 — Manifest `GET /v1/agents`

**Behavior:** always 200 (even with the gate closed — diagnostic function,
see P3), `Cache-Control: no-store`, on the **regular** limiter
(`deps.RateLimit.limit(…)`), unauthenticated. Response:

```json
{
  "version": "v2.1.1",
  "rollout_ready": false,
  "missing": ["pin"],
  "pin_source": "",
  "agents": [
    { "os": "linux", "arch": "amd64", "size": 15728640, "sha256": "<hex>" },
    { "os": "linux", "arch": "arm64", "size": 14680064, "sha256": "<hex>" }
  ]
}
```

`version` comes from `internal/version.String()`. **Deliberate decision —
version stays in the public manifest:** the public binary is identifiable
by version anyway (SHA-256 comparison against release checksums,
`gssh-agentd version` after download); removing it would be security
theater against a targeted attacker and would only save mass scanners a
single JSON read. In return: operator diagnostics via `curl`, UI display
without an extra call.

### B2 — Binary Download `GET /v1/agents/{os}/{arch}`

**Behavior:** unauthenticated (the host has no credentials yet; the binary
is a public artifact — **the token gates enrollment, not binary access**).
Gate closed ⇒ 503. Unknown or non-embedded os/arch ⇒ 404 with a plain-text
message. Otherwise, stream with `Content-Type: application/octet-stream`,
`Content-Length`, `Cache-Control: no-store`.

**A separate, tighter rate limiter** (the binary is 15–40 MB — the regular
60/min limiter used by the sign/enroll endpoints is too loose as flood
protection here):

- A second `RateLimiter` instance (`api.NewRateLimiter`), only for this
  route.
- Env var `GSSH_AGENT_DOWNLOAD_RPM`, **default 10/min, burst 5**, `0` = off
  (same semantics as `GSSH_SIGN_RATE_PER_MINUTE`). Rationale for 10: per-IP
  limits only ever stop individual sources anyway; 10/min does that job
  just as well as a tighter value, while not choking bulk rollouts behind a
  corporate NAT (one IP, an Ansible loop over 50 hosts). Worst-case
  bandwidth per IP at 15–20 MB binary size ≈ 25–35 Mbit/s — sufficient as
  flood protection.
- `TrustProxyHeader` **inherits** from `GSSH_RATE_TRUST_PROXY` (rule 9).
  Otherwise, behind the ingress, all requests would look like they come
  from the proxy IP ⇒ 10/min **globally** — a parallel rollout would
  throttle starting at host 6 and be hard to diagnose.
- The instance's failure budget remains unused (public endpoint, no
  401/403) — just leave the defaults as is.

### B3 — Install Script `GET /install.sh`

**Behavior:** unauthenticated, gate closed ⇒ 503, `Cache-Control:
no-store`, `Content-Type: text/x-shellscript`. Templated server-side via
`text/template`; template values: public base URL, `GSSH_AGENT_PUBLIC_URL`,
version, per-architecture SHA-256 (hex), pin (base64), the list of
available architectures, unit content (`agentdist.UnitFile`, embedded as a
quoted here-doc `<<'UNIT_EOF'` — no shell expansion; the file is static,
there is **no** unit templating).

**Script specification** (POSIX `sh`; rules 5 and 6 apply in full):

Structure: `set -eu` (no `pipefail`!), everything inside `main() { … }`,
with `main "$@"` as the last line; `trap 'rm -f "$tmp"' EXIT` for the temp
file.

Flags: `--token <t>` (required), `--arch <amd64|arm64>` (optional, takes
precedence over `uname -m`), `--session-audit` (optional, passed through to
enroll), `--no-systemd` (optional, see below).

Flow:

1. **Preconditions:** `id -u` = 0, otherwise abort ("run with sudo").
   `command -v curl`, otherwise abort ("install curl"). `command -v sshd`,
   otherwise abort ("install openssh-server"). If
   `/etc/ssh/ssh_host_ed25519_key.pub` is missing ⇒ `ssh-keygen -A`.
2. **Pin guard:** if the templated pin is empty ⇒ abort. (Should never
   happen given the server gate — a belt-and-braces backstop, rule 3.)
3. **Determine architecture:** `--arch` if set, otherwise map `uname -m`
   (`x86_64`→amd64, `aarch64`→arm64). Unknown or non-embedded architecture
   ⇒ abort, with a message naming the available architectures (templated
   list).
4. **Fetch the binary (atomically):** create a temp file in the target
   directory (`mktemp /usr/bin/.gssh-agentd.XXXXXX` — same partition,
   **not** `/tmp`, otherwise the later `mv` becomes a non-atomic
   cross-device copy). `curl -fsSL "<base>/v1/agents/linux/$arch" -o
   "$tmp"`. Verify the hash: `echo "<sha256-hex>  $tmp" | sha256sum -c -`
   (two spaces!); mismatch ⇒ abort. `chmod 0755 "$tmp"`, then `mv -f "$tmp"
   /usr/bin/gssh-agentd`. No `systemctl stop` beforehand — `rename(2)`
   replaces even a running daemon's binary without ETXTBSY; the daemon
   keeps its old inode, no downtime.
5. **State directory:** `mkdir -p /var/lib/guided-ssh`, `chmod 700`.
6. **Write the unit:** content from the here-doc into
   `/etc/systemd/system/gssh-agentd.service` (deliberately `/etc/…`, not
   `/lib/…` — `/lib` belongs to the packages; script-based and deb/rpm
   installs must not be mixed anyway, README note in Phase E). Written even
   with `--no-systemd`.
7. **Enroll (with degradation instead of skipping):**
   ```
   gssh-agentd enroll --server <base> --agent-url <agent-url> \
     --token "$token" --pin <pin> --require-pin [--session-audit]
   ```
   Enroll always runs (no "skip if already enrolled"). If it fails **and**
   `/var/lib/guided-ssh/config.yaml` exists ⇒ clear warning "reusing the
   existing enrollment", set a marker, and **continue**. Without
   `config.yaml` ⇒ hard abort. This covers both cases: re-running the same
   line after a partial failure (token already consumed ⇒ enroll fails, the
   old enrollment carries the host) and a genuine re-enroll with a fresh
   token (enroll succeeds, idempotent overwrite) — without an extra flag.
   Deliberate rough edge: an intentional re-enroll that fails for a
   different reason continues on the old enrollment — which is why the
   warning must be impossible to miss (repeated in the final message too);
   the host always ends up in a working state.
8. **systemd (state-dependent):** with `--no-systemd`: skip all `systemctl`
   steps and the health check; at the end, explicitly list what was
   skipped, plus the manual activation command (`systemctl daemon-reload &&
   systemctl enable --now gssh-agentd`). Otherwise: `systemctl
   daemon-reload`; if the unit is already active (`systemctl is-active
   --quiet gssh-agentd`) ⇒ `systemctl restart gssh-agentd` (an upgrade
   loads the new binary — `enable --now` would **not** restart an active
   unit), otherwise ⇒ `systemctl enable --now gssh-agentd`.
9. **Health check (omitted with `--no-systemd`):** wait up to 10 s for
   **both**: `systemctl is-active --quiet gssh-agentd` **and** the
   existence of `/var/lib/guided-ssh/agentd.sock` — the daemon only creates
   the socket once it's ready (the test fixture uses the same signal); with
   `Type=simple` this is stronger than `is-active` alone. Failure ⇒ a
   message pointing to `journalctl -u gssh-agentd -n 20`, exit ≠ 0.
   Documented limitation: a wrong agent URL is not necessarily caught here
   (the agent may only dial it at the next certificate renewal) — that's
   guarded by the gate from P3/rule 2, not by this check.
10. **Success message** — including repeating the "reusing existing
    enrollment" warning if step 7 degraded.

**Why `--no-systemd` exists:** the E2E fixture
(`internal/agentd/testdata/sshd`, alpine) has no systemd — without the flag
the smoke test would not be runnable (Phase E4). Side benefit: useful for
real hosts without systemd as PID 1 (container hosts with their own
supervisor).

**Do not:**
- Use `set -o pipefail` (rule 5), bash syntax, or `mktemp` under `/tmp`.
- Self-check the script's own hash (a bootstrapping circularity — whoever
  tampers with the script also tampers with the check value).
- Add a `--force-reenroll` flag or "skip enroll if config exists" — the
  degradation logic in step 7 covers both cases without a flag.
- Use reusable tokens or a token-reissue endpoint as a re-run solution — a
  security regression, or API surface for an edge case; single-use
  consumption is the load-bearing security control.
- Use a systemctl stub in the fixture (fakes behavior, swallows real
  errors) or a privileged systemd container in CI (flaky/forbidden).

**Done when:** handler tests: correct content types, `no-store` on all
three routes, 503 paths per gate condition, 404 for an unknown
architecture, script content contains the pin/hashes/URLs/unit; a test runs
`sh -n` (syntax check) over the rendered script. The flow logic itself is
covered by Phase E4.

---

## Phase C — Token Minting API

### C1 — Share the Minting Logic (CLI + API Identical)

**Files:** `internal/store/enrollment.go`, `cmd/gssh-server/main.go`.

Extract the token creation from `runEnrollToken`
(`cmd/gssh-server/main.go:296`) into a shared, network-free helper so the
CLI and API are guaranteed to mint identically:

```go
// in internal/store:
// NewEnrollmentToken creates the plaintext ("gssh-et-" + 32 bytes base64url)
// and the corresponding record (hash only). The caller persists it via
// CreateEnrollmentToken and displays the plaintext exactly once.
func NewEnrollmentToken(hostname string, tags map[string]string, ttl time.Duration) (plaintext string, rec *EnrollmentToken, err error)
```

Switch `runEnrollToken` to use the helper — the CLI's behavior (defaults,
output format, TTL default of **24 h**) remains unchanged.

### C2 — `POST /v1/admin/enroll-tokens`

**Files:** `internal/api/admin_ui.go` (route + handler), `internal/store`
(audit constant).

**Steps:**

1. Register the route following the admin pattern:
   `mux.HandleFunc("POST /v1/admin/enroll-tokens", admin.authorized(roleAdmin, admin.handleCreateEnrollToken))`.
2. Request body:
   ```json
   { "hostname": "web-01", "tags": {"env":"prod"}, "ttl_seconds": 3600, "session_audit": false }
   ```
   All fields optional. `ttl_seconds`: default **3600** (deliberately
   shorter than the CLI's 24 h default — UI tokens are created immediately
   before use); validated to 60 ≤ ttl ≤ 86400, otherwise 400.
   `session_audit` is **not** stored on the token (the token schema doesn't
   know it) — it only controls the `--session-audit` flag in the
   `install_command`.
3. Gate check as in P3 (missing condition ⇒ 503 with `missing`).
4. Response (plaintext **once** — never logged or stored anywhere):
   ```json
   {
     "token": "gssh-et-…",
     "expires_at": "2026-07-25T13:37:00Z",
     "install_command": "curl -fsSL https://gssh.example.com/install.sh | sudo sh -s -- --token gssh-et-… [--session-audit]"
   }
   ```
   Base URL of the command: `GSSH_PUBLIC_URL`, falling back to
   `GSSH_UI_BASE_URL` (guaranteed present by the gate). The frontend builds
   the `--arch` variants itself from the manifest (D2).
5. Audit event: constant `EventEnrollTokenCreated =
   "host.enroll_token.created"` in `internal/store` (analogous to
   `EventHostEnrolled`); write via `AppendAuditEvent` with the actor
   (session user), payload `{hostname, tags, ttl_seconds, expires_at}` —
   **without** the token, without the hash (rule 4).

**Done when:** handler tests: non-admin ⇒ 403; gate closed ⇒ 503; success
⇒ token prefix `gssh-et-`, `expires_at` ≈ now+TTL, `install_command`
contains the token and (only when `session_audit: true`) the flag;
tags/hostname end up in the record; the audit event is present and
token-free; the `enroll-token` CLI test continues to pass.

---

## Phase D — Frontend

**Files:** `web/src/app/features/hosts.ts`,
`web/src/app/features/host-add-dialog.ts` (new), `api/openapi.yaml`,
`web/src/app/api/…` (generated client).

### D1 — Button + Gate Display

In the `page-header` of `hosts.ts` (next to "Refresh"), add a
`mat-flat-button` **"Add Host"**. When the page loads, also fetch
`GET /v1/agents`: `rollout_ready: false` ⇒ the button is **disabled**, with
hint text that lists the `missing` entries in human-readable form (e.g. "pin
not yet determined", "GSSH_AGENT_PUBLIC_URL missing", "server build without
agent binaries"). No silently hiding the button — the operator should see
**why** it isn't available.

### D2 — Dialog

New standalone dialog component following the pattern of `grants.ts`
(MatDialog).

**Form view:** hostname (optional, text), tags (text, `env=prod,role=web`),
TTL (select: 15 min / **1 h default** / 4 h / 24 h), session-audit checkbox
(default **off**) with explanatory text:
> Enables host session/sudo auditing: the agent attaches `pam_exec` hooks to
> the PAM stacks of sshd and sudo (`/etc/pam.d/*`) and correlates sessions
> with certificates (sshd `LogLevel VERBOSE`). Reports session start/end and
> sudo actions to the platform. Changes the host's PAM configuration —
> hence opt-in.

Submit → `POST /v1/admin/enroll-tokens`.

**Result view:**
- Token masked + copy button; hint "the token is shown only once, the TTL
  is already running".
- **Architecture dropdown**: "auto (script detects)" + one option per
  architecture from the manifest. Selecting one live-updates the copy line
  (appends `--arch <x>`); a copy button for the line.
- Agent list (arch, human-readable size, SHA-256) from the manifest.
- An expandable **two-step alternative** for anyone who doesn't want to run
  `curl | sh` (no forced pipe-to-shell):
  ```
  curl -fsSLO https://gssh.example.com/install.sh
  less install.sh          # inspect it
  sudo sh install.sh --token gssh-et-…
  ```

### D3 — OpenAPI + Client

Extend `api/openapi.yaml` (the single source of truth for the REST API)
with `/v1/admin/enroll-tokens`, `/v1/agents`, `/v1/agents/{os}/{arch}`, and
`/install.sh`. Regenerate the client as usual (ng-openapi-gen, a
devDependency in `web/package.json`; produces `web/src/app/api/fn/…`). If
the generator invocation is unclear: hand-write the new request functions,
exactly following the pattern of the existing files under
`web/src/app/api/fn/` — do not hand-edit the generated files.

**Done when:** `npm test` passes; a manual smoke test in the dev setup:
button disabled without a pin (start the server without the env vars),
enabled with one; the dialog mints a token, the copy line changes with the
architecture selection; `ng build` succeeds.

---

## Phase E — Docs, Helm, E2E

### E1 — Helm Chart (Deploy-time Validation, Fail-fast)

**Files:** `deploy/helm/guided-ssh/values.yaml`,
`deploy/helm/guided-ssh/templates/…`, chart README.

New values block (each parameter with **at most 2 lines** of to-the-point
comment — no prose paragraphs):

```yaml
hostRollout:
  # One-command host install (UI button "Add Host"). When true, the
  # mandatory env vars are required (helm fails to render otherwise).
  enabled: false
  # External mTLS agent URL for enrolled agents (required when enabled).
  agentPublicUrl: ""
  # External public URL (install_command + pin dial); empty = ui.baseUrl.
  publicUrl: ""
  pin:
    # Pin source: dial (default) | file | static — see the table in the README.
    source: dial
    # source=static: base64 SPKI pin (openssl snippet in the README).
    static: ""
    # source=file: the ingress's TLS secret; the chart mounts ONLY tls.crt.
    certSecretName: ""
    # Refresh interval for the pin dial (Go duration).
    refreshInterval: 5m
  # Binary downloads per client IP per minute (0 = off).
  downloadRpm: 10
```

Template logic:
- `enabled: false` ⇒ **nothing** is rendered and nothing is required (the
  feature is strictly optional).
- `enabled: true` ⇒ `required` checks in the template for `agentPublicUrl`
  and — depending on `pin.source` — for `pin.static` or
  `pin.certSecretName`; `helm install/upgrade/lint` fails to render with a
  plain-text message. Misconfiguration blows up at setup time, not across
  the fleet. (Second layer: the server gate from P3 remains authoritative —
  it covers non-Helm deployments and drift. The Helm toggle **only**
  controls rendering the env vars, not a second server-side state.)
- `pin.source: file` ⇒ mount a volume from `certSecretName`. Rules
  (rationale: kubelet only refreshes secret mounts without a subPath):
  **no `subPath`**; project only `tls.crt` (`items:` selection — `tls.key`
  stays out, the server doesn't need it); the secret must live in the
  server's namespace (wildcard cert in a different namespace: reflector/
  kubed, or its own `Certificate`). Set env var
  `GSSH_PUBLIC_PIN_CERT_FILE` to the mount path.
- Rendered env vars: `GSSH_AGENT_PUBLIC_URL`, `GSSH_PUBLIC_URL`,
  `GSSH_PUBLIC_PIN` | `GSSH_PUBLIC_PIN_CERT_FILE`,
  `GSSH_PUBLIC_PIN_REFRESH`, `GSSH_AGENT_DOWNLOAD_RPM`.

The chart README adds: a mini decision table "which pin source when" (dial
= default, when the server can reach its external URL; file =
hairpin/split-horizon/cert-manager; static = last resort, e.g. CDN), a
volume snippet, an openssl snippet, and a hairpin note **only** in the dial
section.

### E2 — README / DEVELOPER

- README (English — convention: new user docs are written in English): the
  new internal install path with UI flow, a short security-model summary,
  mandatory pinning and pin sources, the two-step alternative.
- A clear line: **do not mix script-based install with deb/rpm** (the
  script drops a package-foreign file in `/usr/bin` and a unit in
  `/etc/systemd/system`; `deploy/packaging/install.sh` remains as the
  GitHub fallback).
- Dual-cert proxies (RSA+ECDSA depending on the client): one doc line —
  both pin consumers (server dial and agent) are Go TLS with practically
  the same cipher selection; moot for the file source.
- DEVELOPER.md: the `internal/agentdist` concept, dev-build degradation
  (503), how to embed binaries locally (`make cross` + copy into
  `internal/agentdist/bin/`), the E2E invocation.

### E3 — Document Remaining Security Points

Included in the security section (below) and to be mirrored in the README:
- **Token in argv/history (accepted):** `--token` is briefly visible in
  `ps`/`/proc/*/cmdline` on the target host, and persists in the operator's
  shell history. Alternatives considered and rejected: an env-var variant
  ends up in the history just the same, and `sudo` strips envs; stdin
  doesn't work with `curl | sh` (stdin is the pipe); `sh -c "$(curl …)"`
  degrades the copy UX without fixing the history exposure. Load-bearing
  control: single use + short TTL — the token is worthless after use.
- **Version disclosure (accepted):** see B1.
- **`systemctl` path untested in CI (accepted gap):** see E4.

### E4 — E2E Smoke Test

**Files:** new integration test (pattern:
`internal/agentd/enroll_integration_test.go` — build tag `integration`,
testcontainers-go), `internal/agentd/testdata/sshd/Dockerfile`.

**Steps:**

1. Fixture Dockerfile: add `curl` to the `apk add` list (the alpine image
   doesn't have it; the script requires curl).
2. Test flow: bring up Postgres + API server as in the existing test;
   populate `agentdist.NewFromFS(os.DirFS(<tmpdir>))` with an agentd binary
   built for Linux (the embed is empty at test time — that's why
   `NewFromFS` exists); pin source: static, computed via
   `pintls.FromCertificate` from the test TLS certificate (dogfooding P1);
   generate a token via the mint API (C2); in the sshd fixture container,
   fetch `install.sh` via curl and run it with `--token … --no-systemd`.
3. Asserts: script exit 0; binary installed; `config.yaml` created
   (whereupon the fixture entrypoint starts the agent itself and
   `agentd.sock` appears — the same readiness signal as in the script); host
   row enrolled. This covers the full chain **token → script → download →
   hash check → enroll → running agent**.
4. Explicitly document the remaining gap (E2/E3): the `systemctl` branch
   (enable/restart/health check) stays untested in CI — the fixture has no
   systemd, a systemd container in CI would be flaky/privileged, and a
   systemctl stub would fake behavior.

**Done when:** `go test -tags integration ./internal/agentd/ -run
InstallScript` (name analogous to existing ones) passes locally; a CI job
runs it.

---

## Security Model (Summary)

This is `curl … | sudo sh` — the classic supply-chain attack surface.
Measures and deliberately accepted residual risks:

- **Serve only over HTTPS.** TLS terminates at the ingress/reverse proxy in
  front of the server; the script is fetched over `https://`.
- **The binary's SHA-256 is templated into the script.** Tampering with the
  binary download is caught by the hash check, and the script aborts.
- **The SPKI pin is mandatory, not opt-in.** Three fail-closed sources
  (static > file > verified self-dial, Phase P2); without a pin the entire
  rollout is disabled (gate P3). Certificate rotation is picked up
  automatically by the file source (uncached) and the dial source
  (background + lazy refresh); a pin mismatch fails during the TLS
  handshake **before** the token is consumed.
- **`--require-pin` = protection against operator error.** Prevents
  accidentally unpinned enrollments (a copied-out enroll line). **Not**
  MITM protection — that's provided by HTTPS + the pin sources.
- **Two-step alternative in the UI** (download, inspect, execute) — no
  forced pipe-to-shell.
- **Token = one-time, short-lived bearer secret.** UI default 1 h, single
  use enforced server-side (existing). Plaintext appears exactly once, in
  the mint response; never in logs, never in the audit payload. Accepted
  residual exposure: argv/`ps` on the target host + the operator's shell
  history (rationale and rejected alternatives: E3).
- **Binary download is public but tightly rate-limited** (10/IP/min, burst
  5, `GSSH_AGENT_DOWNLOAD_RPM`, inherited XFF behavior). The token gates
  enrollment, not binary access.
- **Token minting is roleAdmin-only and audit-logged**
  (`host.enroll_token.created`).
- **Version disclosure in the manifest accepted** (rationale: B1).
- **`Cache-Control: no-store` on the script, manifest, and binary** — no
  stale pins/hashes/binaries served from intermediate caches.

---

## Roadmap (checklist)

### Phase A — Agent Binaries in the Container
- [x] A1: package `internal/agentdist` (embed `all:bin`, `Source` with `New`/`NewFromFS`/`List`/`Open`, hex SHA-256, `.gitkeep` filtering, `.gitignore`) + unit relocation (`git mv` + `nfpm.yaml` path) + tests (fstest.MapFS)
- [x] A2: Dockerfile stage `agentbuild` (`--platform=$BUILDPLATFORM`, GOOS/GOARCH loop for amd64+arm64, identical `-ldflags`) + `COPY` into the embed directory

### Phase P — Mandatory Pinning & Rollout Gate
- [x] P1: `pintls.FromCertificate` + migration of `spkiPin()` in `internal/cli/client_test.go`
- [x] P2: pin provider — precedence `GSSH_PUBLIC_PIN` > `GSSH_PUBLIC_PIN_CERT_FILE` (uncached) > auto-dial (system roots, fail-closed, background + lazy refresh via `GSSH_PUBLIC_PIN_REFRESH`); active source in log + manifest; tests
- [x] P3: rollout gate — four conditions (binaries, pin, agent_public_url, public_url); download/script/mint return 503 with `missing`, manifest always 200 with diagnostics; tests
  (gate + 503 response implemented and tested; wiring into
  download/script/mint and the manifest diagnostics follow with B1–B3/C2)
- [x] P4: `gssh-agentd enroll --require-pin` + `GSSH_ENROLL_REQUIRE_PIN` (fail-closed before any network call); manual/deb path unchanged; tests

### Phase B — Public Endpoints
- [x] B1: `GET /v1/agents` (manifest with version/rollout_ready/missing/pin_source/agents, regular limiter, `no-store`)
- [x] B2: `GET /v1/agents/{os}/{arch}` (stream, 404/503 paths, `no-store`) + second `RateLimiter` instance (`GSSH_AGENT_DOWNLOAD_RPM` default 10, burst 5, `TrustProxyHeader` from `GSSH_RATE_TRUST_PROXY`)
- [x] B3: `GET /install.sh` — template (base URL, agent URL, version, per-arch hash, mandatory pin, unit here-doc) + script per specification (main() wrapper, `set -eu` without pipefail, trap, same-dir temp file + atomic `mv`, enroll degradation, restart-vs-enable, health check for the socket ≤ 10 s, flags `--arch`/`--session-audit`/`--no-systemd`) + handler/`sh -n` tests

### Phase C — Token Minting API
- [x] C1: extract `store.NewEnrollmentToken`, switch `runEnrollToken` over (CLI behavior unchanged)
- [x] C2: `POST /v1/admin/enroll-tokens` (roleAdmin, TTL default 1 h, gate-checked, `install_command`, audit event `host.enroll_token.created` without the token) + tests

### Phase D — Frontend
- [x] D1: "Add Host" button in `hosts.ts`, disabled + plain-text hint from the manifest's `missing`
- [x] D2: dialog (form with TTL/tags/hostname/session-audit explanation → mint; result with token copy, architecture dropdown, agent list, two-step alternative)
- [x] D3: `api/openapi.yaml` + client (regenerated with `make web-api`: `fn/rollout/*`, models `AgentManifest`/`AgentBinary`/`EnrollToken*`/`RolloutUnavailable`)

### Phase E — Docs, Helm, E2E
- [x] E1: Helm `hostRollout` block (`enabled` + `required` checks, pin-source rendering, secret volume with only `tls.crt` and no `subPath`, ≤ 2 lines of docs per parameter) + README table/snippets
- [x] E2: README (en) + DEVELOPER (install path, do-not-mix note, dual-cert line, dev degradation)
- [x] E3: residual risks documented (argv/history, version, systemctl gap)
- [x] E4: E2E smoke test (fixture + curl, `NewFromFS`, static pin via `FromCertificate`, mint → `install.sh --no-systemd` → enrolled + agent running)
  (Addendum from the E2E work: the script now creates `/etc/systemd/system`
  itself — on a host without systemd, i.e. exactly the `--no-systemd` target
  audience, the directory was missing and writing the unit failed.)

---

## Decision Log

Core decisions (all dated 2026-07-25, review points K1–K17 fully resolved
and incorporated above):

| # | Topic | Decision |
|---|---|---|
| — | Bundling | **Embed** (`go:embed`) instead of an image path — single artifact, hard version lockstep; +30–40 MB accepted |
| — | Download access | Manifest + binary are **public**; the token gates enrollment; download tightly rate-limited |
| — | Session audit | Checkbox in the dialog, default off, opt-in with explanatory text (changes PAM config) |
| K1 | Pin self-dial | Verified fail-closed against system roots; **no** `InsecureSkipVerify` code path; private CA via `SSL_CERT_FILE`/`SSL_CERT_DIR` |
| K2 | Hairpin escape | Three pin sources: static > file (secret volume, rotation-capable) > dial; all fail-closed, active source visible |
| K3 | `--require-pin` | Kept, but honestly declared as **protection against operator error** (not MITM protection) |
| K4 | Agent URL | **No** derivation; Helm `required` (fail-fast) + server gate (authoritative); manifest names missing conditions individually; no feature flag |
| K5 | Download limiter | Inherits `TrustProxyHeader` from `GSSH_RATE_TRUST_PROXY`; default 10/min burst 5; a token-bound download was rejected |
| K6 | E2E without systemd | Script flag `--no-systemd`; a systemctl stub and a systemd container were rejected; the systemctl path remains a documented CI gap |
| K7 | Re-run after a partial failure | Enroll degradation (warn + continue if `config.yaml` exists); same-dir temp file + atomic `mv` instead of `systemctl stop`; restart-vs-enable is state-dependent; multi-use tokens/reissue were rejected |
| K8 | Dockerfile | Agent stage with `--platform=$BUILDPLATFORM` + a GOOS/GOARCH loop; a CI-artifact COPY was rejected; server-stage optimization = future work |
| K9 | Certificate rotation | File source uncached; dial with background + lazy refresh; multi-pin = future work (YAGNI); a pin mismatch does not consume a token |
| K10 | Caching | `no-store` on **all three** endpoints (including the binary); ETag revalidation was rejected |
| K11 | Script hardening | `main()` wrapper, `set -eu` without `pipefail`, `trap` cleanup; self-hashing was rejected (bootstrapping circularity) |
| K12 | Unit source | `git mv` to `internal/agentdist/`, embedded from there, as a quoted here-doc in the script; `nfpm.yaml` follows; duplicate variants were rejected |
| K13 | Version in the manifest | Kept, with the risk accepted (the binary is identifiable anyway; removing it would be security theater) |
| K14 | Token in argv/history | Accepted (single use + TTL carry the risk); env-var/stdin variants only shift the exposure |
| K15 | Pin computation | New helper `pintls.FromCertificate`; test helper `spkiPin` migrated; inline duplicates were rejected |
| K16 | Token listing/revocation | Deliberately out of scope (future note) |
| K17 | Health check | `is-active` **plus** waiting for `agentd.sock` (≤ 10 s), a `journalctl` hint, exit ≠ 0; omitted with `--no-systemd`; a wrong agent URL is caught by the K4 gate |

Correction relative to an earlier version of this plan: the XFF trust env
var is really named `GSSH_RATE_TRUST_PROXY` in the code (not
`GSSH_RATE_TRUST_XFF`); the frontend reference `enrollment/enroll-host.ts`
does not exist — the dialog pattern is `grants.ts`, the client pattern is
`web/src/app/api/fn/`.

## Future Notes (deliberately out of scope)

- **Token management:** `GET/DELETE /v1/admin/enroll-tokens` + a UI list of
  open tokens (revoke before use). The leak window is already small due to
  the 1-h TTL + single use; build this if the need arises.
- **Multi-pin during rotation:** `--pin a,b` as a comma-separated list,
  retrofittable in a backward-compatible way should the seconds-long
  residual window ever become a problem.
- **Also lift the server build stage** onto `--platform=$BUILDPLATFORM` (a
  build-time optimization, independent of this feature).
- **Additional architectures** (386, arm/v7, riscv64): one entry each in
  the Dockerfile loop (A2) — the manifest, script dropdown, and UI follow
  automatically.

---

## Follow-ups from the Code Review (2026-07-26)

Review of the finished implementation (branch `feat/host-rollout`). No
critical findings, all iron rules hold; build, vet, unit tests, `helm
lint`, and Helm rendering of all three pin sources, including the
fail-fast cases, were verified. The following points are follow-up work,
not merge blockers — R1 should be done before the production rollout;
R2/R6 are cheap fixes with operator benefit.

### R1 — [Medium] Self-dial per request with no backoff as long as no pin has ever been read

**Files:** `internal/api/pinprovider.go` (`dialStatus`, line 167), tests.

When `pin == ""`, **every** call dials synchronously (the `checked`
timestamp is ignored), with no singleflight. As long as the gate is closed
and the source is `dial` (the default state of any half-configured or
freshly deployed setup), this means every request to the unauthenticated
`/v1/agents` and `/install.sh`, plus every token mint, triggers an outbound
TLS dial with up to a 5 s timeout. Consequences: the Hosts page hangs for
admins for ~5 s if the dial target is blackholed; an attacker with many IPs
can keep the server permanently issuing outbound handshakes against its own
public URL (the rate limit is per-IP only).

**Fix:** a negative cache of 5–15 s between failed attempts (a minimum
interval even when `pin == ""`) plus singleflight for concurrent callers.
This preserves the intent of the existing behavior ("the gate should open
as soon as the ingress routes") — only the rate is capped.

**Done when:** a test demonstrates: two closely spaced status calls with a
failed dial trigger exactly one dial; after the backoff expires, a new dial
happens; concurrent callers share a single dial.

### R2 — [Small] `sha256sum` missing from the script preconditions

**Files:** `internal/api/install.sh.tmpl` (step 1, line 114 ff.).

curl and sshd are checked, but not `sha256sum`. If the tool is missing, the
verification pipeline (line 140) fails, and its stderr is discarded — the
message "sha256 check failed — binary discarded" then becomes a
misdiagnosis (it looks like tampering/corruption rather than a missing
tool). **Fix:** add one line, `command -v sha256sum`, to the preconditions.

**Done when:** the precondition block checks for sha256sum; the `sh -n`
test continues to pass.

### R3 — [Small] Pin error reason missing from the manifest (plan deviation)

**Files:** `internal/api/agents.go`, `api/openapi.yaml`, possibly a UI hint.

Plan P2 promises "reason in the log **and** the manifest"; `PinStatus.Err`
is documented as "for log/manifest" but is never serialized anywhere — the
manifest only contains `pin_source`. The operator sees *that* the pin is
missing, but the *why* (dial failure, untrusted chain, unreadable file)
only shows up in the server log.

**Decision (2026-07-26): a coarse error category.** New manifest field
`pin_error` with a fixed category (e.g. `dial_failed`, `chain_untrusted`,
`cert_file_unreadable`, `no_public_url`), shown by the UI alongside the
disabled button. Deliberately **no** full text: the manifest is
unauthenticated and public, and the raw error text contains internals
(container file paths, dial details). The full text continues to live in
the container log (slog/stdout, `kubectl logs`) — both sources already log
it today.

**Implementation:** categorization in the `PinProvider` (error → category
constant), a field in `agentManifest` + `api/openapi.yaml` + the generated
client, displayed in `hosts.ts` next to the `missing` labels; this fulfills
the P2 plan text.

### R4 — [Nitpick] Quoting check in `renderInstallScript` is incomplete

**Files:** `internal/api/install_script.go` (line 102 ff.).

URL/pin/version/arch-list are validated, but `Agents[].Arch` and `.SHA256`
flow into the template unchecked — arch even ends up unquoted in the case
pattern. Not an attack path (the values are build-controlled: filenames
from the embed, hex from sha256), but the function's own self-declared
fail-closed claim doesn't actually cover them. **Fix:** `^[a-z0-9]+$` for
arch, `^[0-9a-f]{64}$` for the SHA, in the existing validation loop
(~5 lines).

### R5 — [Nitpick] The UNIT_EOF guard misses the terminator on line 1

**Files:** `internal/api/install_script.go` (line 110).

`strings.Contains(data.Unit, "\nUNIT_EOF")` doesn't match if the unit
**starts** with `UNIT_EOF`. **Fix:** `strings.Contains("\n"+data.Unit,
"\nUNIT_EOF")`. Purely theoretical (the unit is the repo's own file) — a
matter of guard completeness.

### R6 — [UX] Hostname binding is an exact string match, with no warning

**Files:** `web/src/app/features/host-add-dialog.ts` (hostname hint),
README (one-command section).

`store` compares the bound name exactly against the host's
`os.Hostname()` (`internal/store/enrollment.go:112`); the script never
passes `--hostname`. If the admin types `web-01` but the host reports its
FQDN, enrollment fails hard. The token survives the failure (`EnrollHost`
is transactional, and consumption is rolled back) — a re-run after
correcting the hostname works, but the first run ends up looking like an
unexplained error to the operator. Neither the dialog nor the README warns
about the short-name/FQDN trap.

**Decision (2026-07-26): matching stays exact, just add a warning.** The
binding is a safeguard against mistakes (the host reports its own name —
against actual attackers, single use, TTL, and admin-only minting carry
the weight); tolerant matching or a templated `--hostname` would weaken
it, or hollow it out into a mere name suggestion. **Fix:** extend the
dialog hint with both points — the field stays optional (empty = provision
unbound, no requirement to fill it in), and when set: "must exactly match
the target host's `hostname` output (watch for short name vs. FQDN)". Plus
one sentence in the README.

### Follow-up Roadmap

- [x] R1: dial backoff + singleflight in the `PinProvider` (before the production rollout)
- [x] R2: `sha256sum` precondition in install.sh
- [x] R3: `pin_error` as a coarse category in the manifest + UI (decided: variant A)
- [x] R4: arch/SHA validation in `renderInstallScript`
- [x] R5: extend the UNIT_EOF guard to cover line 1
- [x] R6: hostname hint in the dialog + README (decided: matching stays exact, field stays optional)

**Implemented on 2026-07-26.** R1: `pinDialBackoff` (10 s minimum interval
as long as no pin has ever been read) plus `dialMu` as singleflight; `Run`
goes through the same path. R3: categories `no_public_url` /
`chain_untrusted` / `dial_failed` / `cert_file_unreadable` in
`PinStatus.ErrCode` → `pin_error` in the manifest (OpenAPI + generated
client) → plain text under the disabled button. Verified: `make lint`,
`make test` (race), `make web-test`, and the Docker integration test
`internal/agentd` (install.sh in the sshd container).

---

## Follow-ups from the Second Review (2026-07-26)

### R7 — [Medium/Security] Enforce HTTPS on the public and agent URLs

The gate only checked *whether* the URLs were set, not their scheme. The
dial pin source implicitly enforces https — but with the **static**/
**file** sources, the gate would open even with `http://…` and mint `curl
http://… | sudo sh` (plaintext transport defeats both the hash check and
the pin; contradicting security-model point 1).

**Fix:** two new gate conditions, `public_url_https` /
`agent_public_url_https` (`rollout.go: isHTTPSURL`); the OpenAPI enum +
client + UI labels extended; Helm fail-fast (`hasPrefix "https://"`) on
`agentPublicUrl` and the effective public URL; a README sentence.

### R8 — [Small/Bug] Background refresh only fired every second interval

`Run` went through `dialOnce`, whose due-check (`time.Since(checked) >=
refresh`) narrowly missed on every tick by the dial's own duration —
effectively 2× the interval; on top of that, the error backoff would have
throttled the planned refresh further. **Fix:** `Run` now dials
unconditionally on every tick (`refreshDial` directly under `dialMu`); the
due-check remains solely in the requests' lazy path.

### R9 — [Small/Robustness] The lazy dial inherited the request context

A request to the unauthenticated rollout routes that was aborted
immediately (even intentionally) canceled the shared dial, cached `context
canceled` as `dial_failed`, and burned through the backoff window —
repeated deliberately, this kept the gate closed. **Fix:** the lazy dial
now runs with `context.WithoutCancel(r.Context())`; the timeout is set by
`dialPin` itself regardless.

- [x] R7: https gate conditions + Helm fail-fast + docs
- [x] R8: the run loop dials unconditionally on every tick
- [x] R9: the lazy dial is decoupled from client aborts

Tests: gate cases for http/unparsable URLs (`rollout_internal_test.go`),
`TestPinProviderRunDoesNotThrottle`, `TestPinProviderStatusIgnoresClientAbort`.
