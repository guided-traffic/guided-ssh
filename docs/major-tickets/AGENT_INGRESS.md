# Agent mTLS ingress — SNI/TLS-passthrough Ingress for the agent endpoint

Status: **draft / planned**

> **As of 2026-07-27.** Verified against `main`
> ([values.yaml](../../deploy/helm/guided-ssh/values.yaml),
> [service-agent.yaml](../../deploy/helm/guided-ssh/templates/service-agent.yaml),
> [_helpers.tpl](../../deploy/helm/guided-ssh/templates/_helpers.tpl),
> [deployment.yaml](../../deploy/helm/guided-ssh/templates/deployment.yaml)).
> Same work-package style as [GITOPS_EXTERNAL_RULES.md](GITOPS_EXTERNAL_RULES.md):
> **Files**, **Steps**, **Do not**, **Done when**.

Goal: agents outside the cluster reach the agent mTLS API (port 8443) through
a **second Ingress** on an SNI/TLS-passthrough-capable ingress controller —
no extra LoadBalancer IP needed. The public agent hostname declared on that
Ingress becomes the single source of truth: it feeds the server certificate
SANs (`GSSH_AGENT_TLS_NAMES`) and the agent URL rolled out to newly added
hosts (`GSSH_AGENT_PUBLIC_URL` in the one-command install).

---

## Motivation

1. The agent API terminates TLS **in the gssh server itself**: the server
   presents a certificate issued by the internal mTLS CA and authenticates
   agents by client certificate. Any ingress that terminates TLS breaks the
   client-certificate handshake — the chart therefore currently offers only a
   Service (`agent.service`, ClusterIP/LoadBalancer,
   [service-agent.yaml](../../deploy/helm/guided-ssh/templates/service-agent.yaml))
   and no Ingress.
2. A dedicated LoadBalancer per installation costs an external IP and a DNS
   entry outside the ingress wildcard. Target environments (here: HAProxy
   ingress, already deployed) support **SSL/TLS passthrough**: the controller
   inspects only the SNI of the ClientHello, picks the backend, and forwards
   the raw TCP stream — the TLS session stays end-to-end between agent and
   gssh server. mTLS works unchanged.
3. `hostRollout.agentPublicUrl` must currently be set by hand and is
   "deliberately never derived"
   ([_helpers.tpl](../../deploy/helm/guided-ssh/templates/_helpers.tpl),
   `hostRolloutEnv`) — correct as long as no chart value carries the external
   agent hostname. With `agent.ingress.host` such a value exists; deriving
   from it removes a duplicate-and-drift-prone setting (see D3).

---

## Feasibility

**Verdict: feasible, standard pattern.** TLS passthrough by SNI is a
first-class feature of HAProxy ingress (and others); the gssh agent listener
already does everything else itself.

What makes it work:

- **SNI is always present.** `gssh-agentd` dials `https://<host>[:port]`; the
  Go TLS stack sets `ServerName` from the URL host automatically. The
  controller routes on that SNI. (Consequence: an **IP-based** agent URL
  cannot be routed through a passthrough ingress — hostname required. The
  chart's https validation already pushes in that direction.)
- **The controller never touches the TLS session.** Client-certificate
  request, verification against the mTLS CA, and the server certificate all
  stay inside the gssh server. Nothing about the server changes.
- **Port mapping.** Agents connect to the controller's TLS frontend
  (`:443`); the controller forwards the raw stream to the Service port 8443.
  The derived public URL is therefore `https://<agent.ingress.host>`
  (implicit 443), **not** `:8443`.
- **Certificate SANs.** The server certificate must carry the public
  hostname — `GSSH_AGENT_TLS_NAMES` gets the ingress host appended (D3).

Controller specifics (annotation-only, chart stays generic — D2):

| Controller | Passthrough annotation | Notes |
|---|---|---|
| haproxy-ingress (jcmoraisjr) | `haproxy-ingress.github.io/ssl-passthrough: "true"` | routes on the Ingress rule host; backend = TLS port of the service |
| haproxytech kubernetes-ingress | `haproxy.org/ssl-passthrough: "true"` | passthrough switches the whole frontend to SNI inspection |
| ingress-nginx | `nginx.ingress.kubernetes.io/ssl-passthrough: "true"` | controller must run with `--enable-ssl-passthrough`; documented for completeness |

Known limitations (accepted, documented in README):

- **Source IP:** with plain passthrough the server sees the ingress
  controller's pod IP, not the agent's. Fixed by the optional PROXY protocol
  support (D5/WP5, default **off**): the controller prepends a PROXY header,
  the gssh agent listener parses it behind a trust policy. Without WP5 (or
  with the feature off), the controller **must not** send PROXY protocol —
  the listener would read the header as garbage bytes of the TLS handshake.
  Impact when off: agent-side audit entries see the controller IP.
  Acceptable: agent authentication is mTLS, not IP-based.
  (`GSSH_RATE_TRUST_PROXY` is HTTP-header-based and does not apply to the
  raw TLS listener.)
- **No L7 features** on this path: no path routing (path is fixed `/`), no
  controller-side TLS metrics/WAF for this vhost. Inherent to passthrough.
- **No `tls:` block** in the Ingress: there is no controller certificate to
  reference — a `secretName` here would be misleading at best (some
  controllers would start terminating). The template renders none (D2).

Security notes (real ones, no boilerplate):

- Passthrough **improves** the security posture versus termination: mTLS
  stays end-to-end, the controller never holds the agent-facing private key,
  and no re-encryption hop exists to misconfigure.
- SNI is unencrypted routing metadata; it leaks only the hostname — same
  exposure as the DNS record itself.

---

## Design decisions

### D1 — A second, separate Ingress resource — not an extension of `ingress.*`

The existing [ingress.yaml](../../deploy/helm/guided-ssh/templates/ingress.yaml)
serves the HTTP API/UI: TLS-terminating, cert-manager-friendly, path-based.
The agent ingress is the opposite on every axis (passthrough, single host,
fixed path, different — possibly dedicated — controller class). Mixing both
into one values block would force every field to carry "but for agent it
means…" caveats. Separate template, separate values block:

```yaml
agent:
  ingress:
    # Second ingress for the agent mTLS endpoint. Requires an ingress
    # controller doing TLS passthrough (SNI-based routing, raw TCP to the
    # service) — the gssh server terminates mTLS itself; a TLS-terminating
    # ingress breaks the client-certificate handshake.
    enabled: false          # default
    # Class of the passthrough-capable controller (may differ from ingress.className).
    className: ""           # default
    # Public agent hostname (mandatory when enabled). Also feeds
    # GSSH_AGENT_TLS_NAMES and the hostRollout.agentPublicUrl default — see README.
    host: ""                # e.g. gssh-agent.example.com
    # Passthrough is enabled via controller-specific annotations (see README
    # for haproxy-ingress / haproxytech / ingress-nginx).
    annotations: {}         # example: haproxy-ingress.github.io/ssl-passthrough: "true"
```

### D2 — Generic `networking.k8s.io/v1` Ingress, passthrough via annotations only

The chart renders a standard Ingress: one rule (`host`, path `/`,
`pathType: Prefix`), backend `<fullname>-agent` port name `agent`, **no
`tls:` section**. Everything controller-specific lives in
`agent.ingress.annotations`, supplied by the operator. No Traefik
`IngressRouteTCP` or other CRDs in the chart — Traefik users bring their own
manifest (README notes this). Keeps the chart controller-agnostic and the
maintenance surface minimal.

Render guards (fail at render time, consistent with the chart's
fail-fast philosophy in `guided-ssh.validateValues`):

- `agent.ingress.enabled=true` requires `agent.enabled=true` **and**
  `agent.service.enabled=true` (the Ingress needs the backend Service).
- `agent.ingress.enabled=true` requires `agent.ingress.host` (SNI routing
  without a host is meaningless).

### D3 — `agent.ingress.host` becomes the single source of truth (derivations)

Two derivations, both **overridable by the existing explicit values**:

1. **`GSSH_AGENT_TLS_NAMES`** (`guided-ssh.agentTLSNames`): when
   `agent.tlsNames` is empty and `agent.ingress.host` is set, the default
   becomes
   `<fullname>-agent.<ns>.svc,<fullname>-agent.<ns>.svc.cluster.local,<agent.ingress.host>`.
   Explicit `agent.tlsNames` wins unchanged.
2. **`GSSH_AGENT_PUBLIC_URL`** (`guided-ssh.hostRolloutEnv`): when
   `hostRollout.agentPublicUrl` is empty and `agent.ingress.enabled` with a
   host, the default becomes `https://<agent.ingress.host>` (no port —
   passthrough entry is the controller's 443). Explicit value wins.

This consciously **relaxes** the "deliberately never derived" decision in
`hostRolloutEnv`. That guard existed because the only candidates for
derivation were internal service names — rolling those out to the fleet
would be silently wrong. `agent.ingress.host` is different: it is an
operator-declared **public** name, and the Ingress it configures is exactly
the path agents use. Deriving from it removes a second place where the same
hostname must be kept in sync. The `required` error message stays for the
no-ingress case and gains a hint ("…or enable agent.ingress with a host").

Edge case kept explicit: an operator exposing agents on a **non-443** port
(e.g. LoadBalancer with `:8443`) sets `hostRollout.agentPublicUrl`
explicitly, exactly as today.

### D4 — NetworkPolicy: documentation, not new template logic

With the ingress path, agent traffic arrives from the controller's pods, no
longer from an LB directly. `networkPolicy.agentFrom` already models this
(list of `NetworkPolicyPeer`); the values comment and README get an example
(`namespaceSelector` of the ingress controller namespace). No template
change.

### D5 — Optional PROXY protocol on the agent listener, behind a trust policy

**Why, given mTLS.** mTLS fully covers *access*: without a valid client
certificate every connection dies in the handshake, PROXY header or not.
What mTLS does **not** cover is the integrity of `RemoteAddr` — the source
IP recorded in the audit log. The relevant attacker is the *authenticated*
one: a compromised enrolled host holds a valid agent certificate, and if it
may connect directly to the Service and send its own PROXY header, it writes
any source IP it likes into the audit trail (hide its origin, frame another
host). Exactly in the compromise case the audit log has to be truthful.
NetworkPolicies can block the direct path, but `networkPolicy.enabled`
defaults to `false` — the trust policy is the app-level
defense-in-depth for deployments without one, and costs nothing where a
NetworkPolicy already filters (the reject branch simply never fires).

**Feature (default off).** `GSSH_AGENT_PROXY_PROTOCOL=true` wraps the agent
listener with [go-proxyproto](https://github.com/pires/go-proxyproto)
(v1+v2, stdlib-compatible `net.Listener`) **before** TLS — the PROXY header
precedes the TLS bytes, so it composes cleanly with passthrough; after the
wrapper, `RemoteAddr` carries the real agent IP. A header read timeout
bounds the pre-TLS phase.

**Trust policy** (`GSSH_AGENT_PROXY_TRUSTED`, comma-separated; per-connection
`Policy` hook of go-proxyproto):

| Source of connection | PROXY header present | absent |
|---|---|---|
| trusted entry match | accepted (used) | **rejected** — a trusted controller must send one (fail closed on misconfig) |
| no match | **rejected** — spoof attempt | plain TLS, works as today |
| `trusted` empty, feature on | required from everyone | rejected |

**Entries: CIDRs, IPs, or DNS names.** An entry that parses as CIDR/IP is
used as-is; anything else is a DNS name resolved to its A/AAAA records. The
DNS form exists so operators do not have to trust the whole pod CIDR: a
**headless Service** selecting the ingress controller pods resolves exactly
to the controller pod IPs — the IPs the gssh server actually sees as
sources. (A normal Service name resolves to the ClusterIP, which is never a
source address — headless is required. If the controller chart ships none, a
five-line manifest next to it does.) No Kubernetes API access needed; the
server keeps `automountServiceAccountToken: false`.

Resolution semantics:

- **Startup fail-fast:** an unresolvable name at boot is a config error
  (typo) — the server refuses to start rather than running with a silently
  empty trust set.
- **Refresh:** periodic re-resolve (~15 s), plus a rate-limited forced
  re-resolve when a header arrives from an unknown IP — covers controller
  pod restarts without rejecting a new pod until the next tick.
- **DNS failure at runtime:** keep the last known good set and log a
  warning — never empty the set (a CoreDNS hiccup must not self-DoS the
  agent path).
- **Trust anchor** is the cluster DNS: whoever controls CoreDNS can steer
  the trusted set — and also already owns the cluster. Accepted, documented.

**Rollout ordering constraint:** enable the server flag *first*, then the
controller's send-proxy annotation. The reverse order breaks the endpoint
(the listener reads the PROXY header as garbage TLS bytes). Same in
reverse for disabling. Documented in README and the rollout section.

---

## Work packages

### WP1 — Chart: `ingress-agent.yaml` + values

**Files:**
[templates/ingress-agent.yaml](../../deploy/helm/guided-ssh/templates/) (new),
[values.yaml](../../deploy/helm/guided-ssh/values.yaml),
[_helpers.tpl](../../deploy/helm/guided-ssh/templates/_helpers.tpl)

**Steps:**

1. Add the `agent.ingress` block to `values.yaml` (D1), with the passthrough
   warning comment.
2. New template `ingress-agent.yaml`, guarded by
   `agent.enabled && agent.service.enabled && agent.ingress.enabled`:
   name `{{ fullname }}-agent` (matches the Service — naming convention),
   standard labels, `ingressClassName` from `agent.ingress.className`,
   annotations verbatim from values, one rule
   (`host` / `/` / `Prefix` / backend service `{{ fullname }}-agent`, port
   name `agent`), no `tls:` block (D2).
3. Render guards in `guided-ssh.validateValues` (or inline `fail` in the
   template): missing `host`, or `agent.ingress.enabled` while
   `agent.enabled`/`agent.service.enabled` is false → render error with a
   one-line explanation.

**Do not:**

- Do not add a `tls:`/`secretName` option "for flexibility" — on a
  passthrough vhost it is dead config or actively harmful (D2/Feasibility).
- Do not template controller-specific annotations behind a
  `controllerType` switch — annotations stay operator-supplied (D2).
- Do not reuse the existing `ingress.yaml` with a second document — separate
  concerns (D1).

**Done when:** `helm template` with
`--set agent.ingress.enabled=true --set agent.ingress.host=gssh-agent.example.com`
renders the Ingress with backend `gssh-guided-ssh-agent:agent` and no `tls:`
key; render fails with a clear message for each guard violation.

### WP2 — Derivations in `_helpers.tpl`

**Files:**
[_helpers.tpl](../../deploy/helm/guided-ssh/templates/_helpers.tpl),
[values.yaml](../../deploy/helm/guided-ssh/values.yaml) (comments for
`agent.tlsNames`, `hostRollout.agentPublicUrl`)

**Steps:**

1. `guided-ssh.agentTLSNames`: append `agent.ingress.host` to the default
   SAN list when set (D3.1); explicit `agent.tlsNames` unchanged.
2. `guided-ssh.hostRolloutEnv`: default `GSSH_AGENT_PUBLIC_URL` to
   `https://<agent.ingress.host>` when `agent.ingress.enabled` and
   `hostRollout.agentPublicUrl` is empty (D3.2); keep the https validation
   on the explicit value; update the `required` message for the
   neither-set case.
3. Update the values comments: document the derivation and the
   non-443 edge case.

**Do not:**

- Do not derive from `agent.ingress.host` when `agent.ingress.enabled=false`
  — a disabled ingress must not leak its host into the fleet rollout.
- Do not silently normalize an explicit `agentPublicUrl` — explicit values
  keep failing loudly on http (existing behavior).

**Done when:** `helm template` shows (a) the ingress host inside
`GSSH_AGENT_TLS_NAMES` and `GSSH_AGENT_PUBLIC_URL=https://<host>` when only
the ingress is configured, (b) explicit `agent.tlsNames` /
`hostRollout.agentPublicUrl` overriding both, (c) the updated `required`
error when `hostRollout.enabled=true` with neither source set.

### WP3 — Golden render tests

**Files:** [hack/helm-render-test.sh](../../hack/helm-render-test.sh)

**Steps:** add cases following the existing `render`/`has`/`fails` helpers —
ingress renders (annotations, backend, no `tls:`), both derivations, both
overrides, all render guards. Ingress assertions render
`-s templates/ingress-agent.yaml`, env assertions `-s templates/deployment.yaml`
(script convention).

**Done when:** `make helm-test` green; deliberately breaking a guard turns
the matching case red.

### WP4 — Documentation + flux example

**Files:** [README.md](../../README.md),
[deploy/flux-example/](../../deploy/flux-example/)

**Steps:**

1. README naming conventions: new row — Ingress `<fullname>-agent`.
2. README full reference: `agent.ingress.*` parameters; annotation table for
   the three controllers (Feasibility); explicit warning that a
   TLS-terminating ingress breaks agent mTLS; source-IP limitation;
   `networkPolicy.agentFrom` example for the controller namespace (D4).
3. README fast start: minimal example — HAProxy ingress + derived
   `agentPublicUrl` (shows the "one hostname, three consumers" effect).
4. flux-example overlays: commented `agent.ingress` values block in the
   staging patch as a template for real deployments.

**Done when:** every documented value verified against the rendered chart;
README cross-links this ticket.

### WP5 — Optional PROXY protocol support (server + chart)

**Files:**
[cmd/gssh-server/main.go](../../cmd/gssh-server/main.go) (`serve` /
`newAgentServer` — listener setup around `ListenAndServeTLS`),
new `internal/…` helper for the trust policy + DNS refresh (placement
follows existing package layout),
[values.yaml](../../deploy/helm/guided-ssh/values.yaml),
[templates/deployment.yaml](../../deploy/helm/guided-ssh/templates/deployment.yaml),
[hack/helm-render-test.sh](../../hack/helm-render-test.sh),
[README.md](../../README.md), `go.mod` (go-proxyproto)

**Steps:**

1. Server: when `GSSH_AGENT_PROXY_PROTOCOL=true`, open the agent listener
   explicitly (`net.Listen`), wrap with `proxyproto.Listener` (header read
   timeout set), serve via `agentServer.ServeTLS(wrapped, "", "")` instead
   of `ListenAndServeTLS`.
2. Trust policy per D5: parse `GSSH_AGENT_PROXY_TRUSTED` into CIDR/IP
   entries and DNS names; policy hook implements the D5 matrix; DNS names
   get startup fail-fast, periodic refresh, forced re-resolve on unknown
   header sender (rate-limited), keep-last-good on resolution failure.
3. Unit tests: policy matrix (all six cells), mixed entry parsing, DNS
   refresh behavior with a fake resolver, header timeout.
4. Chart: values block

   ```yaml
   agent:
     proxyProtocol:
       # PROXY protocol v1/v2 on the agent listener — only enable when the
       # ingress controller sends it (send-proxy); ordering: server first,
       # then controller annotation (see README).
       enabled: false        # default
       # Trusted senders: CIDRs, IPs, or DNS names (headless service of the
       # ingress controller pods). Empty = header required from ALL
       # connections. See SECURITY note in README.
       trusted: []           # example: ["haproxy-pods.ingress.svc.cluster.local"]
   ```

   → `GSSH_AGENT_PROXY_PROTOCOL` / `GSSH_AGENT_PROXY_TRUSTED` in
   [deployment.yaml](../../deploy/helm/guided-ssh/templates/deployment.yaml);
   render guard: `agent.proxyProtocol.enabled` requires `agent.enabled`.
5. Golden render cases: env set/unset, trusted list joined correctly, guard.
6. README: parameter docs incl. the D5 threat model in two sentences
   (what mTLS covers, what the policy adds), headless-service example
   manifest, send-proxy annotations per controller (haproxytech:
   `haproxy.org/send-proxy-protocol: "proxy-v2"`; jcmoraisjr: verify first —
   see Open questions), rollout ordering warning.

**Do not:**

- Do not accept a PROXY header from untrusted sources "if present" — that
  is precisely the audit-spoofing hole the policy exists for (D5).
- Do not resolve normal (ClusterIP) Service names and call it done — the
  resolved IP would never match a source address; README must point at
  headless Services explicitly.
- Do not empty the trust set on a failed DNS refresh (self-DoS, D5).
- Do not enable PROXY protocol implicitly with `agent.ingress.enabled` —
  the controller-side annotation is operator-managed, the chart cannot know
  it; implicit coupling would break the endpoint on rollout ordering.

**Done when:** unit tests green (`make test`); golden render cases green
(`make helm-test`); manual: with feature + controller annotation enabled,
an agent heartbeat logs the **agent's real IP**; a direct in-cluster
connection sending a forged PROXY header is rejected; a direct connection
without header still works.

---

## Rollout / verification (per environment, manual)

1. DNS: `<agent host>` → same LB/IP as the HAProxy ingress controller.
2. Set values: `agent.ingress.enabled=true`, `className`, `host`,
   passthrough annotation. Roll out (Flux).
3. `openssl s_client -connect <agent-host>:443 -servername <agent-host>`
   must show the **gssh mTLS CA-issued server certificate** (issuer = the
   internal CA, SAN contains the agent host) — *not* the ingress wildcard
   certificate. Wildcard cert ⇒ passthrough annotation not effective.
4. Enroll a fresh host via the UI one-command install: the install command
   must contain the derived `https://<agent-host>`; the agent connects and
   heartbeats.
5. Existing agents (old URL, e.g. LoadBalancer) keep working until their
   config is migrated — both paths hit the same server port.
6. Optional, PROXY protocol (WP5): first roll out the server with
   `agent.proxyProtocol.enabled=true` + `trusted` (headless service of the
   controller pods), **then** add the controller's send-proxy annotation.
   Verify: agent heartbeat log shows the agent's real IP; a direct
   connection with a forged PROXY header is rejected.

## Open questions

- Which HAProxy ingress flavor runs in the target cluster
  (jcmoraisjr vs. haproxytech)? Determines the annotation used in the
  environment values — irrelevant to the chart itself (D2). For WP5 the
  jcmoraisjr **send-proxy** (controller → backend) annotation must be
  verified against its docs before it lands in the README — only the
  haproxytech one (`haproxy.org/send-proxy-protocol`) is confirmed.
- Should the e2e kind suite (`make e2e`) gain a passthrough scenario? Needs
  an ingress controller in kind — deferred; golden render tests (WP3) cover
  the chart logic.
