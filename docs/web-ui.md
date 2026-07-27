# Web UI & auditing interface (Phase 8)

The web UI is an Angular SPA (`web/`) that is embedded into the `gssh-server`
binary as static assets via `go:embed` and served under `/` — one image, no
CORS, no separate deployment (ADR-003, ADR-020).

## Architecture

- **API client**: generated from `api/openapi.yaml` (single source of truth)
  with `ng-openapi-gen` into `web/src/app/api/` — regenerate with `make web-api`;
  the generated code is checked in.
- **Login**: server-side OIDC (BFF). `GET /v1/auth/login` starts an
  authorization-code + PKCE flow with the server's own confidential client
  (`GSSH_SERVER_OIDC_CLIENT_ID`/`GSSH_SERVER_OIDC_CLIENT_SECRET`); the
  session lives in an HttpOnly cookie, tokens never reach the browser.
  `GET /v1/ui/config` (public) only bootstraps the role-group names and the
  CLI setup values (the clients' public client) — no build-time environment
  needed.
- **Roles** from token claims (groups), fail-closed:

  | Role | IdP group (env) | Permissions |
  |---|---|---|
  | Admin | `GSSH_ADMIN_GROUP` | everything, including mutations (grants, CI grants, service-account kill switch) |
  | Auditor | `GSSH_AUDITOR_GROUP` | all read views (hosts, grants, CI, users) plus audit view + export |

  Admin includes auditor (admin ⊃ auditor). An empty group grants the role
  to nobody. The UI only hides elements — roles are enforced server-side on
  every request. If both groups are empty, the entire admin API stays
  disabled (503). **A login without any role is rejected** by the server
  (`/v1/auth/callback` redirects with `login_error=no_role`, no session is
  created) and the login page states that neither the admin nor the auditor
  role is assigned.

- **Server's OIDC client**: `GSSH_SERVER_OIDC_CLIENT_ID` +
  `GSSH_SERVER_OIDC_CLIENT_SECRET` — a **confidential** client in the IdP
  with redirect URI `<public URL>/v1/auth/callback`, separate from the CLIs'
  public client (`GSSH_CLIENT_OIDC_CLIENT_ID`); reusing one client for both
  is a startup error.

## Views

- **Hosts**: status (last seen), tags, host certificate expiry. Each enrolled
  host has a per-row **Connect** dialog: the one-time `client.sh` install
  line (de-emphasized, linking to Client setup), the `gssh ssh <name>` copy
  line, and an expandable **DNS fallback** for hosts without a (working) DNS
  entry that renders `gssh ssh -o HostKeyAlias=<name> <ip>` from a
  user-entered IP — the alias keeps the host-certificate check against the
  enrolled name, so verification stays intact (see
  [README — client install](../README.md#client-install)). The agent's
  last observed source address is offered as a labeled click-to-fill
  suggestion (egress ≠ sshd address behind NAT); it is never silently
  prefilled.
- **Client setup**: install page for the `gssh` client — the three-step flow
  with the `curl … /client.sh | sh` one-liner, a two-step
  download-inspect-run alternative, direct binary downloads per platform
  (size, SHA-256 with copy button), and the manual `config.yaml` snippet.
  If the server-side client gate is closed (`GET /v1/clients` reports
  `missing` conditions), the page shows the reasons in plain language
  instead of the instructions.
- **Access rules**: grants including create/edit/delete (admin); mutations
  generate server-side audit events with an actor.
- **CI & service accounts**: CI grants (CRUD, admin) and service accounts
  with an active toggle (per-project kill switch; audited as
  `service_account.updated`).
- **Users & groups**: inventory synced from the IdP (read-only).
- **Audit** (auditor role): filterable by event type, actor, time range, and
  full text (`q` matches actor and payload — covers host and pipeline
  filters); export as CSV/JSON download (max. 100,000 rows).

## Audit streaming (SIEM)

Committed audit events can be emitted continuously (poller, only new events
since server start; best-effort — the audit table remains the source of
truth):

| Env | Effect |
|---|---|
| `GSSH_AUDIT_STREAM=true` | every event as a structured JSON log line on stdout (msg `audit-event`) |
| `GSSH_AUDIT_WEBHOOK_URL` | POST the events as a JSON array to the webhook |
| `GSSH_AUDIT_STREAM_INTERVAL` | poll interval (Go duration, default `10s`) |

## Build

- `make web` — `npm ci` + Angular build into `web/dist` (gets embedded).
- `make web-test` — frontend unit tests (vitest, headless).
- `make web-api` — regenerate the API client from `api/openapi.yaml`.
- Without a web build, the Go binary works fully; `/` then responds with
  503 ("web-ui not built"). Only `.gitkeep` is versioned in `web/dist/`, so
  `go:embed` always builds.
- Docker: a dedicated Node stage in the `Dockerfile` builds the UI, so the
  release image always includes it.
- CI: the `web-build` job (install, vitest, production build) runs on PRs and
  `main`; the frontend is excluded from the Go coverage gate (Plan Phase 0).

## Development

### Mock mode (default `ng serve` — no backend at all)

```sh
cd web
npm ci
npm start        # ng serve → http://localhost:4200, everything mocked
```

Plain `ng serve` runs the UI entirely without a backend: `angular.json`
replaces [`environment.ts`](../web/src/environments/environment.ts) with
`environment.mock.ts`, which switches on the
[mock interceptor](../web/src/app/core/mock/mock-api.interceptor.ts). Every
`/v1` request is answered from
[fixtures](../web/src/app/core/mock/mock-data.ts) that deliberately contain
one example per UI variant (every pill color, expired/expiring/missing
certificates, active/inactive rows, empty and overlong fields, multi-page
audit log). Grant/CI-grant/service-account dialogs mutate in-memory state,
so create/edit/delete behave realistically until reload.

Role variants without a backend, in the browser console:

```js
localStorage.setItem('gssh-mock-roles', 'auditor'); // read-only view
localStorage.setItem('gssh-mock-roles', '');        // logged-out view
localStorage.removeItem('gssh-mock-roles');         // back to admin
```

(reload after each change). Production builds ship with `mockApi: false` —
the mock never answers outside `ng serve`.

### Against a real server

```sh
npm run start:backend    # ng serve -c backend; /v1 proxied to localhost:8080
```

`proxy.conf.json` forwards `/v1` to `http://localhost:8080`, so login and API
calls work against a locally running `gssh-server`.

### Server developer mode (no IdP)

For integration work against the real server without an IdP: with
`GSSH_DEV_UI_AUTH=insecure` every request without a bearer token acts as a
logged-in admin (`dev`, all roles). Only the exact value `insecure` activates
it — anything else fails startup. PostgreSQL and `GSSH_CA_MASTER_KEY` are
still required; the OIDC/Dex variables are not:

```sh
docker run -d --name gssh-db \
  -e POSTGRES_USER=gssh -e POSTGRES_PASSWORD=gssh -e POSTGRES_DB=gssh \
  -p 5432:5432 postgres:16-alpine

export GSSH_DB_HOST=localhost GSSH_DB_USER=gssh GSSH_DB_PASSWORD=gssh \
       GSSH_DB_NAME=gssh GSSH_DB_SSLMODE=disable
export GSSH_CA_MASTER_KEY="$(openssl rand -base64 32)"
export GSSH_DEV_UI_AUTH=insecure
# In-app rule editing is off by default (rules are expected to come from
# GitOps); enable it if you work on the grants/CI pages.
export GSSH_MANUAL_RULES=true

go run ./cmd/gssh-server -listen :8080
```

Then `npm run start:backend` in `web/` — the UI at `http://localhost:4200`
is signed in as `dev` immediately.

**Security:** this disables authentication on the admin API of that server
process. It is meant for a server bound to localhost with throwaway data;
never set it on anything reachable by others. The `X-Requested-With` CSRF
check stays active, so other websites cannot script your local API.
</content>
