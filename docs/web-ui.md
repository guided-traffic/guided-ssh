# Web UI & auditing interface (Phase 8)

The web UI is an Angular SPA (`web/`) that is embedded into the `gssh-server`
binary as static assets via `go:embed` and served under `/` — one image, no
CORS, no separate deployment (ADR-003, ADR-020).

## Architecture

- **API client**: generated from `api/openapi.yaml` (single source of truth)
  with `ng-openapi-gen` into `web/src/app/api/` — regenerate with `make web-api`;
  the generated code is checked in.
- **Login**: OIDC Authorization Code + PKCE (`angular-auth-oidc-client`).
  The SPA loads the issuer and client ID at runtime from `GET /v1/ui/config`
  (public) — no build-time environment needed. The server validates ID
  tokens as bearer tokens (consistent with `gssh-admin`).
- **Roles** from token claims (groups), fail-closed:

  | Role | IdP group (env) | Permissions |
  |---|---|---|
  | Admin | `GSSH_ADMIN_GROUP` | everything, including mutations (grants, CI grants, service-account kill switch) |
  | Auditor | `GSSH_AUDITOR_GROUP` | audit view + export, all read views |
  | Read-only | `GSSH_READONLY_GROUP` | read views (hosts, grants, CI, users) |

  Higher roles include lower ones (admin ⊃ auditor ⊃ readonly). The UI only
  hides elements — roles are enforced server-side on every request. If all
  three groups are empty, the entire admin API stays disabled (503).

- **UI's OIDC client**: `GSSH_UI_OIDC_CLIENT_ID` (default: `GSSH_OIDC_CLIENT_ID`).
  Set it up in the IdP as a public client with a redirect URI pointing at the
  UI origin.

## Views

- **Hosts**: status (last seen), tags, host certificate expiry.
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

```sh
cd web
npm ci
npm start        # ng serve; proxy.conf.json is wired in angular.json
```

`proxy.conf.json` forwards `/v1` to `http://localhost:8080`, so login and API
calls work against a locally running `gssh-server`.

### Developer mode (no IdP)

For pure frontend work, the server can skip OIDC entirely: with
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

go run ./cmd/gssh-server -listen :8080
```

Then `npm start` in `web/` — the UI at `http://localhost:4200` is signed in
as `dev` immediately.

**Security:** this disables authentication on the admin API of that server
process. It is meant for a server bound to localhost with throwaway data;
never set it on anything reachable by others. The `X-Requested-With` CSRF
check stays active, so other websites cannot script your local API.
</content>
