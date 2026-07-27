# ADR-020: Web UI — role model, generated API client, audit export/streaming

## Status

Accepted (Phase 8)

## Context

Phase 8 calls for a read-mostly web UI (Angular, ADR-003) with roles derived
from token claims, an API client generated from an OpenAPI spec, a filterable
audit view with export, and SIEM connectivity. Open questions: how are roles
mapped, how does the SPA obtain its OIDC configuration, how is the client
generated (without a Java toolchain on the runners), and how are audit events
reliably streamed to external systems?

## Decision

1. **Three roles as IdP groups, enforced server-side.**
   `GSSH_ADMIN_GROUP` (mutations), `GSSH_AUDITOR_GROUP` (read + export
   audit), `GSSH_READONLY_GROUP` (read resources); admin ⊃ auditor ⊃
   readonly. An empty group ⇒ the role is granted to no one (fail-closed);
   if all three are empty ⇒ the admin API stays at 503. The UI evaluates the
   same groups purely for display purposes (`/v1/ui/config` returns the
   group names).

   > **Superseded (readonly-role removal):** the readonly role was merged
   > into auditor — two roles remain (`admin ⊃ auditor`,
   > `GSSH_READONLY_GROUP` removed), and a web-UI login without any role is
   > rejected by the server instead of minting a role-less session. See
   > [docs/web-ui.md](../web-ui.md).

2. **Bootstrap via `GET /v1/ui/config` (public).** The SPA loads the issuer,
   client ID (`GSSH_UI_OIDC_CLIENT_ID`, default `GSSH_OIDC_CLIENT_ID`), and
   role groups at runtime — a single build for all environments, no secrets
   in the frontend. Login via Authorization Code + PKCE
   (`angular-auth-oidc-client`); the ID token serves as the bearer token,
   consistent with `gssh-admin` and the sign endpoint.

   > **Superseded** by the BFF rework and the server/client OIDC split: the
   > SPA login described here was replaced by the server-side login
   > (`/v1/auth/…`) with the server's own confidential client
   > (`GSSH_SERVER_OIDC_CLIENT_ID`); `/v1/ui/config` now only serves the
   > role-group names and the CLI setup values (the clients' public client,
   > `GSSH_CLIENT_OIDC_CLIENT_ID`). See [docs/web-ui.md](../web-ui.md).

3. **API client generated from `api/openapi.yaml` with `ng-openapi-gen`.**
   The spec is hand-maintained and the single source of truth for the REST
   API; the generator is pure Node tooling (no Java, unlike
   openapi-generator). The generated code is checked in (reproducible
   build); regeneration via `make web-api`.

4. **Embedding with a placeholder.** `web/embed.go` embeds `web/dist`; only
   `.gitkeep` is version-controlled. Without an Angular build, the server
   still compiles and runs fully, with `/` responding 503. The SPA handler
   falls back to `index.html` for client routes, but never for `/v1/…`;
   hashed assets are cached immutably. The Docker image builds the UI in
   its own Node stage and always includes it.

5. **Audit export and streaming are separate.** Export is a pull
   (`GET /v1/admin/audit/export`, CSV/JSON, capped at 100,000 rows,
   Auditor role). Streaming is a poller (`internal/auditstream`) that only
   emits committed events from server start onward: as structured JSON logs
   on stdout (`GSSH_AUDIT_STREAM=true`) and optionally as batch POSTs to
   `GSSH_AUDIT_WEBHOOK_URL` — best-effort, with the append-only audit table
   remaining the source of truth. Deliberately no hook into the write
   transactions: the poller only sees committed events, and a webhook
   outage cannot delay certificate issuance.

## Consequences

- Role changes take effect without redeployment (IdP group maintenance).
- New endpoints require maintaining the OpenAPI spec (deliberate: spec-first).
- The streaming cursor lives in-process; after a restart, old events are not
  redelivered (the SIEM only gets gaps during downtime — accepted, export
  covers backfill needs).
- `service_account.updated` extends the audit events: the per-project kill
  switch can be attributed to an actor.
