# Web-UI & Auditing-Oberfläche (Phase 8)

Die Web-UI ist eine Angular-SPA (`web/`), die als statische Assets via
`go:embed` ins `gssh-server`-Binary eingebettet wird und unter `/` läuft —
ein Image, kein CORS, kein separates Deployment (ADR-003, ADR-020).

## Architektur

- **API-Client**: generiert aus `api/openapi.yaml` (Single Source of Truth)
  mit `ng-openapi-gen` nach `web/src/app/api/` — Regenerieren mit `make web-api`,
  der generierte Code ist eingecheckt.
- **Login**: OIDC Authorization Code + PKCE (`angular-auth-oidc-client`).
  Die SPA lädt Issuer und Client-ID zur Laufzeit von `GET /v1/ui/config`
  (öffentlich) — kein Build-time-Environment nötig. Der Server validiert
  ID-Tokens als Bearer-Token (konsistent zu `gssh-admin`).
- **Rollen** aus Token-Claims (Gruppen), fail-closed:

  | Rolle | IdP-Gruppe (Env) | Rechte |
  |---|---|---|
  | Admin | `GSSH_ADMIN_GROUP` | alles inkl. Mutationen (Grants, CI-Grants, Service-Account-Not-Aus) |
  | Auditor | `GSSH_AUDITOR_GROUP` | Audit-Ansicht + Export, alle Read-Ansichten |
  | Read-only | `GSSH_READONLY_GROUP` | Read-Ansichten (Hosts, Grants, CI, Benutzer) |

  Höhere Rollen schließen niedrigere ein (admin ⊃ auditor ⊃ readonly). Die
  UI blendet nur aus — durchgesetzt werden Rollen serverseitig pro Request.
  Sind alle drei Gruppen leer, bleibt die gesamte Admin-API deaktiviert (503).

- **OIDC-Client der UI**: `GSSH_UI_OIDC_CLIENT_ID` (Default: `GSSH_OIDC_CLIENT_ID`).
  Im IdP als Public Client mit Redirect-URI auf den UI-Origin anlegen.

## Ansichten

- **Hosts**: Status (zuletzt gesehen), Tags, Ablauf des Host-Zertifikats.
- **Zugriffsregeln**: Grants inkl. Anlegen/Bearbeiten/Löschen (Admin);
  Mutationen erzeugen serverseitig Audit-Events mit Actor.
- **CI & Service-Accounts**: CI-Grants (CRUD, Admin) und Service-Accounts
  mit Aktiv-Schalter (Not-Aus pro Projekt; auditiert als
  `service_account.updated`).
- **Benutzer & Gruppen**: aus dem IdP synchronisierter Bestand (read-only).
- **Audit** (Rolle Auditor): filterbar nach Ereignistyp, Actor, Zeitraum und
  Volltext (`q` matcht Actor und Payload — deckt Host- und Pipeline-Filter ab);
  Export als CSV/JSON-Download (max. 100 000 Zeilen).

## Audit-Streaming (SIEM)

Committete Audit-Events können fortlaufend emittiert werden (Poller, nur
neue Events ab Serverstart; best-effort, die Audit-Tabelle bleibt Source of
Truth):

| Env | Wirkung |
|---|---|
| `GSSH_AUDIT_STREAM=true` | jedes Event als strukturierter JSON-Log auf stdout (msg `audit-event`) |
| `GSSH_AUDIT_WEBHOOK_URL` | POST der Events als JSON-Array an den Webhook |
| `GSSH_AUDIT_STREAM_INTERVAL` | Poll-Intervall (Go-Duration, Default `10s`) |

## Build

- `make web` — `npm ci` + Angular-Build nach `web/dist` (wird eingebettet).
- `make web-test` — Frontend-Unit-Tests (vitest, headless).
- `make web-api` — API-Client aus `api/openapi.yaml` regenerieren.
- Ohne Web-Build funktioniert das Go-Binary vollständig; `/` antwortet dann
  mit 503 („web-ui nicht gebaut“). In `web/dist/` ist nur `.gitkeep`
  versioniert, damit `go:embed` immer baut.
- Docker: eigene Node-Stage im `Dockerfile` baut die UI; das Release-Image
  enthält sie damit immer.
- CI: Job `web-build` (Install, vitest, Produktions-Build) läuft auf PR und
  `main`; Frontend ist vom Go-Coverage-Gate ausgenommen (Plan Phase 0).

## Entwicklung

```sh
cd web
npm ci
npx ng serve --proxy-config proxy.conf.json   # API-Proxy auf laufenden gssh-server
```

`proxy.conf.json` leitet `/v1` an `http://localhost:8080` weiter, damit
Login und API-Calls gegen einen lokal laufenden `gssh-server` funktionieren.
