# ADR-020: Web-UI — Rollenmodell, generierter API-Client, Audit-Export/-Streaming

## Status

Akzeptiert (Phase 8)

## Kontext

Phase 8 fordert eine read-mostly Web-UI (Angular, ADR-003) mit Rollen aus
Token-Claims, einen aus einer OpenAPI-Spec generierten API-Client, eine
filterbare Audit-Ansicht mit Export sowie SIEM-Anbindung. Offene Fragen:
Wie werden Rollen abgebildet, wie kommt die SPA an ihre OIDC-Konfiguration,
wie wird der Client generiert (ohne Java-Toolchain auf den Runnern), und wie
werden Audit-Events zuverlässig an externe Systeme gestreamt?

## Entscheidung

1. **Drei Rollen als IdP-Gruppen, serverseitig durchgesetzt.**
   `GSSH_ADMIN_GROUP` (Mutationen), `GSSH_AUDITOR_GROUP` (Audit lesen +
   exportieren), `GSSH_READONLY_GROUP` (Ressourcen lesen); admin ⊃ auditor ⊃
   readonly. Leere Gruppe ⇒ Rolle wird an niemanden vergeben (fail-closed);
   alle drei leer ⇒ Admin-API bleibt 503. Die UI wertet dieselben Gruppen nur
   für die Anzeige aus (`/v1/ui/config` liefert die Gruppennamen).

2. **Bootstrap über `GET /v1/ui/config` (öffentlich).** Die SPA lädt Issuer,
   Client-ID (`GSSH_UI_OIDC_CLIENT_ID`, Default `GSSH_OIDC_CLIENT_ID`) und
   Rollen-Gruppen zur Laufzeit — ein Build für alle Umgebungen, keine
   Secrets im Frontend. Login via Authorization Code + PKCE
   (`angular-auth-oidc-client`); als Bearer-Token dient das ID-Token,
   konsistent zu `gssh-admin` und dem Sign-Endpoint.

3. **API-Client aus `api/openapi.yaml` mit `ng-openapi-gen`.** Die Spec ist
   handgepflegt und Single Source of Truth der REST-API; der Generator ist
   reines Node-Tooling (kein Java wie openapi-generator). Der generierte
   Code ist eingecheckt (reproduzierbarer Build), Regenerierung via
   `make web-api`.

4. **Embedding mit Platzhalter.** `web/embed.go` bettet `web/dist` ein; nur
   `.gitkeep` ist versioniert. Ohne Angular-Build kompiliert und läuft der
   Server vollständig, `/` antwortet 503. Der SPA-Handler fällt für
   Client-Routen auf `index.html` zurück, `/v1/…` nie; gehashte Assets
   werden immutable gecacht. Das Docker-Image baut die UI in einer eigenen
   Node-Stage und enthält sie immer.

5. **Audit-Export und -Streaming getrennt.** Export ist ein Pull
   (`GET /v1/admin/audit/export`, CSV/JSON, gedeckelt auf 100 000 Zeilen,
   Rolle Auditor). Streaming ist ein Poller (`internal/auditstream`), der nur
   committete Events ab Serverstart emittiert: als strukturierte JSON-Logs
   auf stdout (`GSSH_AUDIT_STREAM=true`) und optional als Batch-POST an
   `GSSH_AUDIT_WEBHOOK_URL` — best-effort, die append-only Audit-Tabelle
   bleibt Source of Truth. Bewusst kein Hook in die Schreib-Transaktionen:
   der Poller sieht nur committete Events und ein Webhook-Ausfall kann keine
   Zertifikatsausstellung verzögern.

## Konsequenzen

- Rollen-Änderungen wirken ohne Re-Deployment (IdP-Gruppenpflege).
- Neue Endpoints erfordern Pflege der OpenAPI-Spec (bewusst: Spec-first).
- Der Streaming-Cursor lebt im Prozess; nach Neustart werden Alt-Events
  nicht nachgeliefert (SIEM erhält Lücken nur bei Downtime — akzeptiert,
  Export deckt Nachforderungen ab).
- `service_account.updated` ergänzt die Audit-Events: der Not-Aus pro
  Projekt ist einem Actor zuordenbar.
