# ADR-003: Angular-SPA, eingebettet ins Go-Binary

- Status: akzeptiert
- Datum: 2026-07-19

## Kontext

Web-UI (Hosts, Grants, Audit) ist gefordert, Angular gesetzt. Zu klären war die
Auslieferung: eigenes Frontend-Deployment vs. Auslieferung durch den API-Server.

## Entscheidung

Angular-SPA (Standalone Components, Angular Material) mit OIDC via Authorization
Code + PKCE. Der Produktions-Build wird per `embed.FS` in das Go-Binary eingebettet
und vom API-Server ausgeliefert.

## Konsequenzen

- Ein Container-Image, ein Deployment, kein CORS, gleiche Origin für API und UI.
- CI baut erst Angular, dann Go (Assets müssen beim `go build` vorliegen).
- UI-Version ist immer konsistent zur API-Version.
- Frontend bleibt read-mostly; Logik lebt im Backend und ist dort testbar —
  Frontend ist vom Coverage-Gate ausgenommen.
