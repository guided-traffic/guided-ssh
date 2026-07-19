# ADR-008: REST+JSON; mTLS für Host-Agenten, OIDC für Menschen und CI

- Status: akzeptiert
- Datum: 2026-07-19

## Kontext

Drei Arten von API-Konsumenten mit unterschiedlichem Vertrauensmodell:
Menschen (CLI/Browser), CI-Jobs (GitLab) und Host-Agenten.

## Entscheidung

REST + JSON als einheitlicher API-Stil, beschrieben per OpenAPI-Spec (`api/`,
Single Source of Truth, generierte Clients). Authentifizierung strikt getrennt:

- Menschen: OIDC (Authorization Code + PKCE, Device-Flow als Fallback)
- CI: GitLab-OIDC-`id_token`, validiert gegen GitLab-JWKS
- Host-Agenten: mTLS mit host-gebundenem Client-Zertifikat

## Konsequenzen

- Getrennte Auth-Pfade ⇒ getrennte Angriffsflächen und klare Policy-Zuordnung
  (User-Grants vs. CI-Grants vs. Host-Scope).
- Kein gRPC: einfaches Debugging, UI und CLI nutzen dieselbe API; OpenAPI
  generiert Angular- und Go-Clients.
- mTLS erfordert Zertifikatsrotation für Agenten (Phase 10) — bewusst eingepreist.
