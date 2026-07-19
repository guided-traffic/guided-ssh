# ADR-015: OIDC via go-oidc/x-oauth2, Gruppen-Sync über Keycloak-Admin-API

- Status: akzeptiert
- Datum: 2026-07-19

## Kontext

Phase 3 braucht (1) serverseitige Validierung von ID-Tokens (Issuer, Audience,
Signatur via JWKS, Ablauf), (2) CLI-Login-Flows (Authorization Code + PKCE,
Device-Flow als Fallback) und (3) den periodischen Gruppen-Sync vom IdP, damit
Offboarding sofort auf Neuausstellung und Host-ACLs wirkt — laut Plan ohne
SCIM-Server (OIDC-Claims + periodischer Group-Sync).

## Entscheidung

- **Token-Validierung**: `github.com/coreos/go-oidc/v3` (Discovery, JWKS-Cache
  mit automatischem Reload bei unbekannter Key-ID, Standard-Checks). Kein
  Eigenbau der JOSE-Verifikation.
- **CLI-Flows**: `golang.org/x/oauth2` (PKCE via `GenerateVerifier`/
  `S256ChallengeOption`, Device-Flow via `DeviceAuth`/`DeviceAccessToken`).
  Callback-Listener nur auf `127.0.0.1` mit zufälligem Port.
- **Claim-Mapping**: Bei jeder Ausstellung werden Benutzer-Stammdaten und
  Gruppenzugehörigkeiten aus den Token-Claims (`sub`, `email`,
  `preferred_username`, `groups`) in die DB übernommen; Principals sind
  Username + E-Mail. Deaktivierte Benutzer werden abgewiesen und nicht durch
  Login reaktiviert.
- **Gruppen-Sync**: Interface `DirectorySource`; erste Implementierung
  Keycloak-Admin-API (Service-Account mit `view-users`, Client-Credentials).
  Der Sync deaktiviert im IdP entfernte/deaktivierte Benutzer und entzieht
  ihre Gruppen; er legt keine neuen Benutzer an (das passiert beim ersten
  Login). Andere IdPs später über dasselbe Interface.

## Konsequenzen

- Zwei etablierte, schlanke Abhängigkeiten statt eigener JOSE-/OAuth-Logik;
  go-jose kommt transitiv mit und wird in Tests zum Signieren genutzt.
- Offboarding-Latenz = Sync-Intervall (Default 5 m, `GSSH_KC_SYNC_INTERVAL`),
  nicht Token-Laufzeit; zusätzlich prüft jede Ausstellung den Aktiv-Status.
- Keycloak-spezifisch ist nur die `DirectorySource`-Implementierung; Claims-
  Pfad und Sync-Logik sind IdP-neutral. Gruppen-Claims werden um führende
  "/" bereinigt (Keycloak-Pfadnotation).
- Ohne konfigurierten Sync (`GSSH_KC_CLIENT_ID` leer) wirkt Entzug nur über
  Token-Ablauf plus Gruppen-Claims bei Neuausstellung — Warnung im Log.
