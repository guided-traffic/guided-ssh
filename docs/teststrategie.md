# Teststrategie

Gilt für allen Go-Code (Backend, CLI `gssh`, `gssh-admin`, Host-Agent `gssh-agentd`).
Das Angular-Frontend ist vom Coverage-Gate ausgenommen; seine Logik bleibt bewusst dünn
(read-mostly UI), API-Verhalten wird backendseitig getestet.

## Coverage-Gate

- **≥ 80 % Gesamtabdeckung** über alle Go-Pakete, gemessen mit
  `go test -coverpkg=./... ./...` (zählt auch Pakete ohne eigene Tests).
- Durchsetzung: `make cover` → `hack/coverage.sh` — bricht Build lokal und in CI ab.
- Schwelle zentral im Makefile (`COVERAGE_MIN`); Absenken nur mit Begründung im PR.
- Sobald Integrationstests existieren, zählen sie in die Gesamtabdeckung hinein
  (gleicher `go test`-Lauf auf dem Runner, Build-Tag siehe unten).

## Testebenen

### Unit

- Reine Go-Tests ohne externe Systeme; `go test -race ./...` (`make test`).
- Pflicht für: Zertifikatsbau (Inhalte, Ablaufzeiten), Policy-Engine, Claim-Mapping,
  Grant-Auswertung, Konfigurationsparsing.
- Läuft bei jedem Push/PR, muss < 2 Minuten bleiben.

### Integration (Testcontainer)

- `testcontainers-go`; Kennzeichnung mit Build-Tag `integration`
  (`go test -tags integration ./...`), damit Unit-Läufe ohne Docker funktionieren.
- Container-Abhängigkeiten:
  - **Postgres** — Repository-Layer, Migrationen, Append-only-Trigger (`audit_events`)
  - **Keycloak** — OIDC-Flows, Token-Validierung, Gruppen-Sync
  - **sshd-Host** (Container mit sshd) — Enrollment, `AuthorizedPrincipalsCommand`,
    Login mit Benutzerzertifikat
- Läuft bei jedem Push/PR auf dem self-hosted Runner (Docker vorhanden).

### E2E (kind)

- Kompletter Durchstich im Wegwerf-Cluster: Helm-Deployment, Keycloak, simuliertes
  GitLab-OIDC, zwei Testhosts (Container).
- Szenarien: SSO-Login Mensch, Offboarding, CI-Zertifikat + Ansible-Provisioning,
  Grant-Änderung, Host-Rotation, Audit-Vollständigkeit.
- Läuft nightly und vor Releases (nicht pro PR — zu teuer); Details Phase 13.

## Abgrenzung

| Ebene | Scope | Abhängigkeiten | Wann |
|---|---|---|---|
| Unit | einzelnes Paket, reine Logik | keine | jeder Push/PR |
| Integration | Modul gegen echtes Nachbarsystem | Docker (Testcontainer) | jeder Push/PR (self-hosted) |
| E2E | Gesamtsystem im Cluster | kind, Helm | nightly + Release |

Faustregel: Fehlerlogik und Grenzfälle nach unten drücken (Unit), Verkabelung nach
oben (Integration), Geschäftsszenarien ganz oben (E2E) — kein Szenario doppelt testen.

## Testfälle pro Phase (Kernfälle, Pflege parallel zur Implementierung)

| Phase | Kerntestfälle |
|---|---|
| 1 Datenmodell | Migrationen idempotent; CRUD Repository-Layer; `audit_events`: UPDATE/DELETE schlägt fehl (Trigger + fehlende Grants) |
| 2 Core-CA | Zertifikatsinhalte (Serial, KeyID, Principals, Laufzeit, Extensions); Policy-Verletzungen (Laufzeit, Principals) abgelehnt; Signatur ⇒ Audit-Event + `certificates`-Zeile in einer Transaktion; Key-Rotation: alte + neue CA parallel gültig |
| 3 OIDC | Token abgelaufen/falsche Audience/falscher Issuer/kaputte Signatur ⇒ 401; Claim-Mapping `sub`/`email`/`groups`; Gruppen-Sync entfernt Berechtigung |
| 4 CLI | Login legt Key+Cert nur in Agent (nichts auf Platte); `status`/`logout`; Konfigparsing; Fehlerpfade (API nicht erreichbar) |
| 5 Host-Agent | Enrollment mit gültigem/ungültigem/verbrauchtem Token; Zertifikatserneuerung bei 2/3 Laufzeit; `AuthorizedPrincipalsCommand`: Cache-Hit, Cache-TTL abgelaufen + API down ⇒ fail-closed; sshd-Login E2E im Container |
| 6 Grants | Gruppe×Tag-Auswertung bei Ausstellung und Host-ACL; additive Grants (kein deny); YAML-Import idempotent; Gruppe entfernt ⇒ Login schlägt fehl |
| 7 GitLab-CI | GitLab-Token-Claims (`project_path`, `ref_protected`, …) auf CI-Grants gemappt; Laufzeit ≤ 1 h erzwungen; KeyID enthält Pipeline/Job; simuliertes GitLab-OIDC ⇒ Zertifikat ⇒ Ansible-Ping |
| 8 Web-UI | API-Verträge via OpenAPI-generierte Clients; Rollen aus Claims (Admin/Auditor/Read-only); Audit-Filter; Admin-Änderung erzeugt Audit-Event |
| 9 Session-Audit | Session-Start/-Ende und sudo-Events gemeldet; Spool puffert bei API-Ausfall; Korrelation über Cert-Serial |
| 10 Härtung | Rate-Limit greift; Replay/Audience-Confusion/Clock-Skew-Negativtests; Fuzzing Sign-Endpoints; KMS-Signer gegen SoftHSM |
| 11 Helm | `helm test`/chart-testing; Migrations-Job mit Lock; Probes; Deployment mit `existingSecret` |
| 12 GitOps | HelmRelease-Beispiel installierbar; SOPS-Entschlüsselung; `gssh-admin apply` idempotent aus Repo-Datei |
| 13 QS/Release | Konsolidierte Suite grün; Lasttest Sign-Endpoint (Ziel definieren, z. B. 50 Zerts/s); Chaos: API down ⇒ bestehende Sessions leben, Agent-Cache bis TTL, danach fail-closed |

## Pflege

- Neue Features nur mit Tests auf der passenden Ebene; Bugfixes mit Regressionstest.
- Diese Datei wird pro Phase aktualisiert (Testfälle konkretisieren, Erledigtes streichen).
