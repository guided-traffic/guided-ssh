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

- Kompletter Durchstich im Wegwerf-Cluster (`test/e2e`, Build-Tag `e2e`,
  `make e2e`): produktives Helm-Chart, **Dex + GLAuth** als IdP (Dex-Static-
  Passwords können keine Gruppen — GLAuth liefert sie über den LDAP-Connector;
  Offboarding = ConfigMap-Änderung), simuliertes GitLab-OIDC (statisches
  Discovery/JWKS hinter nginx, Job-Tokens signiert die Suite), zwei
  sshd-Testhosts als Pods (`role=web`/`role=db`) und ein Workstation-Pod
  („Mensch": echtes `gssh`-Binary + `ssh-agent` + openssh-Client).
- Szenarien (in dieser Reihenfolge, gemeinsame Umgebung):
  1. **SSO-Login** — `gssh login --device`, die Suite „klickt" den
     Dex-Device-Flow (LDAP-Login), danach transparentes `ssh` mit striktem
     Host-Zertifikats-Check (`@cert-authority`); fail-closed für root und
     nicht gegrantete Hosts.
  2. **Grant-Änderung** — `gssh-admin apply` ergänzt/entfernt einen Grant,
     Wirkung auf der Host-ACL innerhalb der Cache-TTL (30 s im Test).
  3. **CI + Ansible** — simuliertes GitLab-Job-Token → `gssh ci-login`
     (echtes Binary, eigener ssh-agent) → `ansible-playbook` provisioniert
     den Testhost über den Agenten; KeyID `ci:<projekt>:<pipeline>:<job>`,
     403 für unprotected refs. Ohne installiertes ansible deckt ein
     Go-SSH-Fallback denselben Zertifikatspfad ab.
  4. **Host-Rotation** — `GSSH_HOST_CERT_VALIDITY=3m` macht die
     2/3-Erneuerung beobachtbar; Serial wechselt, sshd wird per
     `reload_command` neu geladen, Logins laufen weiter.
  5. **Chaos** — API auf 0 skaliert: bestehende SSH-Session lebt weiter,
     Agent-Cache trägt neue Logins bis zur TTL, danach fail-closed; nach
     Wiederanlauf normal.
  6. **Offboarding** — alice verliert die IdP-Gruppe: keine neue Ausstellung
     (403), Host-ACL verweigert das noch gültige Zertifikat innerhalb der
     Cache-TTL.
  7. **Audit** — Ausstellungen (Mensch + CI mit Pipeline-Zuordnung),
     Enrollments und Grant-Änderungen sind über `/v1/admin/audit/export`
     (JSON + CSV) abfragbar. Session-/sudo-Events sind hier nicht abgedeckt
     (Opt-in-Feature; PAM-Verhalten in den Phase-9-Tests verifiziert).
- Läuft pro PR und auf main (Job `e2e-tests` in `release.yml`,
  self-hosted Runner, kind); Releases sind darauf gegated.
  Lokal: `make e2e` (Schalter `E2E_KEEP`, `E2E_SKIP_BUILD`, `E2E_CLUSTER`).

### Last & Chaos (Phase 13)

- **Lasttest Sign-Endpoint** (`test/load`, Build-Tag `loadtest`,
  `make loadtest`): echte API + Postgres (Testcontainer) + OIDC-Verifier,
  ohne Rate-Limiting. **Ziel: ≥ 50 Zertifikate/s** über 15 s mit 16
  parallelen Clients, fehlerfrei; p50/p95 werden geloggt.
  Referenzmessung (Apple-Silicon-Entwicklungsrechner): ~1770 Zert/s,
  p95 11 ms — das Ziel hat reichlich Marge. CI: Job `load-test` auf main
  (nicht release-blockierend — geteilte Runner machen Durchsatz-Gates flaky).
- **Chaos-Fall API-Ausfall**: Szenario 5 der E2E-Suite (siehe oben) plus
  `TestPrincipalsCacheUndFailClosed` (Unit, `internal/agentd`).

## Abgrenzung

| Ebene | Scope | Abhängigkeiten | Wann |
|---|---|---|---|
| Unit | einzelnes Paket, reine Logik | keine | jeder Push/PR |
| Integration | Modul gegen echtes Nachbarsystem | Docker (Testcontainer) | jeder Push/PR (self-hosted) |
| E2E | Gesamtsystem im Cluster | Docker, kind, kubectl, Helm | jeder Push/PR (self-hosted); Releases gegated |
| Last | Sign-Endpoint-Durchsatz | Docker (Testcontainer) | main (informativ) + lokal |

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
| 13 QS/Release | Konsolidierte Suite grün (Unit + Integration + E2E in `release.yml`); Lasttest Sign-Endpoint ≥ 50 Zert/s (`test/load`, gemessen ~1770/s); Chaos: API down ⇒ bestehende Sessions leben, Agent-Cache bis TTL, danach fail-closed (E2E-Szenario 5) |

## Pflege

- Neue Features nur mit Tests auf der passenden Ebene; Bugfixes mit Regressionstest.
- Diese Datei wird pro Phase aktualisiert (Testfälle konkretisieren, Erledigtes streichen).
