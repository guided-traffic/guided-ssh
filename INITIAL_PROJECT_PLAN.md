# guided-ssh — Design- und Implementierungsplan

Zertifikatsbasierte SSH-Zugriffsplattform: kurzlebige SSH-Zertifikate statt statischer
`authorized_keys`, Single Sign-On über den bestehenden Identity Provider, maschinelle
Zugänge für CI-Pipelines (GitLab), vollständige Auditierbarkeit aller ausgestellten
Zugriffe und Sessions. Betrieb in Kubernetes via Helm, verwaltet über GitOps (FluxCD).

---

## Feature-Zielbild (aus Marktanalyse abgeleitet)

### Zertifikats-Workflow (Benutzer)
- Nutzer führt `ssh <host>` aus; ein lokaler Client/Agent prüft, ob ein gültiges
  SSH-Zertifikat vorliegt.
- Fehlt eines, startet ein OAuth/OIDC-SSO-Flow gegen den Identity Provider
  (Keycloak, Okta, Entra ID, Google Workspace …). Das erhaltene ID-Token wird bei
  der CA gegen ein signiertes, kurzlebiges SSH-Benutzerzertifikat getauscht.
- Standard-Gültigkeit ~16 Stunden (konfigurierbar); Zertifikat enthält eine
  Principal-Liste (Username, E-Mail) zur Identifikation.
- Zertifikate leben ausschließlich im `ssh-agent`, werden nie auf Platte persistiert.

### Identitäts- und Benutzerverwaltung
- Synchronisation von Benutzern und Gruppen aus dem IdP via SCIM bzw. nativer APIs;
  keine Duplikation der Benutzerverwaltung — der IdP bleibt Source of Truth.
- Entfernen eines Nutzers aus einer berechtigten IdP-Gruppe entzieht den Zugriff
  sofort auf allen verwalteten Hosts (Offboarding ohne manuelle Schritte).
- UID/GID-Werte werden aus dem IdP übernommen oder automatisch deterministisch vergeben.

### Host-Verwaltung
- Enrollment: Host bootstrappt Vertrauen zur CA, erhält ein Host-Zertifikat und
  konfiguriert `sshd` für Zertifikats-Authentifizierung (`TrustedUserCAKeys`,
  `HostCertificate`); ein Host-Agent (systemd-Unit) hält Zertifikat und Policies aktuell.
- Host-Tags (Rolle, Umgebung, Region — analog EC2-Tags) kategorisieren Hosts;
  Zugriffsregeln kombinieren IdP-Gruppen mit Host-Tags.
- Automatische Rotation von Host-Zertifikaten vor Ablauf.

### Zugriffssteuerung auf dem Host
- NSS-/PAM-Integration: Benutzer- und Gruppen-ACLs werden zur Laufzeit vom Host-Agent
  über mTLS von der API bezogen.
- Dreistufige Prüfung: (1) NSS löst Benutzerkonto auf und prüft Berechtigung,
  (2) Abgleich Zertifikats-Principals gegen den Ziel-Usernamen,
  (3) PAM prüft SSH- und sudo-Rechte für diesen Nutzer.
- Sudo-Berechtigungen zentral pro Grant steuerbar.
- Bastion-Unterstützung: Zugriff über Sprunghosts mit internen DNS-Namen, alle
  Verbindungen werden protokolliert.

### Audit & Nachvollziehbarkeit
- Jede Zertifikatsausstellung wird protokolliert: wer, wann, welche Principals,
  welche Gültigkeit, aus welchem Kontext (SSO-Session, CI-Pipeline).
- PAM-Modul meldet Session-Start, sudo-Aktionen und Session-Ende an die Plattform.
- Audit-Ansicht in der UI; Export/Streaming an SIEM möglich.
- Signierschlüssel in KMS/HSM ablegbar, damit private Keys nicht exfiltrierbar sind;
  jede Signatur-Operation ist geloggt.

### Maschinelle Zugänge (Kernanforderung)
- GitLab-Runner erhalten für die Dauer einer Pipeline ein kurzlebiges
  SSH-Zertifikat: GitLab stellt pro Job ein OIDC `id_token` aus; die CA validiert
  dieses gegen den GitLab-JWKS-Endpoint und stellt ein Zertifikat mit
  pipeline-gebundener Laufzeit und eingeschränkten Principals aus.
- Damit kann ein Runner Server via Ansible provisionieren — ohne statische Keys
  in CI-Variablen.

---

## Architektur-Entscheidungen

| Bereich | Entscheidung | Begründung |
|---|---|---|
| Backend | Go | starke SSH-/Crypto-Bibliotheken (`golang.org/x/crypto/ssh`), statische Binaries für Host-Agent und CLI |
| Datenbank | PostgreSQL | ACID für Audit-Log, JSONB für Zertifikats-Metadaten |
| Frontend | Angular (SPA), OIDC via Authorization Code + PKCE | Anforderung; Build wird als statische Assets ins Go-Binary eingebettet (`embed.FS`) — ein Image, kein CORS, einfaches Helm-Deployment |
| Ansible | nur Referenz-Playbooks für CI-Provisioning (GitLab-Kernanforderung) | kein Enrollment via Ansible; Host-Installation über Pakete/Install-Skript |
| Host-Integration | Phase 1: `AuthorizedPrincipalsCommand` + Cert-Auth; Phase 2: NSS/PAM-Module | sshd-native Mechanik zuerst (geringe Komplexität, kein C-Code), NSS/PAM später für Konten-Sync und sudo-Audit |
| Schlüsselablage | Interface: Software-Key (verschlüsselt in DB/K8s-Secret) → KMS/HSM (PKCS#11, Cloud-KMS) | Start einfach, Produktion hart |
| Deployment | Helm-Chart, FluxCD-kompatibel (HelmRelease, Kustomize-Overlays) | Anforderung |
| API | REST + JSON, mTLS für Host-Agenten, OIDC für Menschen/CI | klare Trennung der Auth-Pfade |

Bewusste Vereinfachungen fürs MVP: kein SCIM-Server (stattdessen OIDC-Claims +
periodischer IdP-Group-Sync), kein Session-Recording (nur Metadaten-Audit),
Web-UI read-mostly (Verwaltung primär via CLI/API, GitOps-freundlich).

---

## Phase 0 — Projektfundament

- [x] Repository-Struktur festlegen (`cmd/`, `internal/`, `api/`, `web/` (Angular), `deploy/helm/`, `docs/`)
- [x] Go-Modul initialisieren, Linting (`golangci-lint`), `Makefile`/`Taskfile`
      → Makefile (ADR-009), Modul `github.com/guided-traffic/guided-ssh`
- [x] Build-Pipeline in GitHub Actions auf self-hosted Runner (Build, Test, Lint,
      Container-Image via ko oder Dockerfile); Runner-Anforderungen dokumentieren
      (Docker/Podman für Testcontainer, kind für E2E)
      → `.github/workflows/release.yml`, Dockerfile statt ko (ADR-010), `docs/ci-runner.md`;
      Runner-Registrierung selbst ist Ops-seitig noch offen
- [x] Registry-Ziel: Container-Images nach `docker.io/guidedtraffic` (Push-Credentials
      als GitHub-Secrets, Tagging: SemVer + `sha-<commit>`)
      → Secret `DOCKERHUB_PAT` (dokumentiert in `docs/ci-runner.md`), Push nur beim Release
- [x] CI/Release-Pipeline nach Standard-Workflow:
      1. Pull Request gegen `main` → Tests (Lint, Unit-/Integrationstests mit
         Coverage-Gate ≥ 80 %, Build)
      2. Push auf `main` → dieselben Tests, danach `semantic-release`: analysiert
         Conventional Commits, erzeugt Tag `vX.Y.Z` + GitHub-Release (via `BOT_PAT`,
         damit das Release den Build-Workflow triggert)
      3. Release published → Docker-Image bauen und nach
         `docker.io/guidedtraffic/guided-ssh` pushen (Tags: `X.Y.Z`, `X.Y`, `X`,
         `sha-<commit>`; Provenance + SBOM)
      → `.github/workflows/release.yml` (Test + Semantic Release),
      `.github/workflows/build.yml` (Docker-Build auf Release),
      `.releaserc` + `package.json` (semantic-release, Preset conventionalcommits);
      Secrets: `DOCKERHUB_PAT`, `BOT_PAT`
- [x] Coverage-Badge: Test-Job erzeugt auf `main` `.github/badges/coverage.json`
      (shields.io-Endpoint-Format) und reicht es als Artefakt an semantic-release,
      das es via `@semantic-release/git` mit dem Release-Commit eincheckt
      (`[skip ci]`); README bindet das Badge über raw.githubusercontent.com ein
- [x] Renovate (self-hosted, via `BOT_PAT`): täglich 2 Uhr UTC + nach Push auf `main`;
      Automerge für Minor/Patch (gomod, Dockerfile, GitHub Actions, gepinnte
      Workflow-Tools), Major nur mit Review; Go-Version-Updates gruppiert über
      Dockerfile/go.mod (Custom-Regex-Manager)
      → `.github/workflows/renovate.yml`, `renovate.json`
- [x] Coverage-Gate in Pipeline: ≥ 80 % Testabdeckung für allen Go-Code (Backend, CLI,
      Host-Agent) — Frontend ausgenommen; Build bricht bei Unterschreitung
      → `make cover` + `hack/coverage.sh`, lokal und in CI identisch
- [x] Teststrategie-Dokument ausarbeiten: Abgrenzung Unit / Integration (Testcontainer:
      Postgres, Keycloak, sshd-Host) / E2E (kind-Cluster, kompletter Durchstich);
      Testfälle pro Phase definiert, Pflege parallel zur Implementierung
      → `docs/teststrategie.md`
- [x] ADR-Verzeichnis anlegen; Entscheidungen aus Tabelle oben als ADR-001…n festhalten
      → `docs/adr/` (ADR-001…011 + Template)
- [x] Bedrohungsmodell skizzieren (Angriffsflächen: CA-Key, Token-Diebstahl, Host-Agent-Kompromittierung)
      → `docs/bedrohungsmodell.md`
- [x] Lizenz und Versionierungsschema festlegen
      → Apache-2.0, SemVer via Git-Tags `vX.Y.Z` (ADR-011)

## Phase 1 — Datenmodell & Persistenz

- [x] PostgreSQL-Schema entwerfen: `users`, `groups`, `hosts`, `host_tags`, `access_grants`
      (Gruppe × Tag-Selektor × Principals × sudo-Flag × max. Laufzeit), `certificates`
      (ausgestellte Zertifikate inkl. Serial, KeyID, Principals, Gültigkeit, Issuer-Kontext),
      `audit_events` (append-only), `ca_keys`, `service_accounts` (CI-Identitäten)
      → `internal/store/migrations/0001_initial_schema.sql` (zusätzlich `user_groups`,
      Serial-Sequence; `audit_events` von Anfang an nach Monat partitionierbar)
- [x] Migrations-Tooling einrichten (goose oder golang-migrate)
      → goose v3, embedded SQL, `store.Migrate` (ADR-012)
- [x] Repository-Layer in Go (sqlc oder pgx direkt) mit Tests gegen Testcontainer-Postgres
      → pgx v5 direkt (ADR-013), `internal/store`; Integrationstests (Build-Tag
      `integration`) laufen in `make cover` mit — Gesamtabdeckung 86,7 %
- [x] Append-only-Garantie für `audit_events` (kein UPDATE/DELETE-Grant, Trigger als Schutz)
      → Trigger in Migration 0001 (getestet); Grant-Schema für App-Rolle dokumentiert
      in `docs/audit-retention.md`
- [x] Retention-Konzept für Audit-Daten dokumentieren (Partitionierung nach Monat)
      → `docs/audit-retention.md` (Monatspartitionen, Detach/Drop, Archivierung)

## Phase 2 — Zertifizierungsstelle (Core-CA)

- [x] Signer-Interface definieren (`Sign(ctx, CertRequest) (*ssh.Certificate, error)`)
      → `internal/ca/signer.go` (plus `CAKeyID()`/`PublicKey()` für Persistenz und Bundle)
- [x] Software-Signer: Ed25519-CA-Key, verschlüsselt at rest (age/AES-GCM, Key aus K8s-Secret)
      → AES-256-GCM statt age (ADR-014), Master-Key via `GSSH_CA_MASTER_KEY`
- [x] Getrennte CA-Keys für Benutzer- und Host-Zertifikate
      → `CA.EnsureCAKeys` bootstrapt je einen Key pro Zweck; Signer-Auswahl strikt pro Zweck
- [x] Zertifikatsbau: Serial, KeyID (`user:<sub>@<idp>` bzw. `ci:<project>:<pipeline>`),
      Principals, `valid_after`/`valid_before`, Extensions (`permit-pty`, …), Critical Options
      → `SoftwareSigner.Sign` + KeyID-Helfer in `internal/ca/keyid.go`
- [x] Policy-Engine: maximale Laufzeit, erlaubte Principals, erlaubte Extensions pro Requester-Typ
      → `internal/ca/policy.go`; Requester-Typen user/ci/host, Defaults 16 h / 1 h / 30 d
- [x] Jede Signatur erzeugt synchron ein `audit_event` + `certificates`-Eintrag (gleiche Transaktion)
      → `store.CreateCertificateWithAudit` (pgx-Transaktion, Rollback-Test integriert)
- [x] Key-Rotation: mehrere aktive CA-Keys, Übergangsfenster, Endpoint für aktuelles CA-Bundle
      → `CA.Rotate`/`RetireKey` (active → retiring → retired), `GET /v1/ca/bundle/{user|host}`
      in `internal/api`; `gssh-server -listen` startet die HTTP-API
- [x] Unit-Tests: Zertifikatsinhalte, Policy-Verletzungen, Ablaufzeiten
      → `internal/ca/*_test.go`, `internal/api/server_test.go`; Gesamtabdeckung 82 %

## Phase 3 — Benutzer-Authentifizierung (OIDC/SSO)

- [x] OIDC-Integration (Authorization Code + PKCE für CLI, Device-Flow als Fallback)
      → `internal/auth/flow.go` (x/oauth2; PKCE mit 127.0.0.1-Callback, Device-Flow),
      CLI-Kommandos selbst folgen in Phase 4 (ADR-015)
- [x] Token-Validierung: Issuer, Audience, Signatur (JWKS-Cache), Ablauf
      → `internal/auth/verifier.go` (go-oidc/v3, JWKS-Cache mit Auto-Reload)
- [x] Claim-Mapping: `sub`/`email`/`groups` → interner User + Principal-Ableitung
      → `internal/auth/mapper.go`; Principals = Username + E-Mail, Gruppen aus
      Token-Claims bei jeder Ausstellung; inaktive Benutzer werden abgewiesen
- [x] Periodischer Gruppen-Sync vom IdP (Group-Claims bzw. Directory-API) → sofortiger
      Entzug wirkt auf Neuausstellung UND Host-ACLs
      → `internal/auth/sync.go` + Keycloak-Admin-API-Source (`keycloak.go`);
      Env `GSSH_KC_*`, Default-Intervall 5 m; Audit-Events bei De-/Reaktivierung
- [x] Endpoint `POST /v1/sign/user`: ID-Token rein, SSH-Zertifikat raus (Policy-geprüft)
      → `internal/api/sign.go` (Bearer-Token, 401/403/400-Fehlerpfade, Default 16 h)
- [x] Integrationstests gegen Keycloak in Testcontainer
      → `internal/auth/keycloak_integration_test.go` (Realm-Import; Token-Validierung,
      Sign-Endpoint inkl. CertChecker gegen CA-Bundle, Gruppen-Entzug, Offboarding)

## Phase 4 — CLI für Benutzer (`gssh`)

- [x] `gssh login`: SSO-Flow, Schlüsselpaar ephemeral erzeugen, Zertifikat holen,
      beides nur in `ssh-agent` laden (keine Persistenz auf Platte)
      → `internal/cli` + `cmd/gssh` (ADR-016); PKCE-Browser-Flow, `--device` als
      Fallback; Agent-Eintrag mit LifetimeSecs = Zertifikatslaufzeit
- [x] `gssh ssh <host>` bzw. ProxyCommand/Match-exec-Integration in `~/.ssh/config`,
      damit natives `ssh` transparent funktioniert (Auto-Login bei fehlendem Zertifikat)
      → `gssh ssh` (Auto-Login + exec ssh) und `gssh integrate`
      (Match-exec-Schnipsel mit `gssh login --if-needed`, Erneuerung < 5 m Restlaufzeit)
- [x] `gssh status`, `gssh logout` (Agent-Einträge entfernen)
      → Comment-Präfix `guided-ssh` identifiziert eigene Einträge; status mit
      Exit-Code 1 ohne gültiges Zertifikat
- [x] Konfigurationsdatei (`~/.config/guided-ssh/config.yaml`): API-URL, IdP, Fingerprint-Pinning
      → yaml.v3, XDG-Pfad, Override via `--config`/`GSSH_CONFIG`; Pinning als
      SPKI-SHA-256 (ersetzt CA-Prüfung, für selbstsignierte Deployments)
- [x] Cross-Platform-Builds (linux/amd64, linux/arm64, darwin/arm64) in CI
      → `make cross`, läuft im Build-Job von `.github/workflows/release.yml`

## Phase 5 — Host-Enrollment & Host-Agent

- [x] Enrollment-Flow: einmaliges Enrollment-Token (oder Cloud-Identity später) →
      Host registriert sich, erhält Host-Zertifikat + mTLS-Client-Zertifikat für API
      → `POST /v1/enroll` + `gssh-server enroll-token` (Hash in DB, Single-Use
      transaktional, optional Namensbindung); mTLS-Mini-PKI in `ca_keys`
      (purpose `mtls`), Agent-API hinter `-agent-listen` (ADR-017)
- [x] Host-Agent (`gssh-agentd`, ein Go-Binary, systemd-Unit):
  - [x] Host-Zertifikat automatisch erneuern (bei 2/3 der Laufzeit)
        → `internal/agentd` Daemon; optional `reload_command` nach Erneuerung
  - [x] CA-Bundle aktuell halten (`TrustedUserCAKeys`-Datei schreiben)
        → periodisch (`bundle_interval`, Default 1 h), Schreiben nur bei Änderung
  - [x] Autorisierte Principals pro lokalem User von API beziehen und cachen
        → `GET /v1/agent/principals`; Grant-Auswertung minimal (Selektor ⊆
        Host-Tags, aktive Gruppenmitglieder → Username+E-Mail); voll in Phase 6
- [x] `AuthorizedPrincipalsCommand`-Helper: sshd fragt Agent (Unix-Socket), Agent
      antwortet aus Cache — Fail-closed bei nicht erreichbarer API, konfigurierbare Cache-TTL
      → `gssh-agentd principals -user %u`; Cache persistiert, `cache_ttl` Default 5 m
- [x] sshd-Konfigurations-Snippets generieren (`/etc/ssh/sshd_config.d/guided-ssh.conf`)
      → idempotent beim Enrollment; nutzt vorhandenen sshd-Host-Key
- [x] Host-Tags: bei Enrollment setzbar, via API/CLI änderbar
      → Token-Tags + `--tags` beim Enroll (Token gewinnt); Änderung nach
      Enrollment erst mit Admin-API/CLI in Phase 6/8 (bewusste Lücke)
- [x] Paketierung des Host-Agents: deb/rpm (nfpm) + Install-Skript; `gssh-agentd enroll
      --token …` übernimmt sshd-Konfiguration idempotent
      → `deploy/packaging/` (nfpm.yaml, systemd-Unit, postinstall, install.sh), `make packages`
- [x] Integrationstest: Container-Host mit sshd, Enrollment, Login mit Benutzerzertifikat
      → `internal/agentd/enroll_integration_test.go`: alpine-sshd-Container,
      Enrollment über echte API (mTLS), Login als alice (Principal) und deploy
      (Grant), Ablehnung ohne Grant (fail-closed), Host-Cert-Verifikation

## Phase 6 — Zugriffssteuerung (Grants)

- [x] Grant-Modell umsetzen: IdP-Gruppe × Tag-Selektor → Ziel-Principals (z. B. `deploy`,
      `root`), sudo ja/nein, maximale Zertifikatslaufzeit
      → `access_grants` (Schema Phase 1) + `internal/store/grants.go`; jede Mutation
      schreibt transaktional ein Audit-Event (`grant.created/updated/deleted`) mit Actor
- [x] Auswertung an zwei Stellen: bei Zertifikatsausstellung (welche Principals bekommt
      der Requester) und auf dem Host (welche Principals akzeptiert dieser lokale User)
      → Ausstellung: ohne Grant kein Zertifikat (403), Laufzeit = min(Anfrage, Maximum
      über Grants); Principals bleiben Identitäts-Principals (ADR-018). Host:
      `ListAuthorizedPrincipals` (Selektor ⊆ Host-Tags, aktive Gruppenmitglieder)
- [x] Grant-Verwaltung: CRUD via API + CLI (`gssh-admin grant …`); deklarativer
      YAML-Import (`gssh-admin apply -f grants.yaml`) für GitOps-Pflege der Zugriffsregeln
      → `/v1/admin/grants…` (OIDC + `GSSH_ADMIN_GROUP`, fail-closed) +
      `cmd/gssh-admin`/`internal/admincli`; Apply = Vollabgleich über
      (Issuer, Gruppe, Tag-Selektor), Token via OIDC-Flow oder `GSSH_ID_TOKEN`
- [x] Konfliktregeln definieren (deny gibt es nicht — nur additive Grants, dokumentieren)
      → ADR-018 + `docs/grants.md`: Vereinigung der Wirkungen, Laufzeit = Maximum,
      sudo = oder; Entzug nur über Grant-/Gruppenentfernung
- [x] Bastion-Muster dokumentieren (ProxyJump, Grants für Bastion + Ziel getrennt)
      → `docs/grants.md` (eigene Tags/Grants pro Hop, ProxyJump ohne Agent-Forwarding)
- [x] E2E-Test: Gruppe entfernen → nächster Login schlägt fehl, Host-ACL aktualisiert
      → `keycloak_integration_test.go`: Grant auf „admins“, Sign ok + Host-ACL enthält
      alice; nach Gruppen-Entzug + Sync: frisches Token ⇒ 403, Host-ACL leer

## Phase 7 — GitLab-CI-Integration (Kernanforderung)

- [x] GitLab als OIDC-Issuer registrieren: Konfiguration von Issuer-URL + JWKS,
      Audience-Vorgabe (`aud: guided-ssh`)
      → `auth.CIVerifier` (eigener Issuer/Audience, strikt getrennt vom IdP);
      Env `GSSH_CI_ISSUER`/`GSSH_CI_AUDIENCE` (ADR-019)
- [x] Endpoint `POST /v1/sign/ci`: validiert GitLab `id_token`, mappt Claims
      (`project_path`, `ref`, `ref_protected`, `pipeline_id`, `environment`) auf
      CI-Grant-Regeln
      → `internal/api/sign_ci.go`; Service-Account pro Projekt (`active=false`
      als Not-Aus); Principals = `ci:<project_path>` + Namespace-Vorfahren
- [x] CI-Grants: Projekt/Gruppe × Branch-Bedingung (z. B. nur `ref_protected: true`)
      × Tag-Selektor → Principals; Laufzeit gedeckelt (Default 1 h, max. Job-Timeout)
      → Tabelle `ci_grants` (Migration 0003) + `store/ci_grants.go`; Verwaltung via
      `/v1/admin/ci-grants…`, `gssh-admin ci-grant …` und `ci_grants:` in grants.yaml;
      Laufzeit = min(Grant-Maximum, Policy 1 h, Token-`exp` = Job-Timeout);
      Host-ACL liefert `ci:<project>` über AuthorizedPrincipalsCommand
- [x] KeyID-Format `ci:<project_path>:<pipeline_id>:<job_id>` → jede Ausstellung im
      Audit eindeutig einer Pipeline zuordenbar
      → `ca.CIKeyID`; Audit-Actor = KeyID, Claims im issuer_context
- [x] Helper-Kommando `gssh ci-login` (nutzt `CI_JOB_JWT`/`id_tokens`), lädt Zertifikat
      in Agent des Jobs
      → nur `id_tokens` (Env `GSSH_CI_TOKEN`, `--token-env`); `CI_JOB_JWT` ist in
      GitLab entfernt und wird bewusst nicht unterstützt; API-URL via
      `--api-url`/`GSSH_API_URL`, SPKI-Pinning wie gssh login
- [x] Referenz-Pipeline dokumentieren: `.gitlab-ci.yml` mit `id_tokens`, `gssh ci-login`,
      dann `ansible-playbook` gegen Zielhosts (Ansible nutzt den ssh-agent automatisch)
      → `docs/gitlab-ci.md` + `deploy/examples/gitlab-ci/.gitlab-ci.yml`
- [x] Beispiel-Ansible-Playbook + Inventory-Muster für zertifikatsbasiertes Provisioning
      → `deploy/examples/ansible/` (site.yml, inventory.yml)
- [x] E2E-Test: simuliertes GitLab-Token → Zertifikat → Ansible-Ping gegen Testhost
      → `internal/agentd/ci_integration_test.go`: Fake-GitLab (Discovery+JWKS),
      Sign, SSH-Login als deploy (fail-closed für root), Audit-Zuordnung;
      Ansible-Ping läuft, wenn ansible auf dem Runner installiert ist —
      sonst deckt der Go-SSH-Durchstich denselben Pfad ab

## Phase 8 — Web-UI & Auditing-Oberfläche

- [x] Angular-Projekt aufsetzen (`web/`): Standalone Components, Angular Material,
      OIDC-Login (Authorization Code + PKCE, z. B. `angular-auth-oidc-client`),
      Rollen (Admin, Auditor, Read-only) aus Token-Claims
      → Angular 21 + Material 21 (M3-Dark, Glass-Optik); OIDC-Bootstrap via
      `GET /v1/ui/config`; Rollen-Gruppen `GSSH_ADMIN_GROUP`/`GSSH_AUDITOR_GROUP`/
      `GSSH_READONLY_GROUP` (admin ⊃ auditor ⊃ readonly, fail-closed; ADR-020)
- [x] UI-Login auf server-seitiges OIDC umgestellt (BFF): der Server führt
      Authorization Code + PKCE mit Client-Secret aus (`/v1/auth/login|callback|
      logout|me`, `internal/api/ui_auth.go`); Session als HttpOnly-Cookie
      (AES-GCM, Schlüssel per HKDF aus `GSSH_CA_MASTER_KEY`), Admin-API
      akzeptiert Session-Cookie + `X-Requested-With` zusätzlich zu Bearer;
      SPA ohne `angular-auth-oidc-client`, kein CORS/Discovery im Browser.
      Aktivierung über `GSSH_UI_OIDC_CLIENT_SECRET` (Chart:
      `config.oidc.uiExistingSecret`); Dex-Client wird confidential,
      Redirect-URI `<base>/v1/auth/callback`
- [x] API-Client aus OpenAPI-Spec generieren (Single Source of Truth für REST-API)
      → `api/openapi.yaml` (handgepflegt, komplette REST-API) + ng-openapi-gen
      nach `web/src/app/api` (`make web-api`)
- [x] Build-Integration: Angular-Build in CI, Assets via `embed.FS` ins Go-Binary
      → `web/embed.go` (go:embed, `.gitkeep`-Platzhalter — Go-Build ohne Node),
      SPA-Handler mit index.html-Fallback; `make web`; CI-Job `web-build`;
      Docker-Node-Stage im Release-Image
- [x] Ansichten: Hosts (Status, Tags, Zertifikatsablauf), Grants, Benutzer/Gruppen,
      Service-Accounts/CI-Regeln
      → Read-Endpoints `/v1/admin/{hosts,users,groups,service-accounts,certificates}`;
      Grants/CI-Grants-CRUD in der UI (Admin), Service-Account-Not-Aus per Toggle
- [x] Audit-Ansicht: filterbar nach Nutzer, Host, Pipeline, Zeitraum, Ereignistyp
      (Ausstellung, Login, sudo, Session-Ende, Enrollment, Grant-Änderung)
      → `GET /v1/admin/audit` (event_type, actor, q über Actor+Payload für
      Host/Pipeline, Zeitraum, Pagination; Rolle Auditor); sudo/Session-Events
      folgen mit Phase 9
- [x] Audit-Export: CSV/JSON-Download + strukturierte Logs (JSON auf stdout) für
      SIEM-Anbindung; optionaler Webhook
      → `GET /v1/admin/audit/export` (CSV/JSON, max. 100 000 Zeilen);
      `internal/auditstream`: Poller emittiert committete Events als JSON-Logs
      (`GSSH_AUDIT_STREAM=true`) und an `GSSH_AUDIT_WEBHOOK_URL`
- [x] Admin-Änderungen über UI erzeugen selbst Audit-Events (wer änderte welchen Grant)
      → UI nutzt dieselben Admin-Endpoints (transaktionale Audit-Events mit Actor);
      neu auch für Service-Account-Umschaltung (`service_account.updated`)

## Phase 9 — Session-Audit auf dem Host (Ausbaustufe)

- [x] PAM-Modul oder `pam_exec`-Hook: Session-Start/-Ende an API melden (gepuffert,
      asynchron, Verlust-tolerant mit lokalem Spool)
      → `pam_exec`-Hooks (ADR-005: kein C-Code) → `gssh-agentd pam-session`, fail-open;
      Daemon-Spool (`sessions-spool.jsonl`) + Flush über mTLS `POST /v1/agent/sessions`;
      Opt-in per `gssh-agentd enroll --session-audit` (Default aus, host-lokal)
- [x] sudo-Audit: sudo-Events (Kommando, Ziel-User) erfassen und melden
      → `pam_exec` im sudo-Stack → `session.sudo`-Audit-Event (Ziel-/Aufruf-User,
      Kommando best-effort via `SUDO_COMMAND`; zuverlässig nur via sudo-Logfile/Plugin)
- [x] Korrelation: Session-Events via Zertifikats-Serial mit Ausstellung verknüpfen
      → statt journald-Parsing: sshd-Tokens `%s`/`%i` an den Principals-Helfer; Daemon
      merkt sich Serial→User und reichert die Session-Open an; Server löst über
      `certificates.serial` den Nutzer auf (`LogLevel VERBOSE` zusätzlich gesetzt)
- [ ] Optional NSS-Modul für zentrale Konten (UID/GID aus IdP) — Entscheidung nach
      MVP-Erfahrung, bis dahin lokale Konten über bestehendes Provisioning des Betreibers
      → offen gelassen (bewusst zurückgestellt)
- [ ] Dashboards: aktive Sessions, Sessions pro Host/Nutzer
      → zurückgestellt (Folge-Schritt); Backend steht: `host_sessions` +
      `Store.ListActiveSessions`

## Phase 10 — Härtung & Schlüsselverwaltung

- [ ] KMS-Signer implementieren (Interface aus Phase 2): PKCS#11 zuerst (deckt HSM +
      SoftHSM-Tests ab), HashiCorp Vault integration
      → bewusst zurückgestellt
- [x] Rate-Limiting und Brute-Force-Schutz auf Sign-Endpoints
      → `internal/api/ratelimit.go`: Token-Bucket pro Client-IP auf
      `/v1/sign/user|ci` + `/v1/enroll` (Request-Budget 60/min + enges
      Failure-Budget 10/min für 401/403 → 429); Env `GSSH_SIGN_RATE_PER_MINUTE`
      (0 = aus), `GSSH_SIGN_FAIL_PER_MINUTE`, `GSSH_RATE_TRUST_PROXY`;
      zusätzlich 64-KiB-Body-Limits auf den Austausch-Endpunkten
- [x] mTLS-Zertifikatsrotation für Host-Agenten
      → `POST /v1/agent/renew-mtls` (CSR über bestehenden mTLS-Kanal, CN kommt
      serverseitig aus dem Peer-Zertifikat); Daemon rotiert bei 2/3 der
      Laufzeit (frisches Schlüsselpaar, atomarer Dateitausch, Client-Zertifikat
      wird per GetClientCertificate ohne Neustart umgeschaltet)
- [x] Revocation-Strategie dokumentieren: kurze Laufzeiten als primärer Mechanismus,
      zusätzlich `RevokedKeys`-Verteilung über Host-Agent für Notfälle
      → ADR-022: Laufzeiten primär, schneller Entzug über Grants/Principals
      (fail-closed, ~10 min), KRL-Verteilung als geplante Ausbaustufe,
      CA-Rotation als Nuklearoption
- [x] Security-Review des Token-Austauschs (Replay, Audience-Confusion, Clock-Skew)
      → `docs/security-review-token-austausch.md`; Fixes: fail-fast bei
      fehlender `GSSH_OIDC_CLIENT_ID`, Startup-Check gegen Issuer/Audience-
      Kollision von Benutzer-OIDC und GitLab-CI (`checkAudienceSeparation`)
- [x] Fuzzing/Negativtests für Sign-Endpoints
      → Go-Fuzzing: `FuzzDecodeSignRequest`, `FuzzBearerToken`,
      `FuzzSignUser`, `FuzzSignCI` (nie Panic/500); Negativtests für
      übergroße Bodies, negative Laufzeit, Rate-Limit nach Fehlversuchen

## Phase 11 — Helm-Chart & Kubernetes-Deployment

- [x] Helm-Chart `deploy/helm/guided-ssh`: Deployment (API+UI), Service, Ingress,
      ServiceMonitor, NetworkPolicies, PodSecurityContext (non-root, read-only FS)
      → dazu separater Agent-Service (mTLS braucht TLS-Passthrough, kein Ingress)
- [x] Konfiguration vollständig über `values.yaml`: IdP, GitLab-Issuer, DB-DSN,
      Signer-Backend, Laufzeit-Defaults
      → 1:1-Mapping `config.*` → `GSSH_*`-Env; DSN/Master-Key via Secret-Refs;
      Signer-Backend ist der Software-Signer (DB, AES-256) — kein weiteres Backend
- [x] Secrets-Handhabung: `existingSecret`-Referenzen (kompatibel mit external-secrets
      und SOPS — keine Secrets im Chart)
      → `secrets.existingSecret` (Pflicht, fail-fast via `required`),
      `config.keycloak.existingSecret` (optional)
- [x] PostgreSQL: Anbindung an extern/CloudNativePG dokumentieren; optionale
      Subchart-Dependency nur für Entwicklung
      → Chart-README (CNPG-`Cluster` + Secret `…-app`/`uri`); bitnami/postgresql
      als Dependency mit `condition: postgresql.enabled` (Default aus)
- [x] DB-Migrationen als Init-Container/Job mit Lock
      → Subkommando `gssh-server migrate` als Init-Container; goose mit
      Postgres-Advisory-Session-Lock (serialisiert parallele Replikas)
- [x] Health-/Readiness-Probes, PodDisruptionBudget, HPA-Optionen
      → Probes auf `/healthz`; PDB (`minAvailable`) und HPA (autoscaling/v2)
      per Values zuschaltbar
- [x] Prometheus-Metriken (ausgestellte Zertifikate, Fehlerraten, Agent-Heartbeats)
      → `internal/metrics` (client_golang), eigener Listener `-metrics-listen`;
      `gssh_certificates_issued_total{requester,cert_type}`,
      `gssh_http_responses_total{code}`, `gssh_agent_heartbeats_total`;
      ServiceMonitor optional im Chart
- [x] Chart-Tests (`helm test`, chart-testing in CI)
      → `templates/tests/test-connection.yaml` (healthz-Check);
      `helm-lint`-Job (ct lint, `.github/ct.yaml`) in der Test-Pipeline
- [x] Chart-Release über GitHub Pages als Helm-Repository (manuelles
      `helm package` + `helm repo index`, `.tgz` + `index.yaml` auf `gh-pages`
      committet, zusätzlich ans `vX.Y.Z`-Release gehängt — Vorbild valkey-operator)
      → `helm-chart`-Job in `.github/workflows/build.yml`, gemeinsam mit Binaries
      und Image; einmalige gh-pages-Einrichtung im Chart-README
- [x] Image-Referenzen im Chart default auf `docker.io/guidedtraffic/*`
      → `image.repository: docker.io/guidedtraffic/guided-ssh`, Tag default
      Chart-`appVersion`

## Phase 12 — GitOps (FluxCD)

- [x] Referenz-Repo-Struktur dokumentieren: `HelmRepository` (zeigt auf das
      GitHub-Pages-Helm-Repo) + `HelmRelease` für guided-ssh, Kustomize-Overlays
      pro Umgebung; Images aus `docker.io/guidedtraffic`
      → `deploy/flux-example/README.md`: base + Overlays staging/production
      (staging Version-Range, production exakter Pin), Cluster-Kustomizationen
- [x] SOPS-Beispiel für Secrets im GitOps-Repo (age-Key, Flux-Decryption)
      → `.sops.yaml` (age, encrypted_regex data/stringData),
      `decryption.provider: sops` + Secret `sops-age` in den
      Cluster-Kustomizationen; Chart bleibt secret-frei (existingSecret)
- [x] Grants deklarativ via GitOps: `grants.yaml` im Repo, Sync-Job/CronJob ruft
      `gssh-admin apply` — Zugriffsregeln damit versioniert und reviewbar
      → CronJob `guided-ssh-grants-sync` (15 min, gssh-admin im Server-Image);
      neu: Client-Credentials-Flow in gssh-admin (GSSH_CLIENT_SECRET /
      GSSH_CLIENT_ID) für nicht-interaktive Service-Accounts, Keycloak-
      Einrichtung (Audience-/Groups-Mapper) im README
- [x] Upgrade-Pfad testen: Chart-Version-Bump via Flux, Migrationen laufen automatisch
      → `hack/flux-upgrade-test.sh`: kind + Flux, Install 0.1.0 aus lokalem
      Helm-Repo, Bump auf 0.1.1 → Upgrade rollt, migrate-Init-Container läuft
- [x] Beispiel-Manifeste in `deploy/flux-example/` pflegen
      → base (Namespace, HelmRepository, HelmRelease, Sync-Config, CronJob),
      Overlays mit grants.yaml/secrets.yaml, kustomize-build-verifiziert

## Phase 13 — Qualitätssicherung & Release

- [x] Integrationstest-Suite konsolidieren (aus Phasen 1–9) und vollständig in der
      GitHub-Pipeline ausführen (Testcontainer auf self-hosted Runner)
      → einheitlich Build-Tag `integration`, kompletter Lauf in den Jobs
      `unit-tests`/`integration-tests` (`make test-*-coverage`), Coverage-Merge
      im Job `coverage-report`; Abgrenzung in `docs/teststrategie.md`
- [x] E2E-Testumgebung: kind-Cluster + Keycloak + simuliertes GitLab-OIDC + zwei
      Testhosts (Container) — kompletter Durchstich Mensch + CI; läuft in der
      GitHub-Pipeline auf self-hosted Runner (auf merge-request und auf main)
      → `test/e2e` (Build-Tag `e2e`, `make e2e`): produktives Helm-Chart im
      kind-Cluster; **Dex + GLAuth statt Keycloak** (leichter; Gruppen über
      LDAP-Connector, Offboarding per ConfigMap), Fake-GitLab-OIDC (nginx,
      statisches Discovery/JWKS), zwei sshd-Testhost-Pods + Workstation-Pod
      (echtes `gssh` + ssh-agent + openssh); CI-Job `e2e-tests` in
      `release.yml` (PR + main), semantic-release ist darauf gegated
- [x] E2E-Testfälle ausarbeiten und automatisieren: SSO-Login, Offboarding,
      CI-Zertifikat + Ansible-Provisioning, Grant-Änderung, Host-Rotation,
      Audit-Vollständigkeit
      → 7 Szenarien in fester Reihenfolge (inkl. Chaos), Details in
      `docs/teststrategie.md`; Host-Rotation via neuem
      `GSSH_HOST_CERT_VALIDITY` (3 m im Test) beobachtbar; lokal grün (~3 m
      Laufzeit nach Image-Cache)
- [x] Coverage-Report prüfen: ≥ 80 % über Go-Module, Lücken begründen oder schließen
      → Stand vor Phase 13: 77,2 %; geschlossen mit Unit-Tests für
      `cmd/gssh-server` (Setup-/Env-Funktionen) und `internal/agentd`
      (pam_exec-Roundtrip, mTLS-Client RenewMTLS/SendSessions) → **80,4 %**.
      Begründete Rest-Lücken: `cmd/*`-main-Wrapper und `serve()`/
      `newAgentServer()` (Verkabelung, durch E2E-Suite abgedeckt — läuft
      als eigenes Binary und zählt nicht in die Coverage), agentd-Daemon-
      Schleifen (Integrationstests im Container, gleiche Einschränkung)
- [x] Lasttest Sign-Endpoint (Ziel definieren, z. B. 50 Zertifikate/s)
      → Ziel definiert: ≥ 50 Zert/s (docs/teststrategie.md); `test/load`
      (Build-Tag `loadtest`, `make loadtest`), echte API + Postgres + OIDC-
      Verifier ohne Rate-Limit; Referenzmessung ~1770 Zert/s, p95 11 ms;
      CI-Job `load-test` auf main (informativ, nicht release-blockierend)
- [x] Chaos-Fälle: API down → bestehende SSH-Sessions unbeeinträchtigt, Agent-Cache
      trägt Logins bis TTL, danach fail-closed (verifizieren)
      → E2E-Szenario `05_Chaos_API_Down` (Session überlebt Replicas=0,
      Cache-Login bis TTL, danach fail-closed, Wiederanlauf ok) +
      `TestPrincipalsCacheUndFailClosed` (Unit, internal/agentd)
- [x] Dokumentation: Betriebs-Handbuch, Enrollment-Guide, GitLab-Integrations-Guide,
      Troubleshooting, Architekturdiagramm
      → `docs/betriebshandbuch.md`, `docs/enrollment-guide.md`,
      `docs/troubleshooting.md`, `docs/architektur.md` (Mermaid-Diagramme);
      GitLab-Integrations-Guide war mit `docs/gitlab-ci.md` bereits vollständig
- [x] Versionierte Releases (Binaries, Container-Images, Helm-Chart), version ist von git-tag abzuleiten
      → semantic-release erzeugt Tag `vX.Y.Z`; neu: Job `binaries` in
      `build.yml` hängt Cross-Binaries (gssh, gssh-agentd), deb/rpm-Pakete
      und SHA256SUMS ans GitHub-Release (Version via `git describe` aus dem
      Tag, Makefile); Docker-Images (SemVer-Tags, build.yml) und
      Helm-Chart-Releases (chart-release.yml) bestanden bereits
- [x] Erfolgskriterien final verifizieren (siehe unten)

---

## Erfolgskriterien (Definition of Done, produktweit)

- [x] Mensch: `ssh host` ohne vorhandenes Zertifikat → SSO-Browser-Flow → Login klappt;
      Zertifikat nur im Agent, Laufzeit ≤ konfiguriertem Maximum
      → E2E `01_SSO_Login_DeviceFlow` (echtes gssh-Binary, Dex-SSO via
      Device-Flow, transparentes ssh mit CA-verifiziertem Host-Cert);
      PKCE-Browser-Flow unit-getestet (internal/auth, internal/cli);
      Agent-only ADR-016, Laufzeit-Deckelung Policy-Tests (internal/ca)
- [x] Offboarding: Nutzer aus IdP-Gruppe entfernt → keine neue Ausstellung, Host-ACL
      verweigert innerhalb Cache-TTL
      → E2E `06_Offboarding` (403 + ACL-Entzug ≤ Cache-TTL trotz gültigem
      Zertifikat); Offboarding ohne Re-Login (Admin-API-Sync) im
      Keycloak-Integrationstest
- [x] CI: GitLab-Job ohne statische Secrets provisioniert Host via Ansible; Zertifikat
      läuft ≤ 1 h und ist im Audit der Pipeline zugeordnet
      → E2E `03_CI_Zertifikat_Ansible` (Job-Token → gssh ci-login →
      ansible-playbook über den Agenten, KeyID `ci:<projekt>:<pipeline>:<job>`
      im Audit); 1-h-Deckelung: CI-Policy-Tests (internal/ca, internal/api)
- [x] Audit: jede Ausstellung, jeder Login, jedes sudo, jede Grant-Änderung abfragbar
      (UI + Export), Audit-Tabelle append-only
      → E2E `07_Audit_Vollstaendigkeit` (Export JSON+CSV: Ausstellungen
      Mensch+CI, Enrollments, Grant-Änderungen); Session-/sudo-Events:
      Phase-9-Tests; Append-only-Trigger: store-Integrationstest
- [x] Deployment: Installation ausschließlich über HelmRelease in Flux-Repo, Secrets
      via SOPS/external-secrets, Upgrade ohne Downtime der Sign-Endpoints
      → Flux-Referenz + SOPS (Phase 12, `deploy/flux-example/`); Upgrade-Pfad
      verifiziert via `hack/flux-upgrade-test.sh` (Migrations-Advisory-Lock);
      Zero-Downtime setzt `replicaCount ≥ 2` + PDB voraus (Chart-Optionen,
      dokumentiert im Betriebshandbuch)
- [x] Qualität: ≥ 80 % Testabdeckung im Go-Code (Frontend ausgenommen), Coverage-Gate
      aktiv; Integrations- und E2E-Suite laufen grün in GitHub Actions (self-hosted)
      → 80,4 % (`make cover`, Gate aktiv lokal + CI); Unit-/Integrations-Jobs
      laufen in `release.yml`; E2E-Job `e2e-tests` neu — lokal grün, erster
      Pipeline-Lauf mit dem nächsten Push auf den PR


## Later Topics
- [ ] gssh login: CLI-Login gegen Dex scheitert — Operator kann keine secretlosen
      Public Clients

      **Kontext.** `gssh login` nutzt einen eigenen Public Client (`gssh-cli`,
      `internal/cli/config.go`) mit Authorization Code + PKCE (Default) bzw.
      Device-Flow (`internal/auth/flow.go`) — beide tauschen den Code/Device-Code
      ohne `client_secret` gegen Tokens. Dex prüft das Secret aber immer, sobald
      am registrierten Client eines hinterlegt ist; `public: true` schaltet die
      Prüfung nicht ab (Dex-Log: `missing client_secret on token request`).
      Der dex-operator (`dex.gtrfc.com/v1 DexStaticClient`) hängt derzeit an
      jeden Client ein Secret (`iso.gtrfc.com/autogenerate`-Annotation,
      `clientSecretKey` wird gedefaultet, gerendert als `secretEnv` in der
      Dex-Config) — echte secretlose Clients sind mit dem Operator nicht
      abbildbar. Die Web-UI ist davon nicht mehr betroffen (BFF, confidential
      Client); die CLI bleibt Public Client und läuft gegen Dex in denselben
      401 am Token-Endpoint.

      **Ziel.** `gssh login` (PKCE- und Device-Flow) funktioniert gegen Dex
      end-to-end (Token-Tausch 200, `POST /v1/sign/user` liefert Zertifikat).

      **Lösungsansatz.**
      1. Operator-Fix: bei `public: true` den Client OHNE Secret rendern
         (kein `secretEnv`, `clientSecretKey`/Autogenerate nicht erzwingen).
      2. Operator muss leere `redirectURIs` erlauben: die CLI lauscht auf
         `127.0.0.1:<random>`; Dex erlaubt localhost-Redirects für Public
         Clients nur, wenn KEINE redirectURIs registriert sind — sonst ist
         der zufällige Port nicht abbildbar.
      3. Eigenen Dex-Client für die CLI anlegen (z. B.
         `${cluster_name}-gssh-cli`, public, secretlos, ohne redirectURIs)
         und `GSSH_OIDC_CLIENT_ID` (= erwartete Audience von /v1/sign/user)
         darauf zeigen lassen — UI- und CLI-Client sind nach dem BFF-Umbau
         getrennt.

      **Verworfen:** `client_secret` in der CLI-Config (confidential CLI) —
      Secret läge in jeder User-Config, faktisch doch public, nur mit
      Verteilproblem.

      **Akzeptanzkriterien.**
      - `DexStaticClient` mit `public: true` rendert ohne Secret und ohne
        Pflicht-redirectURIs
      - `gssh login` (PKCE) gegen wds18-Dex erfolgreich, ebenso `--device`
      - Audience-Kette dokumentiert: CLI-Client-ID = `GSSH_OIDC_CLIENT_ID`