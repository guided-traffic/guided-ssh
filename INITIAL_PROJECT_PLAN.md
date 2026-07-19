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
      → `.github/workflows/ci.yml`, Dockerfile statt ko (ADR-010), `docs/ci-runner.md`;
      Runner-Registrierung selbst ist Ops-seitig noch offen
- [x] Registry-Ziel: Container-Images nach `docker.io/guidedtraffic` (Push-Credentials
      als GitHub-Secrets, Tagging: SemVer + `sha-<commit>`)
      → Secrets `DOCKERHUB_USERNAME`/`DOCKERHUB_TOKEN` (dokumentiert in `docs/ci-runner.md`),
      Push nur auf `main`/Tags; Secrets in GitHub anlegen ist noch offen
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

- [ ] PostgreSQL-Schema entwerfen: `users`, `groups`, `hosts`, `host_tags`, `access_grants`
      (Gruppe × Tag-Selektor × Principals × sudo-Flag × max. Laufzeit), `certificates`
      (ausgestellte Zertifikate inkl. Serial, KeyID, Principals, Gültigkeit, Issuer-Kontext),
      `audit_events` (append-only), `ca_keys`, `service_accounts` (CI-Identitäten)
- [ ] Migrations-Tooling einrichten (goose oder golang-migrate)
- [ ] Repository-Layer in Go (sqlc oder pgx direkt) mit Tests gegen Testcontainer-Postgres
- [ ] Append-only-Garantie für `audit_events` (kein UPDATE/DELETE-Grant, Trigger als Schutz)
- [ ] Retention-Konzept für Audit-Daten dokumentieren (Partitionierung nach Monat)

## Phase 2 — Zertifizierungsstelle (Core-CA)

- [ ] Signer-Interface definieren (`Sign(ctx, CertRequest) (*ssh.Certificate, error)`)
- [ ] Software-Signer: Ed25519-CA-Key, verschlüsselt at rest (age/AES-GCM, Key aus K8s-Secret)
- [ ] Getrennte CA-Keys für Benutzer- und Host-Zertifikate
- [ ] Zertifikatsbau: Serial, KeyID (`user:<sub>@<idp>` bzw. `ci:<project>:<pipeline>`),
      Principals, `valid_after`/`valid_before`, Extensions (`permit-pty`, …), Critical Options
- [ ] Policy-Engine: maximale Laufzeit, erlaubte Principals, erlaubte Extensions pro Requester-Typ
- [ ] Jede Signatur erzeugt synchron ein `audit_event` + `certificates`-Eintrag (gleiche Transaktion)
- [ ] Key-Rotation: mehrere aktive CA-Keys, Übergangsfenster, Endpoint für aktuelles CA-Bundle
- [ ] Unit-Tests: Zertifikatsinhalte, Policy-Verletzungen, Ablaufzeiten

## Phase 3 — Benutzer-Authentifizierung (OIDC/SSO)

- [ ] OIDC-Integration (Authorization Code + PKCE für CLI, Device-Flow als Fallback)
- [ ] Token-Validierung: Issuer, Audience, Signatur (JWKS-Cache), Ablauf
- [ ] Claim-Mapping: `sub`/`email`/`groups` → interner User + Principal-Ableitung
- [ ] Periodischer Gruppen-Sync vom IdP (Group-Claims bzw. Directory-API) → sofortiger
      Entzug wirkt auf Neuausstellung UND Host-ACLs
- [ ] Endpoint `POST /v1/sign/user`: ID-Token rein, SSH-Zertifikat raus (Policy-geprüft)
- [ ] Integrationstests gegen Keycloak in Testcontainer

## Phase 4 — CLI für Benutzer (`gssh`)

- [ ] `gssh login`: SSO-Flow, Schlüsselpaar ephemeral erzeugen, Zertifikat holen,
      beides nur in `ssh-agent` laden (keine Persistenz auf Platte)
- [ ] `gssh ssh <host>` bzw. ProxyCommand/Match-exec-Integration in `~/.ssh/config`,
      damit natives `ssh` transparent funktioniert (Auto-Login bei fehlendem Zertifikat)
- [ ] `gssh status`, `gssh logout` (Agent-Einträge entfernen)
- [ ] Konfigurationsdatei (`~/.config/guided-ssh/config.yaml`): API-URL, IdP, Fingerprint-Pinning
- [ ] Cross-Platform-Builds (linux/amd64, linux/arm64, darwin/arm64) in CI

## Phase 5 — Host-Enrollment & Host-Agent

- [ ] Enrollment-Flow: einmaliges Enrollment-Token (oder Cloud-Identity später) →
      Host registriert sich, erhält Host-Zertifikat + mTLS-Client-Zertifikat für API
- [ ] Host-Agent (`gssh-agentd`, ein Go-Binary, systemd-Unit):
  - [ ] Host-Zertifikat automatisch erneuern (bei 2/3 der Laufzeit)
  - [ ] CA-Bundle aktuell halten (`TrustedUserCAKeys`-Datei schreiben)
  - [ ] Autorisierte Principals pro lokalem User von API beziehen und cachen
- [ ] `AuthorizedPrincipalsCommand`-Helper: sshd fragt Agent (Unix-Socket), Agent
      antwortet aus Cache — Fail-closed bei nicht erreichbarer API, konfigurierbare Cache-TTL
- [ ] sshd-Konfigurations-Snippets generieren (`/etc/ssh/sshd_config.d/guided-ssh.conf`)
- [ ] Host-Tags: bei Enrollment setzbar, via API/CLI änderbar
- [ ] Paketierung des Host-Agents: deb/rpm (nfpm) + Install-Skript; `gssh-agentd enroll
      --token …` übernimmt sshd-Konfiguration idempotent
- [ ] Integrationstest: Container-Host mit sshd, Enrollment, Login mit Benutzerzertifikat

## Phase 6 — Zugriffssteuerung (Grants)

- [ ] Grant-Modell umsetzen: IdP-Gruppe × Tag-Selektor → Ziel-Principals (z. B. `deploy`,
      `root`), sudo ja/nein, maximale Zertifikatslaufzeit
- [ ] Auswertung an zwei Stellen: bei Zertifikatsausstellung (welche Principals bekommt
      der Requester) und auf dem Host (welche Principals akzeptiert dieser lokale User)
- [ ] Grant-Verwaltung: CRUD via API + CLI (`gssh-admin grant …`); deklarativer
      YAML-Import (`gssh-admin apply -f grants.yaml`) für GitOps-Pflege der Zugriffsregeln
- [ ] Konfliktregeln definieren (deny gibt es nicht — nur additive Grants, dokumentieren)
- [ ] Bastion-Muster dokumentieren (ProxyJump, Grants für Bastion + Ziel getrennt)
- [ ] E2E-Test: Gruppe entfernen → nächster Login schlägt fehl, Host-ACL aktualisiert

## Phase 7 — GitLab-CI-Integration (Kernanforderung)

- [ ] GitLab als OIDC-Issuer registrieren: Konfiguration von Issuer-URL + JWKS,
      Audience-Vorgabe (`aud: guided-ssh`)
- [ ] Endpoint `POST /v1/sign/ci`: validiert GitLab `id_token`, mappt Claims
      (`project_path`, `ref`, `ref_protected`, `pipeline_id`, `environment`) auf
      CI-Grant-Regeln
- [ ] CI-Grants: Projekt/Gruppe × Branch-Bedingung (z. B. nur `ref_protected: true`)
      × Tag-Selektor → Principals; Laufzeit gedeckelt (Default 1 h, max. Job-Timeout)
- [ ] KeyID-Format `ci:<project_path>:<pipeline_id>:<job_id>` → jede Ausstellung im
      Audit eindeutig einer Pipeline zuordenbar
- [ ] Helper-Kommando `gssh ci-login` (nutzt `CI_JOB_JWT`/`id_tokens`), lädt Zertifikat
      in Agent des Jobs
- [ ] Referenz-Pipeline dokumentieren: `.gitlab-ci.yml` mit `id_tokens`, `gssh ci-login`,
      dann `ansible-playbook` gegen Zielhosts (Ansible nutzt den ssh-agent automatisch)
- [ ] Beispiel-Ansible-Playbook + Inventory-Muster für zertifikatsbasiertes Provisioning
- [ ] E2E-Test: simuliertes GitLab-Token → Zertifikat → Ansible-Ping gegen Testhost

## Phase 8 — Web-UI & Auditing-Oberfläche

- [ ] Angular-Projekt aufsetzen (`web/`): Standalone Components, Angular Material,
      OIDC-Login (Authorization Code + PKCE, z. B. `angular-auth-oidc-client`),
      Rollen (Admin, Auditor, Read-only) aus Token-Claims
- [ ] API-Client aus OpenAPI-Spec generieren (Single Source of Truth für REST-API)
- [ ] Build-Integration: Angular-Build in CI, Assets via `embed.FS` ins Go-Binary
- [ ] Ansichten: Hosts (Status, Tags, Zertifikatsablauf), Grants, Benutzer/Gruppen,
      Service-Accounts/CI-Regeln
- [ ] Audit-Ansicht: filterbar nach Nutzer, Host, Pipeline, Zeitraum, Ereignistyp
      (Ausstellung, Login, sudo, Session-Ende, Enrollment, Grant-Änderung)
- [ ] Audit-Export: CSV/JSON-Download + strukturierte Logs (JSON auf stdout) für
      SIEM-Anbindung; optionaler Webhook
- [ ] Admin-Änderungen über UI erzeugen selbst Audit-Events (wer änderte welchen Grant)

## Phase 9 — Session-Audit auf dem Host (Ausbaustufe)

- [ ] PAM-Modul oder `pam_exec`-Hook: Session-Start/-Ende an API melden (gepuffert,
      asynchron, Verlust-tolerant mit lokalem Spool)
- [ ] sudo-Audit: sudo-Events (Kommando, Ziel-User) erfassen und melden
- [ ] Korrelation: Session-Events via Zertifikats-Serial mit Ausstellung verknüpfen
      (sshd-LogLevel VERBOSE loggt Cert-Serial; Agent parst `auth.log`/journald)
- [ ] Optional NSS-Modul für zentrale Konten (UID/GID aus IdP) — Entscheidung nach
      MVP-Erfahrung, bis dahin lokale Konten über bestehendes Provisioning des Betreibers
- [ ] Dashboards: aktive Sessions, Sessions pro Host/Nutzer

## Phase 10 — Härtung & Schlüsselverwaltung

- [ ] KMS-Signer implementieren (Interface aus Phase 2): PKCS#11 zuerst (deckt HSM +
      SoftHSM-Tests ab), Cloud-KMS nach Bedarf
- [ ] Rate-Limiting und Brute-Force-Schutz auf Sign-Endpoints
- [ ] mTLS-Zertifikatsrotation für Host-Agenten
- [ ] Revocation-Strategie dokumentieren: kurze Laufzeiten als primärer Mechanismus,
      zusätzlich `RevokedKeys`-Verteilung über Host-Agent für Notfälle
- [ ] Security-Review des Token-Austauschs (Replay, Audience-Confusion, Clock-Skew)
- [ ] Fuzzing/Negativtests für Sign-Endpoints

## Phase 11 — Helm-Chart & Kubernetes-Deployment

- [ ] Helm-Chart `deploy/helm/guided-ssh`: Deployment (API+UI), Service, Ingress,
      ServiceMonitor, NetworkPolicies, PodSecurityContext (non-root, read-only FS)
- [ ] Konfiguration vollständig über `values.yaml`: IdP, GitLab-Issuer, DB-DSN,
      Signer-Backend, Laufzeit-Defaults
- [ ] Secrets-Handhabung: `existingSecret`-Referenzen (kompatibel mit external-secrets
      und SOPS — keine Secrets im Chart)
- [ ] PostgreSQL: Anbindung an extern/CloudNativePG dokumentieren; optionale
      Subchart-Dependency nur für Entwicklung
- [ ] DB-Migrationen als Init-Container/Job mit Lock
- [ ] Health-/Readiness-Probes, PodDisruptionBudget, HPA-Optionen
- [ ] Prometheus-Metriken (ausgestellte Zertifikate, Fehlerraten, Agent-Heartbeats)
- [ ] Chart-Tests (`helm test`, chart-testing in CI)
- [ ] Chart-Release über GitHub Pages als Helm-Repository (chart-releaser:
      `gh-pages`-Branch mit `index.yaml`, Release-Workflow bei Chart-Version-Bump)
- [ ] Image-Referenzen im Chart default auf `docker.io/guidedtraffic/*`

## Phase 12 — GitOps (FluxCD)

- [ ] Referenz-Repo-Struktur dokumentieren: `HelmRepository` (zeigt auf das
      GitHub-Pages-Helm-Repo) + `HelmRelease` für guided-ssh, Kustomize-Overlays
      pro Umgebung; Images aus `docker.io/guidedtraffic`
- [ ] SOPS-Beispiel für Secrets im GitOps-Repo (age-Key, Flux-Decryption)
- [ ] Grants deklarativ via GitOps: `grants.yaml` im Repo, Sync-Job/CronJob ruft
      `gssh-admin apply` — Zugriffsregeln damit versioniert und reviewbar
- [ ] Upgrade-Pfad testen: Chart-Version-Bump via Flux, Migrationen laufen automatisch
- [ ] Beispiel-Manifeste in `deploy/flux-example/` pflegen

## Phase 13 — Qualitätssicherung & Release

- [ ] Integrationstest-Suite konsolidieren (aus Phasen 1–9) und vollständig in der
      GitHub-Pipeline ausführen (Testcontainer auf self-hosted Runner)
- [ ] E2E-Testumgebung: kind-Cluster + Keycloak + simuliertes GitLab-OIDC + zwei
      Testhosts (Container) — kompletter Durchstich Mensch + CI; läuft in der
      GitHub-Pipeline auf self-hosted Runner (nightly + vor Release)
- [ ] E2E-Testfälle ausarbeiten und automatisieren: SSO-Login, Offboarding,
      CI-Zertifikat + Ansible-Provisioning, Grant-Änderung, Host-Rotation,
      Audit-Vollständigkeit
- [ ] Coverage-Report prüfen: ≥ 80 % über Go-Module, Lücken begründen oder schließen
- [ ] Lasttest Sign-Endpoint (Ziel definieren, z. B. 50 Zertifikate/s)
- [ ] Chaos-Fälle: API down → bestehende SSH-Sessions unbeeinträchtigt, Agent-Cache
      trägt Logins bis TTL, danach fail-closed (verifizieren)
- [ ] Dokumentation: Betriebs-Handbuch, Enrollment-Guide, GitLab-Integrations-Guide,
      Troubleshooting, Architekturdiagramm
- [ ] Versionierte Releases (Binaries, Container-Images, Helm-Chart)
- [ ] Erfolgskriterien final verifizieren (siehe unten)

---

## Erfolgskriterien (Definition of Done, produktweit)

- [ ] Mensch: `ssh host` ohne vorhandenes Zertifikat → SSO-Browser-Flow → Login klappt;
      Zertifikat nur im Agent, Laufzeit ≤ konfiguriertem Maximum
- [ ] Offboarding: Nutzer aus IdP-Gruppe entfernt → keine neue Ausstellung, Host-ACL
      verweigert innerhalb Cache-TTL
- [ ] CI: GitLab-Job ohne statische Secrets provisioniert Host via Ansible; Zertifikat
      läuft ≤ 1 h und ist im Audit der Pipeline zugeordnet
- [ ] Audit: jede Ausstellung, jeder Login, jedes sudo, jede Grant-Änderung abfragbar
      (UI + Export), Audit-Tabelle append-only
- [ ] Deployment: Installation ausschließlich über HelmRelease in Flux-Repo, Secrets
      via SOPS/external-secrets, Upgrade ohne Downtime der Sign-Endpoints
- [ ] Qualität: ≥ 80 % Testabdeckung im Go-Code (Frontend ausgenommen), Coverage-Gate
      aktiv; Integrations- und E2E-Suite laufen grün in GitHub Actions (self-hosted)
