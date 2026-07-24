# Betriebs-Handbuch

Zielgruppe: Betreiber der guided-ssh-Plattform (Kubernetes/GitOps).
Ergänzende Dokumente: [Architektur](architektur.md),
[Enrollment-Guide](enrollment-guide.md), [Troubleshooting](troubleshooting.md),
[GitLab-CI-Integration](gitlab-ci.md), [Audit-Retention](audit-retention.md),
[ADR-Index](adr/README.md).

## Architekturüberblick

Ein Go-Binary (`gssh-server`) bündelt REST-API, Zertifizierungsstelle (CA),
eingebettete Web-UI, Agent-API (mTLS, eigener Port) und Metrics-Endpoint
(eigener Port). Persistenz ausschließlich in PostgreSQL; die CA-Private-Keys
liegen AES-256-GCM-verschlüsselt in der Tabelle `ca_keys` (ADR-014). Drei
strikt getrennte Auth-Pfade: OIDC für Menschen, GitLab-OIDC für CI, mTLS für
Host-Agenten (ADR-008). Details und Diagramme: [architektur.md](architektur.md).

## Deployment

- **Helm-Chart** `deploy/helm/guided-ssh` — Installation, Secrets,
  PostgreSQL-Anbindung (extern/CloudNativePG), Agent-Service (TLS-Passthrough),
  ServiceMonitor: siehe [Chart-README](../deploy/helm/guided-ssh/README.md).
- **GitOps (FluxCD)** — HelmRelease aus dem GitHub-Pages-Helm-Repo,
  Kustomize-Overlays pro Umgebung, SOPS-Secrets, deklarative Grants per
  Sync-CronJob: siehe [deploy/flux-example/README.md](../deploy/flux-example/README.md).

Der Server startet mit `-listen :8080` (HTTP-API + UI); optional
`-agent-listen :8443` (Agent-API, mTLS) und `-metrics-listen :9090`
(Prometheus). Subkommandos: `gssh-server migrate` (nur Migrationen,
Init-Container) und `gssh-server enroll-token` (Host-Enrollment-Token,
siehe [enrollment-guide.md](enrollment-guide.md)).

## Konfigurations-Referenz (Umgebungsvariablen)

Alle Werte aus `cmd/gssh-server/main.go`; im Helm-Chart 1:1 über
`config.*`/`secrets.*` gemappt.

| Variable | Default | Wirkung |
|---|---|---|
| `GSSH_DB_HOST` | — (Pflicht) | PostgreSQL-Host |
| `GSSH_DB_PORT` | `5432` | PostgreSQL-Port |
| `GSSH_DB_USER` | — (Pflicht) | Datenbank-Benutzer |
| `GSSH_DB_PASSWORD` | — (Pflicht) | Datenbank-Passwort (Sonderzeichen unkritisch, wird URL-escaped) |
| `GSSH_DB_NAME` | — (Pflicht) | Datenbank-Name |
| `GSSH_DB_SSLMODE` | `prefer` | `sslmode` der Verbindung (`disable`, `require`, `verify-full`, …) |
| `GSSH_CA_MASTER_KEY` | — (Pflicht) | Master-Key der CA-Key-Verschlüsselung: 32 Bytes, Base64 |
| `GSSH_OIDC_ISSUER` | leer | Issuer-URL des IdP; leer ⇒ `/v1/sign/user` deaktiviert (503) |
| `GSSH_OIDC_CLIENT_ID` | leer | erwartete Audience der ID-Tokens; fehlt sie bei gesetztem Issuer ⇒ Startfehler (fail-fast) |
| `GSSH_CI_ISSUER` | leer | GitLab-Basis-URL (OIDC-Issuer); leer ⇒ `/v1/sign/ci` deaktiviert (503) |
| `GSSH_CI_AUDIENCE` | `guided-ssh` | erwartete Audience der GitLab-Job-Tokens |
| `GSSH_KC_BASE_URL` | leer | Keycloak-Basis-URL für den Gruppen-Sync |
| `GSSH_KC_REALM` | leer | Keycloak-Realm |
| `GSSH_KC_CLIENT_ID` | leer | Service-Account-Client des Syncs; leer ⇒ Gruppen-Sync deaktiviert |
| `GSSH_KC_CLIENT_SECRET` | leer | Client-Secret des Sync-Clients |
| `GSSH_KC_SYNC_INTERVAL` | `5m` | Sync-Intervall (Go-Duration) |
| `GSSH_AGENT_TLS_NAMES` | `localhost,127.0.0.1` | SANs des mTLS-Server-Zertifikats der Agent-API (Komma-getrennt) |
| `GSSH_ADMIN_GROUP` | leer | IdP-Gruppe der Admins; leer ⇒ keine Admin-Mutationen (fail-closed) |
| `GSSH_AUDITOR_GROUP` | leer | IdP-Gruppe der Auditoren (Audit-Log lesen/exportieren) |
| `GSSH_READONLY_GROUP` | leer | IdP-Gruppe für Read-only-Ansichten; alle drei Gruppen leer ⇒ Admin-API komplett deaktiviert |
| `GSSH_UI_OIDC_CLIENT_ID` | `GSSH_OIDC_CLIENT_ID` | OIDC-Client der Web-UI (Public Client, PKCE) |
| `GSSH_AUDIT_STREAM` | leer | `true` ⇒ committete Audit-Events als JSON-Logs auf stdout (SIEM) |
| `GSSH_AUDIT_WEBHOOK_URL` | leer | Audit-Events zusätzlich als JSON-Array an diesen Webhook |
| `GSSH_AUDIT_STREAM_INTERVAL` | `10s` | Poll-Intervall des Audit-Streamers (Go-Duration) |
| `GSSH_SIGN_RATE_PER_MINUTE` | `60` | Request-Budget pro Client-IP auf Sign-/Enroll-Endpunkten; `0` deaktiviert das Rate-Limiting komplett |
| `GSSH_SIGN_FAIL_PER_MINUTE` | `10` | Failure-Budget pro Client-IP (401/403-Antworten) |
| `GSSH_RATE_TRUST_PROXY` | leer | `true` ⇒ Client-IP aus dem letzten `X-Forwarded-For`-Eintrag (nur hinter vertrauenswürdigem Proxy/Ingress) |

## Secrets

Zwei Pflicht-Secrets (im Chart: `secrets.db.existingSecret` mit den einzelnen
Postgres-Verbindungsdaten, `secrets.ca.existingSecret` mit dem CA-Master-Key;
Key-Namen über `secrets.*.keys` anpassbar, Details im Chart-README):

- **`GSSH_DB_*`** — Datenbank-Zugang (Host, Port, Benutzer, Passwort, Name,
  SSL-Mode als einzelne Keys, kein DSN). Rotation: neues DB-Passwort setzen,
  Secret aktualisieren, Rollout; kein Datenverlust.
- **`GSSH_CA_MASTER_KEY`** — Erzeugung: `head -c 32 /dev/urandom | base64`
  (bzw. `openssl rand -base64 32`). Verschlüsselt alle CA-Private-Keys
  (User-, Host- und mTLS-CA) at rest. **Verlust des Master-Keys = Totalverlust
  der CA** — die verschlüsselten Keys in `ca_keys` sind dann unbrauchbar,
  alle Hosts müssten gegen eine neue CA re-enrollt werden. Sicher und
  redundant ablegen (SOPS/Vault + Offline-Kopie). Eine Rotation des
  Master-Keys selbst ist nicht implementiert (Umschlüsselung der `ca_keys`
  wäre ein manueller DB-Eingriff); der vorgesehene Weg bei Kompromittierung
  ist die CA-Rotation (unten) in Kombination mit neuem Master-Key und
  Re-Enrollment.

Optional: `GSSH_KC_CLIENT_SECRET` (Gruppen-Sync) sowie das Client-Secret des
GitOps-Sync-Service-Accounts (`GSSH_CLIENT_SECRET` für `gssh-admin`, siehe
Flux-README).

## Datenbank-Betrieb

- **Migrationen**: goose, embedded (ADR-012). Im Kubernetes-Deployment als
  Init-Container `gssh-server migrate` vor jedem Pod-Start; ein
  Postgres-Advisory-Session-Lock serialisiert parallele Replikas — Rollouts
  mit mehreren Replikas sind sicher. Der Server migriert beim Start ohnehin
  idempotent (ebenfalls mit Lock). Migrationen sind vorwärts-only und müssen
  abwärtskompatibel zur Vorversion sein (Helm-Rollback durch Flux).
- **Audit-Retention**: `audit_events` ist append-only (Trigger + DB-Grants)
  und nach Monat partitionierbar; Retention läuft über `DETACH`/`DROP`
  ganzer Partitionen, nie zeilenweise. Verfahren, Rollen-Schema und
  Empfehlung (18 Monate): [audit-retention.md](audit-retention.md).
- **DB-Rollen**: Anwendungsrolle ohne `UPDATE`/`DELETE`/`TRUNCATE` auf
  `audit_events`; Migrationen als Schema-Owner (siehe audit-retention.md).

## Monitoring

Prometheus-Metriken auf eigenem Listener (`-metrics-listen`, Chart-Port 9090,
nicht ingress-exponiert; `metrics.serviceMonitor.enabled=true` für den
Prometheus-Operator):

| Metrik | Labels | Bedeutung |
|---|---|---|
| `gssh_certificates_issued_total` | `requester` (user/ci/host), `cert_type` (user/host) | erfolgreich ausgestellte SSH-Zertifikate |
| `gssh_http_responses_total` | `code` | HTTP-Antworten nach Status-Code (API- und Agent-Endpunkte) |
| `gssh_agent_heartbeats_total` | — | Agent-Kontakte (erfolgreiche mTLS-Requests, stempeln `last_seen_at`) |

`GET /healthz` ist die Liveness-/Readiness-Probe (Chart-Default).

Sinnvolle Alerts:

- **Fehlerrate**: `rate(gssh_http_responses_total{code=~"5.."}[5m])` > 0
  anhaltend ⇒ Server-/DB-Problem.
- **Auth-Fehler-Spike**: steigende `code="401"`/`code="403"`-Rate ⇒
  IdP-Problem, abgelaufene Konfiguration oder Angriffsversuch (das
  Failure-Budget drosselt auf 429).
- **Rate-Limit greift**: `code="429"` dauerhaft > 0 ⇒ Limits prüfen
  (`GSSH_SIGN_RATE_PER_MINUTE`) oder Missbrauch untersuchen.
- **Agent-Heartbeats bleiben aus**:
  `rate(gssh_agent_heartbeats_total[15m]) == 0` bei enrollten Hosts ⇒
  Agent-API nicht erreichbar (Service/LoadBalancer/mTLS); Hosts laufen dann
  auf den Fail-closed-Cache zu (Logins scheitern nach `cache_ttl`).
- **Keine Ausstellungen**: `rate(gssh_certificates_issued_total[1h]) == 0`
  während üblicher Arbeitszeiten ⇒ Sign-Pfad prüfen.

Zusätzlich: strukturierte JSON-Logs auf stdout (`kubectl logs`), Audit-Events
per `GSSH_AUDIT_STREAM=true`/`GSSH_AUDIT_WEBHOOK_URL` ans SIEM
([web-ui.md](web-ui.md)).

## CA-Schlüssel-Rotation

Die CA unterstützt mehrere Keys pro Zweck mit Lebenszyklus
`active → retiring → retired` (`CA.Rotate`/`CA.RetireKey` in `internal/ca`):
`Rotate` legt einen neuen aktiven Key an und setzt bisherige auf `retiring`;
die Bundles (`GET /v1/ca/bundle/{user|host}`, Agent-Abruf stündlich)
enthalten aktive **und** retiring Keys — das Übergangsfenster, in dem alte
Zertifikate gültig bleiben. `RetireKey` entfernt einen Key endgültig aus dem
Bundle (auditiert als `ca.key_rotated`/`ca.key_retired`).

**Stand heute ist die Rotation nicht über Admin-API oder CLI exponiert** —
es gibt keinen Endpoint und kein `gssh-server`-Subkommando dafür. Auslösen
heißt derzeit: Eingriff auf Code-/DB-Ebene (die Zustandsübergänge sind
reine `ca_keys`-Updates; neuer Key erfordert die Verschlüsselung mit dem
Master-Key, also den Code-Pfad `CA.Rotate`). Für den Notfall
(CA-Kompromittierung) ist der Ablauf in [ADR-022](adr/022-revocation-kurze-laufzeiten.md)
als „Nuklearoption" beschrieben: neuen Key ausrollen, Agenten ziehen das
Bundle binnen einer Stunde, alten Key retiren ⇒ alle Alt-Zertifikate
ungültig; alle aktiven Nutzer brauchen eine Neuausstellung.

Die **mTLS-Client-Zertifikate der Agenten** rotieren dagegen automatisch
(bei 2/3 von 1 Jahr Laufzeit, `POST /v1/agent/renew-mtls`), ebenso die
**Host-Zertifikate** (bei 2/3 von 30 Tagen) — kein Betriebseingriff nötig.

## Rate-Limiting-Betrieb

Token-Bucket pro Client-IP auf `POST /v1/sign/user`, `POST /v1/sign/ci` und
`POST /v1/enroll` (`internal/api/ratelimit.go`):

- **Request-Budget**: Default 60/min, Burst 20 (bei konfigurierter Rate:
  Burst = max(10, Rate/3)).
- **Failure-Budget**: Default 10/min — nur 401/403-Antworten zehren es auf;
  ist es leer, kommt 429 (`Retry-After: 60`). Brute-Force-Schutz.
- Hinter Ingress/Proxy `GSSH_RATE_TRUST_PROXY=true` setzen (Chart-Default
  `config.rateLimit.trustProxy: true`), sonst zählt die Proxy-IP als ein
  Client und drosselt alle Nutzer gemeinsam. Ohne vertrauenswürdigen Proxy
  aus lassen — der Header ist fälschbar.
- `GSSH_SIGN_RATE_PER_MINUTE=0` deaktiviert das Limiting komplett (Lasttests).
- Speicherschutz: max. 65 536 getrackte IPs, inaktive Einträge (> 5 min)
  werden verdrängt. Body-Limit der Austausch-Endpunkte: 64 KiB.

## Revocation

Zusammenfassung von [ADR-022](adr/022-revocation-kurze-laufzeiten.md):

1. **Kurze Laufzeiten primär**: Benutzer-Zertifikate ≤ 16 h, CI ≤ 1 h
   (zusätzlich auf Token-`exp` = Job-Timeout gedeckelt), Host 30 Tage.
2. **Schneller Entzug über die Principals-Auskunft**: Grant entziehen,
   Benutzer deaktivieren oder IdP-Gruppe entfernen wirkt unabhängig von der
   Restlaufzeit ausgestellter Zertifikate — Host-seitig innerhalb der
   Cache-TTL (Default 5 min) + Sync-Intervall (5 min), also ~10 min;
   fail-closed bei nicht erreichbarer API.
3. **mTLS-Agenten**: Identität wird pro Request über den Host-Datensatz
   aufgelöst — gelöschter Host ⇒ Zertifikat sofort wirkungslos.
4. **KRL/`RevokedKeys`-Verteilung**: bewusst noch nicht implementiert
   (geplante Ausbaustufe).
5. **Nuklearoption**: CA-Rotation (oben).

## Backup & Restore

- **Alles Zustandsbehaftete liegt in PostgreSQL** — reguläre
  Postgres-Backups (pg_dump/PITR bzw. CloudNativePG-Backup) sichern die
  komplette Plattform: Hosts, Grants, Zertifikats-Metadaten, Audit,
  `ca_keys`.
- Die CA-Keys im Backup sind AES-256-GCM-verschlüsselt — **ein DB-Backup
  ohne den zugehörigen `GSSH_CA_MASTER_KEY` ist für die CA wertlos**.
  Master-Key getrennt vom Backup sichern (und getrennt von der DB, das ist
  der Sinn der Verschlüsselung).
- Restore: Datenbank wiederherstellen, Secrets (DSN, Master-Key) unverändert
  bereitstellen, Deployment starten — Migrationen laufen idempotent. Agenten
  und CLIs brauchen nichts Neues, solange `ca_keys` und `hosts` erhalten sind.
- Audit-Langzeitarchiv: abgehängte Monatspartitionen vor dem `DROP`
  exportieren (audit-retention.md); SIEM-Streaming reduziert die
  Abhängigkeit von langer DB-Retention.

## Upgrades

- **Helm/Flux**: staging folgt einem Versions-Range, production pinnt exakt;
  Bump per Merge-Request, Flux rollt aus (Flux-README). Der Docker-Tag folgt
  der Chart-`appVersion`.
- **Zero-Downtime**: `replicaCount ≥ 2` (bzw. HPA `minReplicas: 2`),
  `podDisruptionBudget.enabled=true` (`minAvailable: 1`); RollingUpdate des
  Deployments hält die Sign-Endpoints verfügbar.
- **Migrationen beim Rollout**: Init-Container `migrate` mit Advisory-Lock —
  neue und alte Replikas laufen während des Rollouts gegen dasselbe Schema,
  deshalb müssen Migrationen abwärtskompatibel zur Vorversion sein
  (vorwärts-only; Rollback via `upgrade.remediation.retries` rollt nur die
  Anwendung zurück, nicht das Schema).
- Kompletter Pfad automatisiert testbar: `hack/flux-upgrade-test.sh`
  (kind + Flux, Install → Bump → Upgrade inkl. Migrationslauf).
- Host-Agenten sind unabhängig versioniert (deb/rpm); die Agent-API ist
  abwärtskompatibel zu behandeln — Agenten-Updates per Paketmanagement,
  kein Re-Enrollment nötig.
