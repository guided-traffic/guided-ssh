# Troubleshooting

Echte Fehlerbilder mit Ursache → Diagnose → Fix. Die zitierten Meldungen
stammen aus dem Code (Stand Phase 13). Grundlagen:
[Betriebs-Handbuch](betriebshandbuch.md), [Enrollment-Guide](enrollment-guide.md),
[Grants](grants.md), [GitLab-CI](gitlab-ci.md).

## Login/Ausstellung schlägt fehl (`gssh login` / `POST /v1/sign/user`)

### 401 — „id-token ungültig" / „authorization: bearer-token fehlt"

- **Ursache**: ID-Token abgelaufen, falsche Audience (Token nicht für
  `GSSH_OIDC_CLIENT_ID` ausgestellt), falscher Issuer oder kaputte Signatur
  (JWKS). Der Grund steht serverseitig im Log (`sign/user: token abgelehnt`),
  die 401-Antwort ist bewusst generisch.
- **Diagnose**: Server-Log (`kubectl logs`) zum Zeitpunkt des Versuchs;
  Token-Claims prüfen (iss/aud/exp).
- **Fix**: Client neu anmelden (`gssh login` holt Tokens frisch); im IdP
  prüfen, dass der CLI-Client die erwartete Audience liefert. Geht die
  Server-Uhr vor, lehnt go-oidc frische Tokens als abgelaufen ab (kein
  Leeway auf `exp`) — NTP sicherstellen.

### 403 — „keine zugriffsregeln (grants) für diesen benutzer"

- **Ursache**: Der Benutzer hat über seine Gruppen keinen einzigen Grant —
  ohne Grant kein Zertifikat (ADR-018).
- **Diagnose**: `gssh-admin grant list`; Gruppen im Token bzw. Web-UI
  (Benutzer & Gruppen) mit den Grant-Gruppen abgleichen; Server-Log nennt
  `subject` und `groups`.
- **Fix**: Grant für eine Gruppe des Benutzers anlegen bzw. Benutzer im IdP
  in die richtige Gruppe aufnehmen (Sync-Intervall Default 5 m abwarten oder
  frisches Token verwenden — die Gruppen kommen bei der Ausstellung aus den
  Token-Claims).

### 403 — „benutzer ist deaktiviert"

- **Ursache**: Der Gruppen-Sync hat den Benutzer als inaktiv markiert
  (Offboarding).
- **Fix**: Wenn beabsichtigt: nichts. Sonst IdP-Konto prüfen; nach dem
  nächsten Sync (5 m) wird der Benutzer reaktiviert.

### 429 — „zu viele anfragen — bitte später erneut versuchen"

- **Ursache**: Rate-Limit pro Client-IP: Request-Budget (Default 60/min,
  Burst 20) erschöpft — oder das **Failure-Budget** (Default 10/min): schon
  10 aufeinanderfolgende 401/403 sperren weitere Versuche, auch wenn das
  Request-Budget noch Deckung hätte.
- **Diagnose**: Metrik `gssh_http_responses_total{code="429"}`; vorher
  gehäufte 401/403 derselben Quelle? Hinter Ingress ohne
  `GSSH_RATE_TRUST_PROXY=true` zählen alle Nutzer als eine IP (die des
  Proxys) und drosseln sich gegenseitig.
- **Fix**: `Retry-After: 60` respektieren; Grundproblem der Fehlversuche
  beheben; hinter Proxy `GSSH_RATE_TRUST_PROXY=true` setzen; Limits über
  `GSSH_SIGN_RATE_PER_MINUTE`/`GSSH_SIGN_FAIL_PER_MINUTE` anpassen.

### 503 — „oidc nicht konfiguriert"

- **Ursache**: `GSSH_OIDC_ISSUER` ist auf dem Server nicht gesetzt —
  `/v1/sign/user` ist gezielt deaktiviert.
- **Fix**: `config.oidc.issuer`/`clientID` im Helm-Values setzen und ausrollen.

## gssh-Fehlermeldungen (Client-seitig)

### „SSH_AUTH_SOCK nicht gesetzt — läuft ein ssh-agent?"

- **Ursache**: Kein ssh-agent in der Session — gssh legt Schlüssel und
  Zertifikat ausschließlich in den Agenten (ADR-016).
- **Fix**: `eval $(ssh-agent -s)` (in CI-Jobs Pflicht vor `gssh ci-login`)
  bzw. den Agenten der Desktop-Session nutzen.

### „konfiguration …: pflichtfelder fehlen: api_url, issuer, client_id"

- **Ursache**: `~/.config/guided-ssh/config.yaml` unvollständig (die drei
  Felder sind Pflicht).
- **Fix**: Datei ergänzen; bei fehlender Datei druckt gssh einen
  Beispielinhalt. Pfad-Override: `--config` bzw. `GSSH_CONFIG`.

### `gssh status` liefert Exit-Code 1

- Kein gültiges guided-ssh-Zertifikat im Agenten — gewollt skriptbar.
  `gssh login` (oder `--if-needed` in der Match-exec-Integration).

## Host-Login scheitert (Zertifikat vorhanden, sshd lehnt ab)

### AuthorizedPrincipalsCommand liefert nichts — fail-closed

- **Ursache**: API nicht erreichbar **und** Principals-Cache älter als
  `cache_ttl` (Default 5 m) — der Helper verweigert dann bewusst
  (Daemon-Log: „api nicht erreichbar und cache abgelaufen" bzw.
  „principals nicht verfügbar (fail-closed)"). Oder der Daemon läuft gar
  nicht („gssh-agentd nicht erreichbar (läuft der dienst?)").
- **Diagnose**: auf dem Host `gssh-agentd principals -user <name>`;
  `journalctl -u gssh-agentd`; serverseitig Agent-Erreichbarkeit
  (`gssh_agent_heartbeats_total`, LoadBalancer/mTLS-Service).
- **Fix**: Dienst starten (`systemctl start gssh-agentd`); Netzpfad zur
  Agent-API reparieren. Bestehende SSH-Sessions sind nicht betroffen — nur
  neue Logins.

### Grant/Tag-Selektor passt nicht

- **Ursache**: Für den lokalen Ziel-Benutzer `%u` existiert kein Grant,
  dessen Tag-Selektor auf die Host-Tags passt (Selektor ⊆ Tags), oder der
  anfragende Benutzer ist kein aktives Mitglied der Grant-Gruppe. Der Helper
  liefert dann eine leere/fremde Principals-Liste — sshd lehnt ab.
- **Diagnose**: `gssh-agentd principals -user <ziel-user>` auf dem Host —
  steht der Identitäts-Principal (Username/E-Mail) des Nutzers in der
  Ausgabe? Host-Tags und Grants in der Web-UI abgleichen.
- **Fix**: Grant anpassen (`gssh-admin grant …`) oder Host mit passenden
  Tags enrollen. Änderungen wirken innerhalb der Cache-TTL (5 m).

### Zertifikat abgelaufen

- **Diagnose**: `gssh status` (zeigt „abgelaufen") oder `ssh -vvv` (Server
  ignoriert das Zertifikat).
- **Fix**: `gssh login`; für transparente Erneuerung `gssh integrate`
  (erneuert bei < 5 m Restlaufzeit).

### TrustedUserCAKeys veraltet (nach CA-Rotation)

- **Ursache**: Host hat den neuen CA-Key noch nicht — das Bundle wird nur
  alle `bundle_interval` (Default 1 h) geholt, oder der Agent lief nicht.
- **Diagnose**: `/etc/ssh/guided-ssh-user-ca.pub` mit
  `GET /v1/ca/bundle/user` vergleichen; Daemon-Log („user-ca-bundle
  aktualisiert" fehlt).
- **Fix**: `systemctl restart gssh-agentd` (holt das Bundle sofort initial).

## Enrollment-Fehler

### 403 — „enrollment-token ungültig, verbraucht oder abgelaufen"

- **Ursache**: Token bereits benutzt (Single-Use, transaktional), TTL
  abgelaufen oder Tippfehler.
- **Fix**: Neues Token erzeugen (`gssh-server enroll-token`).

### 403 — „enrollment-token ist an einen anderen hostnamen gebunden"

- **Ursache**: Token wurde mit `-name` erzeugt und der Host meldet sich mit
  anderem Hostnamen (`os.Hostname()` weicht ab).
- **Fix**: `--hostname` beim Enroll passend setzen oder Token ohne
  Namensbindung erzeugen.

### „ssh-host-key lesen (sshd installiert? ssh-keygen -A)"

- **Ursache**: `/etc/ssh/ssh_host_ed25519_key.pub` fehlt.
- **Fix**: `ssh-keygen -A` bzw. `--ssh-key` auf einen vorhandenen Key zeigen.

## Agent-Probleme

### mTLS-Zertifikat abgelaufen

- **Ursache**: Agent war länger als das Rotationsfenster aus (Rotation läuft
  bei 2/3 von 1 Jahr über den noch gültigen Kanal — ist das Zertifikat erst
  einmal abgelaufen, gibt es keinen Kanal mehr).
- **Diagnose**: Daemon-Log: TLS-Handshake-Fehler bei jedem API-Kontakt;
  `openssl x509 -in /var/lib/guided-ssh/agent.crt -noout -enddate`.
- **Fix**: Re-Enrollment mit neuem Token ([enrollment-guide.md](enrollment-guide.md) §7).

### `agentd.sock` fehlt

- **Ursache**: Daemon läuft nicht (der Socket wird bei jedem Start neu
  angelegt) oder abweichender `socket_path`/`-state-dir` zwischen Daemon und
  sshd-Snippet.
- **Diagnose**: `systemctl status gssh-agentd`; `ls -l /var/lib/guided-ssh/agentd.sock`;
  Snippet und `config.yaml` auf denselben `-state-dir` prüfen.
- **Fix**: Dienst starten; Pfade angleichen.

## CI-Fehler (`gssh ci-login` / `POST /v1/sign/ci`)

### 401 — „job-token ungültig"

- **Ursache**: meist falsche Audience — `id_tokens` im Job ohne
  `aud: guided-ssh` (bzw. abweichend von `GSSH_CI_AUDIENCE`); oder
  `GSSH_CI_ISSUER` zeigt nicht auf die GitLab-Instanz des Jobs.
- **Fix**: `.gitlab-ci.yml` gemäß [gitlab-ci.md](gitlab-ci.md) (Abschnitt
  Referenz-Pipeline).

### 403 — „kein passender ci-grant für dieses projekt/ref"

- **Ursache**: Kein CI-Grant matcht — häufig: Ref nicht geschützt
  (`protected_only` ist per Default `true`), Projekt-Pfad stimmt nicht mit
  dem Grant überein (Mismatch nach Projekt-Umzug/-Umbenennung), oder
  `ref`/`environment`-Glob passt nicht.
- **Diagnose**: Server-Log nennt `project`, `ref`, `ref_protected`,
  `environment`; `gssh-admin ci-grant list`.
- **Fix**: Branch schützen oder CI-Grant anpassen.

### 403 — „ci-zugang für dieses projekt ist deaktiviert"

- **Ursache**: Der Service-Account des Projekts steht auf `active=false`
  (Not-Aus, z. B. über die Web-UI).
- **Fix**: bewusste Entscheidung prüfen; ggf. in der Web-UI reaktivieren.

### 400 — „job-token läuft zu bald ab für ein zertifikat"

- **Ursache**: Token-`exp` (= Job-Timeout) liegt praktisch in der
  Gegenwart — die Laufzeit wird auf `exp` gedeckelt, es bliebe nichts übrig.
- **Fix**: `gssh ci-login` früh im Job ausführen; Job-Timeout prüfen.

### Serverstart scheitert mit „gleicher issuer und gleiche audience …"

- **Ursache**: `checkAudienceSeparation` — Benutzer-OIDC und GitLab-CI sind
  auf denselben Issuer konfiguriert **und** `GSSH_CI_AUDIENCE` ==
  `GSSH_OIDC_CLIENT_ID`. Tokens wären an beiden Sign-Endpunkten
  austauschbar; der Server verweigert den Start (Security-Review Phase 10).
- **Fix**: getrennte Audiences (oder getrennte Issuer) konfigurieren.

## Server-Startfehler

| Meldung | Ursache → Fix |
|---|---|
| `GSSH_OIDC_ISSUER ist gesetzt, aber GSSH_OIDC_CLIENT_ID fehlt` | fail-fast statt stiller Ablehnung aller Tokens → Client-ID setzen |
| `datenbank-konfiguration unvollständig: GSSH_DB_… nicht gesetzt` | Secret fehlt/Key-Mapping falsch (`secrets.db.existingSecret`, Keys via `secrets.db.keys`) |
| `GSSH_CA_MASTER_KEY dekodieren: …` | Wert ist kein gültiges Base64 → korrekt erzeugen (`head -c 32 /dev/urandom \| base64`) |
| `ca: ungültiger master-key: <n> Bytes statt 32` | Wert dekodiert nicht zu 32 Bytes → 32-Byte-Key verwenden |
| `ca: ungültiger master-key: entschlüsselung fehlgeschlagen` | Master-Key passt nicht zu den bereits verschlüsselten `ca_keys` (vertauschtes Secret zwischen Umgebungen) → richtigen Key einspielen; **nicht** die DB „bereinigen" — das wäre eine neue CA |
| `migrationen: …` | DB-Verbindungsdaten/Netz/DB-Rechte prüfen; Advisory-Lock: hängt eine andere Instanz in der Migration? |

## Clock-Skew

- Zertifikate werden 1 min rückdatiert (`signBackdate`); die Policy erlaubt
  maximal 5 min Rückdatierung (`maxBackdate`). Hosts, deren Uhr mehr als
  ~1 min **vor** der Server-Uhr geht, lehnen frisch ausgestellte Zertifikate
  als „not yet valid" ab (sichtbar in `ssh -vvv`).
- go-oidc prüft `exp` ohne Leeway — geht die **Server**-Uhr vor, werden
  frische ID-Tokens als abgelaufen abgelehnt (401).
- **Fix**: NTP auf Server, Hosts und IdP (im Kubernetes-Deployment gegeben;
  bei Bare-Metal-Hosts prüfen: `timedatectl`).

## Diagnose-Werkzeuge

| Werkzeug | Wofür |
|---|---|
| Web-UI → Audit (Rolle Auditor) bzw. `GET /v1/admin/audit?event_type=…&actor=…&q=…` | jede Ausstellung/Grant-Änderung/Session; `q` matcht Actor + Payload (Host, Pipeline); Export CSV/JSON |
| `gssh status` | Zertifikate im Agenten, Restlaufzeit, Principals; Exit-Code skriptbar |
| `ssh -vvv user@host` | zeigt, ob das Zertifikat angeboten und warum es abgelehnt wird |
| `gssh-agentd principals -user <name>` (auf dem Host) | genau das, was sshd sieht — leere Ausgabe/Fehler erklärt jeden abgelehnten Login |
| `journalctl -u gssh-agentd` / `journalctl -u sshd` | Agent-JSON-Logs (Renewals, fail-closed-Warnungen); sshd mit `LogLevel VERBOSE` loggt den Zertifikats-Serial |
| `kubectl logs deploy/guided-ssh` | Server-Logs: abgelehnte Tokens mit Grund, Enrollments, Sync-Läufe |
| Metriken (`/metrics`, Port 9090) | `gssh_http_responses_total{code}` (Fehlerraten, 429), `gssh_agent_heartbeats_total`, `gssh_certificates_issued_total` |
| `sshd -t` | sshd-Konfiguration (Snippet) validieren |
