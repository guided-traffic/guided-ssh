# Host-Enrollment — Schritt für Schritt

Registriert einen Linux-Host bei der Plattform: der Host erhält ein
SSH-Host-Zertifikat und ein mTLS-Client-Zertifikat, sshd wird für
Zertifikats-Authentifizierung konfiguriert, der Agent `gssh-agentd` hält
alles aktuell (ADR-017). Betriebssicht: [betriebshandbuch.md](betriebshandbuch.md);
Fehlerbilder: [troubleshooting.md](troubleshooting.md).

## 1. Voraussetzungen

- Laufender **sshd** mit vorhandenen Host-Keys — fehlen sie:
  `ssh-keygen -A`. Der Agent nutzt standardmäßig
  `/etc/ssh/ssh_host_ed25519_key.pub` (Override: `--ssh-key`).
- Die Haupt-`sshd_config` muss das Konfigurationsverzeichnis einbinden:

  ```
  Include /etc/ssh/sshd_config.d/*.conf
  ```

  (bei den meisten Distributionen Standard; ohne das Include bleibt der
  generierte Schnipsel wirkungslos).
- Netzzugang zum gssh-server: öffentliche API (`POST /v1/enroll`) und
  Agent-API (mTLS, Port 8443 — TLS-Passthrough/LoadBalancer, siehe
  Chart-README).
- root-Rechte auf dem Host (schreibt nach `/etc/ssh` und `/var/lib/guided-ssh`).

## 2. Paket installieren

**deb/rpm** (gebaut mit nfpm, `make packages`; Inhalt: Binary
`/usr/bin/gssh-agentd`, systemd-Unit `/lib/systemd/system/gssh-agentd.service`):

```sh
dpkg -i gssh-agentd_<version>_amd64.deb     # bzw. rpm -i …
```

Das postinstall-Skript legt `/var/lib/guided-ssh` (0700) an und lädt systemd
neu; der Dienst wird bewusst **nicht** gestartet — erst nach dem Enrollment.

**Ohne Paketmanager** — Install-Skript lädt das Binary aus dem
GitHub-Release:

```sh
curl -fsSL https://raw.githubusercontent.com/guided-traffic/guided-ssh/main/deploy/packaging/install.sh \
  | sh -s -- v0.3.0
```

## 3. Enrollment-Token erzeugen (auf dem Server)

```sh
gssh-server enroll-token -name web01.example.com -tags env=prod,role=web -ttl 24h
```

| Flag | Default | Bedeutung |
|---|---|---|
| `-name` | leer | Token an genau diesen Hostnamen binden (empfohlen); anderer Hostname beim Enroll ⇒ 403 |
| `-tags` | leer | Host-Tags (`k=v,…`); Token-Tags haben Vorrang vor `--tags` beim Enroll |
| `-ttl` | `24h` | Gültigkeitsdauer des Tokens |

Der Klartext (`gssh-et-…`, 256 bit Zufall) geht einmalig nach stdout — in
der Datenbank liegt nur der SHA-256-Hash. Das Token ist **Single-Use**: der
Verbrauch ist transaktional, ein zweiter Versuch liefert 403. Das Kommando
braucht `GSSH_DB_DSN` (z. B. via `kubectl exec` im Server-Pod ausführen).

## 4. Host registrieren

```sh
gssh-agentd enroll \
  --server https://gssh.example.com \
  --agent-url https://gssh-agent.example.com:8443 \
  --token gssh-et-…
```

Alle Flags:

| Flag | Default | Bedeutung |
|---|---|---|
| `--server` | — (Pflicht) | öffentliche API des gssh-servers (`POST /v1/enroll`) |
| `--agent-url` | — (Pflicht) | mTLS-Agent-API für den späteren Betrieb |
| `--token` | — (Pflicht) | einmaliges Enrollment-Token |
| `--hostname` | `os.Hostname()` | Name, unter dem sich der Host registriert |
| `--tags` | leer | Host-Tags `k=v,…` (Token-Tags gewinnen serverseitig) |
| `--pin` | leer | SPKI-SHA-256-Pin (Base64) des Enroll-Endpoints — für selbstsignierte Deployments |
| `--state-dir` | `/var/lib/guided-ssh` | State-Verzeichnis des Agenten |
| `--ssh-dir` | `/etc/ssh` | sshd-Konfigurationsverzeichnis |
| `--ssh-key` | `<ssh-dir>/ssh_host_ed25519_key.pub` | SSH-Host-Public-Key, dessen Zertifikat gepflegt wird |
| `--session-audit` | aus | Host-Session-/sudo-Audit aktivieren (pam_exec-Hooks, Opt-in, ADR-021) |

Was das Enrollment schreibt (idempotent; ein Re-Enrollment mit neuem Token
überschreibt):

**State-Verzeichnis** (`/var/lib/guided-ssh`, 0700):

| Datei | Inhalt |
|---|---|
| `agent.key` (0600) | privater mTLS-Schlüssel (Ed25519, frisch erzeugt) |
| `agent.crt` | mTLS-Client-Zertifikat (CN = Host-UUID, vom Server vergeben) |
| `server-ca.pem` | mTLS-CA zum Verifizieren der Agent-API |
| `config.yaml` (0600) | Agent-Konfiguration (unten) |
| `socket-token` (0600) | nur bei `--session-audit`: Token der schreibenden Socket-Endpunkte |

**sshd** (`/etc/ssh`):

| Datei | Inhalt |
|---|---|
| `ssh_host_ed25519_key-cert.pub` | Host-Zertifikat (Pfad = Public-Key-Pfad mit `-cert.pub`) |
| `guided-ssh-user-ca.pub` | `TrustedUserCAKeys`-Bundle der Benutzer-CA |
| `sshd_config.d/guided-ssh.conf` | generierter Schnipsel (nicht manuell editieren) |

Der Schnipsel:

```
TrustedUserCAKeys /etc/ssh/guided-ssh-user-ca.pub
HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub
AuthorizedPrincipalsCommand /usr/bin/gssh-agentd principals -state-dir /var/lib/guided-ssh -user %u
AuthorizedPrincipalsCommandUser root
```

Mit `--session-audit` zusätzlich `LogLevel VERBOSE`, und der Helper bekommt
`-serial %s -keyid %i` (Korrelation Session ↔ Zertifikat); außerdem wird an
`/etc/pam.d/sshd` und `/etc/pam.d/sudo` idempotent ein Hook angehängt
(Marker `# guided-ssh session audit (managed)`):

```
session optional pam_exec.so quiet /usr/bin/gssh-agentd pam-session -state-dir /var/lib/guided-ssh
```

`optional` + Helper-Exit 0 ⇒ fail-open: der Hook blockiert niemals Login
oder sudo.

## 5. Dienst starten und verifizieren

```sh
sshd -t                              # Konfiguration prüfen
systemctl reload sshd                # sshd liest HostCertificate nur beim Start/Reload
systemctl enable --now gssh-agentd
```

Verifikation:

```sh
# Daemon läuft und beantwortet Principals-Anfragen?
gssh-agentd principals -user deploy
# → eine Zeile pro autorisiertem Principal; Fehler ⇒ Dienst/Grants prüfen

journalctl -u gssh-agentd            # JSON-Logs des Agenten

# Login-Test von einem Client mit gültigem Zertifikat:
gssh login && gssh ssh deploy@web01.example.com true
```

Erscheint beim Login-Test ein Host-Key-Prompt, fehlt dem Client das
Host-CA-Vertrauen — `@cert-authority`-Zeile aus `GET /v1/ca/bundle/host` in
die `known_hosts` aufnehmen.

## 6. Betrieb des Agenten

Systemd-Unit (`deploy/packaging/gssh-agentd.service`): `gssh-agentd run`,
`Restart=on-failure`, `ProtectSystem=full` mit `ReadWritePaths=/var/lib/guided-ssh /etc/ssh`,
`NoNewPrivileges`.

Der Daemon übernimmt:

- **Host-Zertifikat erneuern** bei 2/3 der Laufzeit (Laufzeit 30 Tage;
  Prüfintervall `renew_interval`, Default 5 m) über `POST /v1/agent/renew`.
  Danach läuft `reload_command`, falls konfiguriert — sshd liest das
  `HostCertificate` nur beim Start.
- **mTLS-Client-Zertifikat rotieren** bei 2/3 der Laufzeit (1 Jahr): frisches
  Schlüsselpaar + CSR über den noch gültigen mTLS-Kanal
  (`POST /v1/agent/renew-mtls`), atomarer Dateitausch, Umschalten ohne
  Neustart. Fehlversuche sind unkritisch, solange das alte Zertifikat gültig
  ist.
- **CA-Bundle pflegen** (`TrustedUserCAKeys`-Datei): Abruf alle
  `bundle_interval` (Default 1 h), geschrieben nur bei Änderung — so kommen
  CA-Rotationen auf die Hosts.
- **Principals-Cache + Unix-Socket** (`agentd.sock`) für den sshd-Helper:
  Antworten jünger als 10 s kommen direkt aus dem Cache; sonst API-Abfrage
  mit 5-s-Timeout; bei nicht erreichbarer API trägt der (über Neustarts
  persistierte) Cache bis `cache_ttl` — **danach fail-closed**, Logins
  werden verweigert.
- Bei `--session-audit`: Session-/sudo-Events aus dem lokalen Spool
  (`sessions-spool.jsonl`, verlust-tolerant) alle 15 s per mTLS an
  `POST /v1/agent/sessions` flushen.

`config.yaml` im State-Verzeichnis (beim Enrollment geschrieben, manuell
anpassbar; danach `systemctl restart gssh-agentd`):

| Feld | Default | Bedeutung |
|---|---|---|
| `agent_url` | aus Enrollment | mTLS-Agent-API des Servers |
| `host_id` | aus Enrollment | vergebene Host-UUID |
| `host_name` | aus Enrollment | registrierter Hostname |
| `ssh_key_path` | aus Enrollment | Host-Public-Key, dessen Zertifikat gepflegt wird |
| `ssh_dir` | `/etc/ssh` | Ziel für Bundle/Zertifikat/Schnipsel |
| `socket_path` | `<state-dir>/agentd.sock` | Unix-Socket des Principals-Helpers |
| `cache_ttl` | `5m` | wie lange gecachte Principals bei API-Ausfall noch gelten (danach fail-closed) |
| `bundle_interval` | `1h` | Aktualisierungsintervall des CA-Bundles |
| `renew_interval` | `5m` | Prüfintervall Zertifikats-/mTLS-Erneuerung |
| `reload_command` | leer | Kommando nach neuem Host-Zertifikat, z. B. `systemctl reload sshd` |
| `session_audit` | `false` | Session-/sudo-Audit (nur via `enroll --session-audit` sinnvoll setzbar) |

Hinweis zur `cache_ttl`: höhere Werte überbrücken längere API-Ausfälle,
verlängern aber auch das Fenster, in dem entzogene Berechtigungen auf diesem
Host noch wirken (ADR-022).

## 7. Re-Enrollment

Neues Token erzeugen und `gssh-agentd enroll` erneut ausführen — alle
Dateien werden überschrieben (neues mTLS-Schlüsselpaar, neues
Host-Zertifikat, frische Konfiguration); ein vorhandenes `socket-token`
bleibt erhalten. Nötig z. B. bei abgelaufenem mTLS-Zertifikat (Agent war
lange aus) oder Wechsel der Server-URL. Danach `systemctl restart
gssh-agentd` und `systemctl reload sshd`.

## 8. Deinstallation

1. `systemctl disable --now gssh-agentd`
2. Paket entfernen (`apt remove gssh-agentd` / `rpm -e gssh-agentd`).
3. sshd zurückbauen: `/etc/ssh/sshd_config.d/guided-ssh.conf`,
   `/etc/ssh/guided-ssh-user-ca.pub` und
   `/etc/ssh/ssh_host_ed25519_key-cert.pub` löschen, `systemctl reload sshd`
   — der Host akzeptiert dann keine Zertifikats-Logins mehr.
4. Bei aktivem Session-Audit: die von guided-ssh markierten Zeilen
   (`# guided-ssh session audit (managed)` + `session optional pam_exec.so …`)
   aus `/etc/pam.d/sshd` und `/etc/pam.d/sudo` entfernen.
5. State löschen: `rm -rf /var/lib/guided-ssh`.
6. Serverseitig den Host-Datensatz entfernen (macht das mTLS-Zertifikat
   sofort wirkungslos, ADR-022); ein API-/CLI-Endpunkt dafür existiert noch
   nicht — Eingriff auf DB-Ebene (`hosts`).
