# ADR-016: CLI `gssh` — Agent-only-Schlüssel, stdlib-Subkommandos, SPKI-Pinning, Match-exec-Integration

- Status: akzeptiert
- Datum: 2026-07-19

## Kontext

Phase 4 liefert das Benutzer-CLI: `gssh login` (SSO-Flow, ephemerales
Schlüsselpaar, Zertifikat in den `ssh-agent`), transparente Integration in
natives `ssh`, `status`/`logout`, eine Konfigurationsdatei mit
Fingerprint-Pinning sowie Cross-Platform-Builds. Der Plan verlangt explizit:
keine Persistenz von Schlüsseln oder Zertifikaten auf Platte.

## Entscheidung

- **Kommandostruktur**: Subkommandos (`login`, `ssh`, `status`, `logout`,
  `integrate`, `version`) mit stdlib `flag` pro Subkommando — kein
  cobra/urfave (keine neue Abhängigkeit, fünf Kommandos rechtfertigen kein
  Framework). Logik liegt testbar in `internal/cli`; `cmd/gssh` ist ein
  Einzeiler.
- **Agent-only**: Pro Login entsteht ein frisches Ed25519-Schlüsselpaar im
  Speicher; Private Key + Zertifikat gehen ausschließlich per
  `SSH_AUTH_SOCK` in den Agenten (`AddedKey` mit `LifetimeSecs` =
  Restlaufzeit des Zertifikats — der Agent räumt selbst auf). Einträge
  tragen den Comment-Präfix `guided-ssh`, darüber finden `status`, `logout`
  und der Auto-Login die eigenen Einträge. Verlust des Agenten ⇒ einfach neu
  anmelden.
- **Transparentes `ssh`**: `Match exec`-Integration statt ProxyCommand.
  `gssh integrate` gibt den Schnipsel aus
  (`Match host "<muster>" exec "gssh login --if-needed"`); der Login ist
  Seiteneffekt der Config-Auswertung, natives `ssh` bleibt der Transport.
  ProxyCommand müsste den Kanal selbst stellen (stdio-Proxy, bricht
  ControlMaster, mehr Code). Zusätzlich `gssh ssh <args…>` als Wrapper
  (Auto-Login, dann `exec ssh` mit unveränderten Argumenten).
- **Erneuerung**: Auto-Login erneuert, wenn die Restlaufzeit < 5 Minuten ist
  (Clock-Skew, Verbindungsaufbau).
- **Konfiguration**: `~/.config/guided-ssh/config.yaml` (XDG), yaml.v3 (im
  Modul bereits transitiv vorhanden). Felder: `api_url`, `issuer`,
  `client_id`, optional `scopes`, `pin_sha256`, `validity`. Pfad-Override:
  `--config` bzw. `GSSH_CONFIG` (letzteres nötig, weil `gssh ssh` alle
  Argumente unverändert an ssh durchreicht).
- **Fingerprint-Pinning**: `pin_sha256` = Base64-kodierter SHA-256 über den
  SubjectPublicKeyInfo des API-Serverzertifikats (wie HPKP /
  `curl --pinnedpubkey`). Gesetzt ersetzt der Pin die CA-/Hostname-Prüfung
  vollständig (`VerifyPeerCertificate`) — deckt selbstsignierte Deployments
  ab. Gilt nur für die gssh-API; der IdP wird normal über System-CAs
  validiert.

## Konsequenzen

- Keine neuen direkten Abhängigkeiten außer yaml.v3 (war schon transitiv).
- `ssh-add -l` zeigt die Einträge als `guided-ssh user:<sub>@<issuer>`;
  fremde Agent-Einträge werden nie angefasst.
- Die Match-exec-Ausgaben unterdrückt ssh; der Browser-Flow funktioniert
  trotzdem, headless-Umgebungen nutzen vorher `gssh login --device`.
- `gssh status` liefert Exit-Code 1 ohne gültiges Zertifikat (skriptbar).
- Windows (named-pipe-Agent) ist bewusst außen vor; Zielplattformen laut
  Plan: linux/amd64, linux/arm64, darwin/arm64 (`make cross`, läuft in CI).
