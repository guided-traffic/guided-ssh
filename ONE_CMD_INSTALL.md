# One-Command Host-Install

Ziel: Auf der Web-Page **Hosts** ein Button „Host hinzufügen“. Klick zeigt ein
einmaliges Enrollment-Token plus eine **eine Zeile**, die man auf der CLI eines
Linux-Hosts einfügt und die den Agenten **vollständig installiert** — Binary,
systemd-Unit, Enrollment, Dienststart. Die passenden Agent-Binaries liegen **im
Container** (versionsgleich zum laufenden Server), Download läuft rein intern,
kein Umweg über GitHub-Releases.

---

## Machbarkeit: JA

Alle Bausteine existieren bereits, es fehlt Verdrahtung, kein neues Konzept:

| Baustein | Status heute | Was fehlt |
|---|---|---|
| Web-Bundling ins Server-Binary | `web/embed.go` → `//go:embed all:dist`, Server importiert `web.Dist` | zweites Embed für Agent-Binaries |
| Cross-Build Agent (linux/amd64+arm64) | `make cross` baut `bin/gssh-agentd-linux-<arch>` mit `-ldflags` Version | im Dockerfile-Build-Stage einhängen |
| Token-Erzeugung | `gssh-server enroll-token` + `store.CreateEnrollmentToken` (Hash in DB, Klartext nach stdout) | Admin-API-Endpoint statt nur CLI |
| Host-Enrollment | `gssh-agentd enroll --server --agent-url --token [--pin]` (idempotent) | unverändert nutzbar |
| Manuelles Install-Script | `deploy/packaging/install.sh` zieht Binary aus GitHub-Release | server-templated Variante, Download vom Server |
| Getrennte Listener | Public-Mux (UI/Admin/enroll) und mTLS-Agent-Mux (`/v1/agent/…`) getrennt (`New` vs `NewAgent`) | neue Public-Routen unter Prefix `/v1/agents/` (kein Konflikt) |
| Externe URL | `GSSH_UI_BASE_URL`, sonst aus Request-Host abgeleitet | zusätzlich externe Agent-URL nötig |

**Versionsgleichheit** ist geschenkt: Agent-Binaries werden im **selben
Docker-Build** wie der Server erzeugt (gleiche `-ldflags`, gleicher Commit) und
ins Server-Image gelegt. Der Server serviert exakt das Binary, das zu ihm passt —
kein Netz nach außen, air-gap-tauglich.

**Alle Arches, immer, unabhängig von der Server-Arch.** Der Host kann eine andere
Architektur haben als der Server (amd64-Server, arm64-Host o. u.). Deshalb werden
die Agent-Binaries **für alle unterstützten Ziel-Arches cross-gebaut und komplett
eingebettet** — nicht nur für die Arch, auf der der Server-Build läuft. Cross-Build
ist `CGO_ENABLED=0` statisch, also arch-unabhängig aus jeder Build-Umgebung möglich.
Ziel-Arches (Agent ist linux-only, systemd): aktuell **linux/amd64, linux/arm64**;
Liste erweiterbar (386, arm/v7, riscv64) durch einen Eintrag in der Build-Matrix.

---

## Ziel-Ablauf (UX)

1. Admin öffnet **Hosts** → Button **„Host hinzufügen“**.
2. Dialog: optional Hostname-Bindung, Tags (`env=prod,role=web`), TTL, Session-Audit-Flag.
3. Klick **„Token erzeugen“** → Server mintet einmaliges Token, Antwort enthält
   Token-Klartext (einmalig), Server-Version und Liste der verfügbaren Agenten
   (arch, Größe, SHA-256).
4. Dialog zeigt eine **Copy-Zeile** plus **Arch-Auswahl** (Dropdown), die die
   Zeile anpasst:
   - Default **„auto (Script erkennt)"** — eine Zeile, deckt alle Arches ab, das
     Script macht `uname -m`:
     ```
     curl -fsSL https://gssh.example.com/install.sh | sudo sh -s -- --token gssh-et-XXXXXXXX
     ```
   - Explizite Wahl **amd64 / arm64** — pinnt die Arch im Kommando (nötig bei
     Cross-Provisioning oder Pipe ohne TTY, wo `uname` die Ziel-Arch nicht trifft):
     ```
     curl -fsSL https://gssh.example.com/install.sh | sudo sh -s -- --token gssh-et-XXXXXXXX --arch arm64
     ```
   Copy-Button je Variante. Die Arch-Liste im Dropdown kommt aus dem Manifest
   (`GET /v1/agents`) — nur tatsächlich eingebettete Arches erscheinen.
5. Operator fügt Zeile auf dem Linux-Host ein. **Ein Kommando**, Ende: Binary
   installiert, Unit aktiv, Host enrolled, sshd konfiguriert.

Das server-servierte `install.sh` ist zur Laufzeit getemplatet und kennt bereits
Server-URL, Agent-URL, Version, SHA-256 und den (Pflicht-)SPKI-Pin. Einzige
Variable ist das Token.

Was das Script tut (identisch zur heutigen manuellen 3-Schritt-Sequenz, nur
gebündelt):
1. root + `sshd` prüfen (`ssh-keygen -A`, falls Host-Keys fehlen)
2. arch bestimmen: `--arch`-Argument (falls gesetzt) hat Vorrang, sonst `uname -m`
   → amd64/arm64; unbekannte/nicht eingebettete arch → Abbruch mit Klartext
3. Binary vom Server laden: `GET /v1/agents/linux/<arch>` → `/usr/bin/gssh-agentd`,
   SHA-256 gegen den ins Script getemplateten (arch-spezifischen) Hash prüfen
4. systemd-Unit schreiben (Server serviert `gssh-agentd.service`, oder Here-Doc)
5. Pin-Guard: ist der getemplatete Pin leer → **Abbruch** (Rollout ist ohne Pin
   nicht erlaubt)
6. `gssh-agentd enroll --server <base> --agent-url <agent> --token <t> --pin <spki>
   --require-pin` (Pin immer gesetzt, Agent erzwingt ihn fail-closed)
7. `systemctl enable --now gssh-agentd`
8. Erfolgsmeldung

---

## Architektur / neue Bausteine

### Backend (Go)

**A. Agent-Binaries ins Image**
- Empfehlung: neues Paket `internal/agentdist` mit `//go:embed all:bin` und einer
  Zugriffs-API `Open(os, arch) (fs.File, sha256 string, ok bool)`.
- Dockerfile: neue Build-Stage cross-baut `gssh-agentd` **für alle Ziel-Arches**
  (linux/amd64 + linux/arm64, Matrix erweiterbar) mit gleichen `-ldflags` wie der
  Server, legt sie nach `internal/agentdist/bin/gssh-agentd-linux-<arch>`, dann
  baut `gssh-server` mit eingebettetem Verzeichnis. **Wichtig:** dieser Cross-Build
  ist von `TARGETARCH` des Server-Images entkoppelt — auch ein arm64-Server-Image
  bettet das amd64-Agent-Binary mit ein und umgekehrt. Bei Multi-Arch-Server-Image
  (buildx) baut jede Plattform-Variante denselben vollständigen Agent-Satz ein.
- Lokaler `go build` ohne Binaries: Embed-Verzeichnis enthält nur `.gitkeep` →
  Endpoints antworten `503 „agent binaries not bundled in this build"`. Sauber
  degradiert, keine Test-Brüche.
- Tradeoff: Server-Binary ~+30–40 MB (zwei statische Agenten). Alternative:
  Binaries per `COPY` in Image-Pfad `/usr/local/share/gssh-agents/`, Server liest
  via `os.DirFS`. Behält Binary klein, ist aber zwei Artefakte. **Empfehlung:
  Embed** (Single-Artifact, garantierter Versions-Lockstep).

**B. Neue Public-Endpoints** (Public-Listener, `internal/api/server.go`)
- `GET /v1/agents` → Manifest: `{ version, agents: [{os, arch, size, sha256}] }`.
  **Unauthentifiziert** (kein Geheimnis, nur öffentliche Metadaten); billig, auf
  dem regulären Limiter.
- `GET /v1/agents/{os}/{arch}` → Binary-Stream (`application/octet-stream`).
  **Unauthentifiziert** (Host hat noch keine Credentials). Binary ist öffentliches
  Artefakt; das Token ist das Gate. **Eigener, enger Download-Rate-Limiter** gegen
  Bandbreiten-Flooding (Binary 15–40 MB): der bestehende `RateLimiter`
  (Per-IP-Token-Bucket, `internal/api/ratelimit.go`) als **zweite Instanz** mit
  eigener Config, **Default 3 Downloads/IP/Minute** (Burst 3), konfigurierbar via
  Env `GSSH_AGENT_DOWNLOAD_RPM`. Der reguläre 60/min-Limiter der Sign-/Enroll-
  Endpunkte ist dafür zu locker.
- `GET /install.sh` → getemplatetes POSIX-`sh`-Script mit Base-URL, Agent-URL,
  Version, SHA-256, optional Pin. Unauthentifiziert.
- Prefix bewusst `/v1/agents/` (Plural) — `/v1/agent/` (Singular) ist der mTLS-Listener.

**C. Token-Minting-Endpoint** (`internal/api/admin_ui.go`, roleAdmin)
- `POST /v1/admin/enroll-tokens`, Body `{ hostname?, tags?, ttl_seconds?, session_audit? }`.
- Logik aus `cmd/gssh-server/main.go:runEnrollToken` extrahieren → gemeinsame
  Funktion in `internal/store` oder Helper, damit CLI und API identisch minten.
- Antwort `{ token, expires_at, install_command }` (Klartext **einmalig**).
- Audit-Event `host.enroll_token.created` (Actor, Tags, TTL, kein Token-Klartext).

**D. Externe Agent-URL konfigurierbar**
- Enroll braucht `--agent-url` = externe mTLS-Agent-API. Neuer Env
  `GSSH_AGENT_PUBLIC_URL` (Fallback: aus `GSSH_UI_BASE_URL`-Host + Agent-Port
  ableiten). Ins Template und in `install_command` einsetzen.

**E. Pflicht-Pinning & Rollout-Gate (fail-closed)**
- SPKI-Pin ist **verpflichtend**. Kein Codepfad gibt je ein ungepinntes
  Install-Kommando aus.
- **Der Server liest das Cert selbst vom eigenen Public-Endpoint.** Der
  Public-Listener terminiert kein TLS — das läuft am **Reverse-Proxy**. Der
  Pin ist **nicht statisch** (Cert rotiert). Mechanismus:
  - Der GSSHS wählt seinen eigenen externen Public-URL per TLS an (`GSSH_PUBLIC_URL`,
    Fallback `GSSH_UI_BASE_URL`), macht einen Handshake gegen den Reverse-Proxy,
    liest das **Leaf-Zertifikat** aus (`cs.PeerCertificates[0]`) und berechnet
    `base64(SHA-256(SubjectPublicKeyInfo))` — exakt der Wert, den ein echter Host
    beim Enrollment sieht.
  - **Hintergrund-Refresh-Loop** (Intervall via `GSSH_PUBLIC_PIN_REFRESH`, Default
    z. B. 5 min) hält den gecachten Pin aktuell → bei Cert-Rotation zieht der Pin
    automatisch nach, ohne Operator-Eingriff. Neu geminttete Kommandos tragen den
    frischen Pin.
  - Voraussetzung: der Server muss seinen eigenen Public-URL erreichen (Hairpin/
    internes DNS auf den Reverse-Proxy). Dokumentieren.
- **Rollout-Gate:** Solange **kein Pin gelesen** wurde (Start noch nicht
  erfolgreich, Endpoint nicht erreichbar), sind Token-Minting, `install.sh` und
  Binary-Download **deaktiviert** (503), und der UI-Button „Host hinzufügen“ ist
  ausgegraut mit Klartext-Hinweis („Pin noch nicht ermittelt"). Kein stiller
  ungepinnter Fallback.
- **Client-Zwang:** Das getemplatete `install.sh` bricht ab, wenn der Pin leer ist,
  und übergibt `--pin` immer. Zusätzlich erzwingt der Agent den Pin in diesem Pfad
  (`gssh-agentd enroll --require-pin` bzw. Env `GSSH_ENROLL_REQUIRE_PIN=1`, vom
  Script gesetzt) → ein manuell entferntes `--pin` scheitert fail-closed. Der
  bestehende manuelle/deb-rpm-Pfad bleibt unverändert (Pin dort weiter optional).

### Frontend (Angular, `web/src/app/features/hosts.ts`)
- Button „Host hinzufügen“ in `page-header`.
- Dialog-Komponente: Formular (Hostname, Tags, TTL, Session-Audit) → `POST
  /v1/admin/enroll-tokens`.
- Ergebnis-Ansicht: Token (maskiert + Copy), **Arch-Dropdown** (Optionen aus
  `GET /v1/agents`: „auto" + je eingebettete Arch) das die Copy-Zeile live anpasst
  (`--arch <x>`), Agent-Liste (arch/Größe/SHA-256), Hinweis „Token einmalig, TTL läuft“.
- API-Anbindung: OpenAPI (`api/openapi.yaml`) um Pfade erweitern, Client-`fn`
  regenerieren (oder hand-geschrieben analog `enrollment/enroll-host.ts`).

### OpenAPI / Doku
- `api/openapi.yaml`: `/v1/admin/enroll-tokens`, `/v1/agents`, `/v1/agents/{os}/{arch}`, `/install.sh`.
- `deploy/packaging/install.sh` bleibt als GitHub-Fallback; README-Hinweis auf
  neuen server-internen Weg.

---

## Sicherheit (bewusst in Klartext, nicht Caveman)

Dies ist `curl … | sudo sh`, ausgeführt als root — die klassische
Supply-Chain-Angriffsfläche. Maßnahmen:

- **Nur über HTTPS ausliefern.** Der Ingress-TLS terminiert vor dem Server; das
  Script muss über `https://` gezogen werden.
- **SHA-256 des Binaries ins Script templaten.** Selbst bei kompromittiertem
  Transport des Binary-Downloads erkennt das Script eine Manipulation und bricht ab.
- **SPKI-Pin ist Pflicht, kein Opt-in.** `gssh-agentd enroll --pin` existiert
  bereits. Der Server liest das TLS-Leaf-Cert seines eigenen Public-Endpoints
  (Reverse-Proxy) selbst aus und templatet den Pin immer ins Script →
  MITM-resistentes Enrollment, auch bei Cert-Rotation (Background-Refresh). Solange
  kein Pin gelesen wurde, ist der gesamte Host-Rollout deaktiviert (fail-closed)
  statt ungepinnt weiterzumachen. Client erzwingt den Pin zusätzlich
  (`--require-pin`), ein entferntes `--pin` scheitert.
- **Zwei-Schritt-Alternative in der UI anbieten** („herunterladen, prüfen, dann
  ausführen") für Sicherheitsbewusste — kein Zwang zum Pipe-to-shell.
- **Token = einmaliges, kurzlebiges Bearer-Secret.** TTL-Default kurz (z. B. 1 h),
  Einmalverbrauch ist bereits serverseitig erzwungen. Copy-Zeile als Geheimnis
  behandeln, nie loggen.
- **Binary-Download unauthentifiziert, aber eng rate-limited** (Default 3/IP/min,
  Env `GSSH_AGENT_DOWNLOAD_RPM`) gegen Bandbreiten-Flooding. Öffentliches Artefakt;
  das Token gated das Enrollment, nicht der Binary-Zugriff.
- **Token-Mint nur roleAdmin, audit-geloggt.**

---

## Phasen (abhaken)

### Phase A — Agent-Binaries im Container
- [ ] Paket `internal/agentdist` mit `//go:embed all:bin` + `.gitkeep`, Zugriffs-API `Open(os, arch)` + `List()` inkl. SHA-256
- [ ] `503`-Degradation bei leerem Embed (Dev-Build)
- [ ] Dockerfile: Cross-Build-Stage `gssh-agentd` für **alle** Ziel-Arches (linux/amd64+arm64), von `TARGETARCH` entkoppelt, Binaries nach `internal/agentdist/bin/`
- [ ] Unit-Test: Embed liefert je Arch Binary + korrekten Hash, `List()` vollständig

### Phase B — Public-Endpoints
- [ ] `GET /v1/agents` (Manifest, regulärer Limiter), `GET /v1/agents/{os}/{arch}` (Binary)
- [ ] Zweite `RateLimiter`-Instanz für Downloads, Env `GSSH_AGENT_DOWNLOAD_RPM`, Default 3/IP/min (Burst 3)
- [ ] `GET /install.sh` getemplatet (Base-URL, Agent-URL, Version, per-arch SHA-256, Pflicht-Pin); Script akzeptiert `--arch` (Vorrang vor `uname -m`) und `--session-audit` (Passthrough), bricht bei leerem Pin ab, ruft `enroll --pin … --require-pin`
- [ ] Env `GSSH_AGENT_PUBLIC_URL` (+ Fallback-Ableitung)
- [ ] Handler-Tests (Content-Type, 503-Pfad, unbekannte/nicht eingebettete arch → 404)

### Phase P — Pflicht-Pinning & Rollout-Gate
- [ ] Pin-Provider: TLS-Dial gegen `GSSH_PUBLIC_URL` (Fallback `GSSH_UI_BASE_URL`), Leaf-Cert lesen, `base64(SHA-256(SPKI))` berechnen, cachen (Wiederverwendung `internal/pintls`)
- [ ] Background-Refresh-Loop, Intervall `GSSH_PUBLIC_PIN_REFRESH` (Default 5 min); Rotation zieht nach
- [ ] Rollout-Gate: kein Pin → `/v1/agents/*`, `/install.sh`, Token-Mint = 503; Zustand im Manifest/`ui/config` sichtbar für UI-Button
- [ ] Client: `gssh-agentd enroll --require-pin` (bzw. `GSSH_ENROLL_REQUIRE_PIN`) — leerer/fehlender Pin ⇒ fail-closed; manueller/deb-Pfad unverändert
- [ ] Tests: Pin-Berechnung, Gate 503 ohne Pin, `--require-pin` bricht ohne Pin ab

### Phase C — Token-Minting-API
- [ ] Mint-Logik aus `runEnrollToken` in gemeinsamen Helper extrahieren
- [ ] `POST /v1/admin/enroll-tokens` (roleAdmin), Antwort mit `install_command`
- [ ] Audit-Event `host.enroll_token.created`
- [ ] Handler-Test (Rolle, Einmal-Klartext, Tag/TTL-Weitergabe)

### Phase D — Frontend
- [ ] Button „Host hinzufügen“ + Dialog in `hosts.ts`; Button **ausgegraut** wenn Rollout ungated (kein Pin), mit Hinweistext
- [ ] Formular → Mint-Call, Ergebnis-Ansicht mit Arch-Dropdown (aus `/v1/agents`), live-angepasster Copy-Zeile + Agent-Liste
- [ ] Session-Audit-Checkbox (Default aus) mit Erklärtext (PAM-Hooks sshd/sudo, Session-/sudo-Audit) → setzt `--session-audit` im Kommando
- [ ] Zwei-Schritt-Alternative (Download + Prüfen) anzeigen
- [ ] `api/openapi.yaml` erweitern, Client-`fn` (regeneriert oder hand-geschrieben)

### Phase E — Doku & Integration
- [ ] README/DEVELOPER: neuer interner Install-Weg, Sicherheitshinweise, Pflicht-Pinning
- [ ] Envs in Helm-`values.yaml` dokumentieren: `GSSH_AGENT_PUBLIC_URL`, `GSSH_PUBLIC_URL`, `GSSH_PUBLIC_PIN_REFRESH`, `GSSH_AGENT_DOWNLOAD_RPM`; Hairpin-Voraussetzung (Server erreicht eigenen Public-URL)
- [ ] E2E/Smoke: Token minten → `install.sh` in Container-sshd-Testfixture (`internal/agentd/testdata/sshd`) ausführen → Host enrolled

---

## Entschieden

- **Embed** (`go:embed`) für Agent-Binaries — Single-Artifact, harter Version-Lockstep,
  konsistent zur Web-UI. Tradeoff Binary +30–40 MB akzeptiert. (2026-07-25)
- **Manifest + Download öffentlich** (kein Geheimnis). Download gegen Flooding
  eng rate-limited: Default 3/IP/min, konfigurierbar via `GSSH_AGENT_DOWNLOAD_RPM`.
  Manifest auf dem regulären Limiter. (2026-07-25)
- **SPKI-Pin Pflicht, fail-closed, nicht statisch.** Der Server liest das
  TLS-Leaf-Cert seines eigenen Public-Endpoints (Reverse-Proxy) selbst per TLS-Dial
  aus und berechnet den Pin; Background-Refresh zieht bei Cert-Rotation nach.
  Solange kein Pin gelesen wurde, ist der Host-Rollout deaktiviert (UI-Button
  ausgegraut, Endpoints 503). Kein ungepinnter Fallback. (2026-07-25)

- **Session-Audit** — Pflicht-Element der „Host hinzufügen"-Maske: Checkbox,
  Default **aus**, wahlfrei, mit Erklärtext im Dialog. An → `enroll --session-audit`.
  Erklärung für den Anwender: aktiviert Host-Session-/sudo-Audit; der Agent hängt
  `pam_exec`-Hooks an die PAM-Stacks von sshd und sudo (`/etc/pam.d/*`) und
  korreliert Sessions mit Zertifikaten (sshd `LogLevel VERBOSE`). Meldet
  Session-Start/-Ende und sudo-Aktionen an die Plattform. Ändert PAM-Konfiguration
  des Hosts → bewusst opt-in. (2026-07-25)

## Offene Entscheidungen

_(keine)_
