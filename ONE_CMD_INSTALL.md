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
4. systemd-Unit schreiben (Inhalt aus derselben eingebetteten Quelle wie deb/rpm — `internal/agentdist/gssh-agentd.service`, K12)
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
  eigener Config, **Default 10 Downloads/IP/Minute** (Burst 5), konfigurierbar via
  Env `GSSH_AGENT_DOWNLOAD_RPM`; erbt `TrustProxyHeader` aus derselben Env wie der
  reguläre Limiter (`GSSH_RATE_TRUST_XFF`, K5). Der reguläre 60/min-Limiter der
  Sign-/Enroll-Endpunkte ist dafür zu locker.
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
- **Bedienfehler-Schutz (kein MITM-Schutz):** Das getemplatete `install.sh` bricht
  ab, wenn der Pin leer ist, und übergibt `--pin` immer. Zusätzlich erzwingt der
  Agent den Pin in diesem Pfad (`gssh-agentd enroll --require-pin` bzw. Env
  `GSSH_ENROLL_REQUIRE_PIN=1`, vom Script gesetzt) → eine aus dem Script
  herauskopierte enroll-Zeile ohne `--pin` scheitert fail-closed statt still
  ungepinnt zu enrollen. Gegen Script-Manipulation (MITM) schützt das **nicht** —
  das adressieren HTTPS-Abruf und die Pin-Quellen (K1/K2). Der bestehende
  manuelle/deb-rpm-Pfad bleibt unverändert (Pin dort weiter optional).

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
  (`--require-pin`) — Schutz gegen versehentlich ungepinnte Enrollments
  (Bedienfehler), kein Schutz gegen Script-Manipulation.
- **Zwei-Schritt-Alternative in der UI anbieten** („herunterladen, prüfen, dann
  ausführen") für Sicherheitsbewusste — kein Zwang zum Pipe-to-shell.
- **Token = einmaliges, kurzlebiges Bearer-Secret.** TTL-Default kurz (z. B. 1 h),
  Einmalverbrauch ist bereits serverseitig erzwungen. Copy-Zeile als Geheimnis
  behandeln, nie loggen. Akzeptierte Restexposition (K14): Token steht in der
  Operator-Shell-History und während des Laufs in argv/`ps` des Zielhosts —
  durch Einmalverbrauch + TTL nach Gebrauch wertlos; Env-/stdin-Varianten
  verschieben die Exposition nur, ohne sie zu beheben.
- **Binary-Download unauthentifiziert, aber eng rate-limited** (Default 10/IP/min,
  Burst 5, Env `GSSH_AGENT_DOWNLOAD_RPM`) gegen Bandbreiten-Flooding. Öffentliches Artefakt;
  das Token gated das Enrollment, nicht der Binary-Zugriff.
- **Token-Mint nur roleAdmin, audit-geloggt.**
- **Versions-Disclosure akzeptiert (K13):** `GET /v1/agents` nennt die
  Server-Version unauthentifiziert. Bewusst — das öffentliche Binary ist
  ohnehin version-identifizierbar (Hash-Abgleich mit Releases,
  `gssh-agentd version`); Streichen wäre Scheinschutz.

---

## Phasen (abhaken)

### Phase A — Agent-Binaries im Container
- [ ] Paket `internal/agentdist` mit `//go:embed all:bin` + `.gitkeep`, Zugriffs-API `Open(os, arch)` + `List()` inkl. SHA-256
- [ ] `503`-Degradation bei leerem Embed (Dev-Build)
- [ ] Dockerfile: Cross-Build-Stage `gssh-agentd` für **alle** Ziel-Arches (linux/amd64+arm64) via `FROM --platform=$BUILDPLATFORM` + GOOS/GOARCH-Schleife (K8), Binaries nach `internal/agentdist/bin/`
- [ ] `gssh-agentd.service` per `git mv` nach `internal/agentdist/`, dort `go:embed`; `nfpm.yaml`-src-Pfad anpassen (K12)
- [ ] Unit-Test: Embed liefert je Arch Binary + korrekten Hash, `List()` vollständig

### Phase B — Public-Endpoints
- [ ] `GET /v1/agents` (Manifest, regulärer Limiter), `GET /v1/agents/{os}/{arch}` (Binary)
- [ ] Zweite `RateLimiter`-Instanz für Downloads, Env `GSSH_AGENT_DOWNLOAD_RPM`, Default 10/IP/min (Burst 5), erbt `GSSH_RATE_TRUST_XFF` (K5)
- [ ] `GET /install.sh` getemplatet (Base-URL, Agent-URL, Version, per-arch SHA-256, Pflicht-Pin); Script akzeptiert `--arch` (Vorrang vor `uname -m`), `--session-audit` (Passthrough) und `--no-systemd` (K6: alles außer `systemctl`, Ausgabe nennt übersprungene Schritte), bricht bei leerem Pin ab, ruft `enroll --pin … --require-pin`
- [ ] Env `GSSH_AGENT_PUBLIC_URL` als Gate-Bedingung (K4 — keine Fallback-Ableitung)
- [ ] Script-Robustheit (K7): Enroll-Fehler bei vorhandener `config.yaml` ⇒ Warnung + weiter; Binary via Same-Dir-Tempfile + atomarem `mv` (kein ETXTBSY); Unit aktiv ⇒ `systemctl restart` statt `enable --now`
- [ ] Script-Härtung (K11): `main()`-Wrapper gegen Truncation, `set -eu` (kein `pipefail`, Exit-Codes explizit), `trap`-Cleanup fürs Tempfile
- [ ] Health-Check (K17): `systemctl is-active` + Warten auf `agentd.sock` (≤ 10 s); Fehlschlag ⇒ `journalctl`-Hinweis + Exit ≠ 0; entfällt bei `--no-systemd`
- [ ] `Cache-Control: no-store` auf `install.sh`, Manifest und Binary-Download (K10)
- [ ] Handler-Tests (Content-Type, `no-store`-Header, 503-Pfad, unbekannte/nicht eingebettete arch → 404)

### Phase P — Pflicht-Pinning & Rollout-Gate
- [ ] Pin-Provider mit drei Quellen (K2, Präzedenz absteigend): `GSSH_PUBLIC_PIN` (statisch) → `GSSH_PUBLIC_PIN_CERT_FILE` (PEM, erster Block, **ungecacht** gelesen, K9) → TLS-Dial gegen `GSSH_PUBLIC_URL` (Fallback `GSSH_UI_BASE_URL`) mit Chain-Verify fail-closed (K1); Berechnung via neuem Helper `pintls.FromCertificate` (K15, migriert auch Test-Helper `spkiPin`)
- [ ] Background-Refresh-Loop nur für Dial-Quelle, Intervall `GSSH_PUBLIC_PIN_REFRESH` (Default 5 min) **plus** Lazy-Refresh beim Servieren, wenn Cache älter als Intervall (K9)
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
- [ ] Envs in Helm-`values.yaml`: `GSSH_PUBLIC_URL`, `GSSH_PUBLIC_PIN`, `GSSH_PUBLIC_PIN_CERT_FILE`, `GSSH_PUBLIC_PIN_REFRESH`, `GSSH_AGENT_PUBLIC_URL`, `GSSH_AGENT_DOWNLOAD_RPM` — **je Parameter max. 2 Zeilen on-point Doku**; Entscheidungstabelle Pin-Quellen; Volume-Snippet Cert-File (nur `tls.crt`, kein `subPath`); Hairpin-Hinweis nur für Pin-Quelle Auto-Dial (K2)
- [ ] E2E/Smoke: Token minten → `install.sh --no-systemd` in Container-sshd-Testfixture (`internal/agentd/testdata/sshd`) ausführen → Host enrolled, Agent von Fixture gestartet (K6); Restlücke systemctl-Pfad dokumentieren

---

## Entschieden

- **Embed** (`go:embed`) für Agent-Binaries — Single-Artifact, harter Version-Lockstep,
  konsistent zur Web-UI. Tradeoff Binary +30–40 MB akzeptiert. (2026-07-25)
- **Manifest + Download öffentlich** (kein Geheimnis). Download gegen Flooding
  rate-limited: Default 10/IP/min (Burst 5), erbt das XFF-Vertrauen des regulären
  Limiters; konfigurierbar via `GSSH_AGENT_DOWNLOAD_RPM` (angepasst per K5).
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

_(keine)_ — Review-Kritik K1–K17 vollständig entschieden (2026-07-25);
Ergebnisse stehen je Punkt unter **Entscheidung** in der Review-Sektion,
Phasen-Checkboxen sind entsprechend nachgezogen.

---

## Review-Kritik (2026-07-25)

Kritische Durchsicht des Plans gegen den Code-Stand (`feat/host-rollout`).
Bausteine-Tabelle verifiziert und korrekt: `web/embed.go`, `make cross`
(agentd amd64+arm64), `runEnrollToken`/`CreateEnrollmentToken`,
`gssh-agentd enroll --pin/--session-audit/--agent-url`, `New`/`NewAgent`-Split,
`RateLimiter` (per-IP-Token-Bucket), `internal/pintls`, `deploy/packaging/`.
Gesamturteil: **Plan tragfähig, Machbarkeit „JA“ bestätigt.** Die kritischen
Punkte konzentrieren sich auf Phase P — den einzigen Teil, der neu erfunden
wird statt Vorhandenes zu verdrahten.

Severity: 🔴 kritisch (Designlücke Sicherheit) · 🟠 wichtig (bricht
Funktion/UX in realen Deployments) · 🟡 klein (Härtung, Doku, Polish).
Jeder Punkt wird einzeln besprochen; Ergebnis unter **Entscheidung**.

### K1 🔴 Pin-Selbst-Dial: Chain-Verifikation nicht spezifiziert

**Befund.** Phase P: Server dialt eigenen Public-URL, liest
`cs.PeerCertificates[0]`, berechnet den Pin. Nicht festgelegt, ob dieser Dial
die Zertifikatskette verifiziert. Die naheliegende Implementierung („nur das
Cert lesen“) wäre `InsecureSkipVerify: true`.

**Risiko.** Verifiziert der Dial nicht, kann ein MITM zwischen Server und
Reverse-Proxy (oder DNS-Poisoning aus Sicht des Server-Pods) ein eigenes
Zertifikat präsentieren. Der Server berechnet dann den **Angreifer-Pin** und
templatet ihn in jedes `install.sh` — das verpflichtende Pinning
authentifiziert ab da den Angreifer gegenüber allen neu enrollten Hosts. Die
eine unverifizierte Stelle hebelt den gesamten Mechanismus aus.

**Vorschlag.** Der Pin-Dial verifiziert fail-closed gegen System-Roots
(Standard-`tls.Config`, keinerlei Sonderbehandlung). Verifikationsfehler ⇒
kein Pin ⇒ Rollout-Gate bleibt zu, Grund wird geloggt und im Manifest/UI
sichtbar. Trust-Basis damit: „das WebPKI-gültige Zertifikat, das mein eigener
URL serviert“. Selbstsignierte/Private-CA-Proxies laufen über den
K2-Override. distroless/static enthält das CA-Bundle — kein Image-Umbau.

**Entscheidung.** (2026-07-25) Pin-Dial verifiziert fail-closed mit
Standard-`tls.Config` gegen System-Roots; es gibt keinen
`InsecureSkipVerify`-Codepfad. Verifikationsfehler ⇒ kein Pin, Gate zu, Grund
in Log + Manifest/UI. Unternehmens-/Private-CA: CA-Bundle mounten und
`SSL_CERT_FILE`/`SSL_CERT_DIR` setzen (Go liest beide, distroless unverändert;
Achtung: `SSL_CERT_FILE` **ersetzt** das Standard-Bundle — bei Mischbetrieb
konkatenieren) → auch dieser Fall bleibt auf dem verifizierten Pfad.
Self-signed ohne CA läuft über die alternativen Pin-Quellen aus K2.

### K2 🔴 Hairpin-Pflicht ohne Escape-Hatch

**Befund.** Das Rollout-Gate setzt voraus, dass der Server seinen eigenen
Public-URL erreicht. Der Plan sagt dazu nur: „Dokumentieren“.

**Risiko.** Genau das scheitert in realen Deployments regelmäßig: Cloud-LBs
ohne Hairpin-NAT, Egress-NetworkPolicies, vor allem Split-Horizon-DNS — der
Server dialt intern, sieht ein **anderes** Zertifikat als die Hosts von
außen, jedes Enrollment scheitert fail-closed mit verwirrender Meldung. Ohne
Ausweichpfad ist das Feature dort dauerhaft gebrickt (503).

**Vorschlag.** Drei Pin-Quellen mit fester Präzedenz, alle fail-closed;
aktive Quelle wird geloggt und im Manifest ausgewiesen:

1. **`GSSH_PUBLIC_PIN`** (statisch, höchste Präzedenz): Operator liefert den
   Pin selbst (Doku-Snippet: `openssl s_client … | openssl x509 -pubkey … |
   openssl dgst -sha256 -binary | base64`). Auto-Dial + Refresh aus. Rotation
   in Operator-Hand (bei Key-Reuse im Renewal bleibt der Pin stabil).
   Letzter Ausweg, z. B. Cert liegt am CDN.
2. **`GSSH_PUBLIC_PIN_CERT_FILE`** (Datei): Pfad zu einem PEM-Zertifikat
   (erster Block = Leaf, cert-manager-Konvention); Server liest die Datei im
   bestehenden Refresh-Loop neu → Rotation automatisch. K8s: TLS-Secret des
   Ingress als **Volume** mounten — kein K8s-API-Zugriff/RBAC nötig, Kubelet
   aktualisiert den Mount bei Secret-Rotation (≤ ~1 min). Regeln: kein
   `subPath` (bekommt keine Updates); nur `tls.crt` projizieren
   (`items:`-Auswahl — `tls.key` bleibt draußen, Server braucht ihn nicht);
   Secret muss im Server-Namespace liegen (Wildcard-Cert in fremdem
   Namespace: reflector/kubed oder eigenes `Certificate`). Funktioniert auch
   ohne K8s (bind-mount von `fullchain.pem`). Löst Hairpin- und
   Split-Horizon-Fälle ohne manuellen Rotations-Aufwand.
3. **Auto-Dial** (Default, Mechanik + Verifikation aus K1).

Mehrere Quellen gesetzt ⇒ höchste Präzedenz gewinnt, Warnung im Log. Pin
bleibt in allen Fällen Pflicht und fail-closed — nur die Quelle variiert.

**Entscheidung.** (2026-07-25) Drei-Quellen-Modell angenommen: Präzedenz
`GSSH_PUBLIC_PIN` (statisch) > `GSSH_PUBLIC_PIN_CERT_FILE` (Datei,
rotationsfähig via Secret-Volume-Mount, kein K8s-API-Zugriff) > Auto-Dial
(Default, Verifikation aus K1). Alle Quellen fail-closed; aktive Quelle in
Log + Manifest; mehrere gesetzt ⇒ höchste gewinnt + Warnung.
Hairpin-Voraussetzung gilt nur noch für den Dial-Default. Alle Pin-Envs
kommen in die Helm-`values.yaml`, **je Parameter max. 2 Zeilen on-point
dokumentiert**; dazu Mini-Entscheidungstabelle „welche Quelle wann“ und
Volume-Snippet (nur `tls.crt` via `items:` projizieren, kein `subPath`).

### K3 🟠 `--require-pin`: Begründung ist schief

**Befund.** Der Plan rahmt `--require-pin` als „Client-Zwang“ gegen ein
manipuliertes Kommando („ein manuell entferntes `--pin` scheitert“).

**Risiko.** Falsches Sicherheitsversprechen: Wer das gepipte Script
manipulieren kann, entfernt auch `--require-pin`/die Env — und könnte ohnehin
das Token exfiltrieren oder gleich ein eigenes Binary installieren. Gegen
MITM ist das Flag wirkungslos.

**Vorschlag.** Flag behalten (billig, sinnvoll), aber ehrlich begründen:
Schutz gegen **Bedienfehler** — Operator kopiert die enroll-Zeile aus dem
Script heraus und lässt `--pin` weg. Nicht mehr, nicht weniger. Plan- und
README-Text entsprechend formulieren.

**Entscheidung.** (2026-07-25) Angenommen: `--require-pin` +
`GSSH_ENROLL_REQUIRE_PIN` bleiben unverändert; Begründung überall auf
Bedienfehler-Schutz umformuliert (versehentlich ungepinnte Enrollments, z. B.
herauskopierte enroll-Zeile), „Client-Zwang“-Wording entfernt. Explizit
dokumentiert: kein Schutz gegen Script-Manipulation — die adressieren
HTTPS-Abruf + K1/K2. Plantext (Abschnitt E, Security-Sektion) angepasst.

### K4 🟠 `GSSH_AGENT_PUBLIC_URL`: stille Fallback-Ableitung ist eine Falle

**Befund.** Plan: Fallback „aus `GSSH_UI_BASE_URL`-Host + Agent-Port
ableiten“.

**Risiko.** Hinter LB/Ingress stimmt der externe Port praktisch nie mit dem
internen Listen-Port überein. `enroll` schreibt die Agent-URL ungeprüft nach
`config.yaml` (`internal/agentd/enroll.go`, `writeState`); das Enrollment
gelingt, der Daemon scheitert erst später beim ersten Renew. Auf N Hosts
ausgerollt = N kaputte Configs, Korrektur = N Hosts anfassen.

**Vorschlag.** Keine stille Ableitung. `GSSH_AGENT_PUBLIC_URL` wird dritte
Gate-Bedingung: fehlt sie ⇒ Token-Mint/`install.sh`/Download 503 + UI-Hinweis
(analog Pin). Misconfig knallt beim Setup, nicht auf der Flotte.

**Entscheidung.** (2026-07-25) Angenommen, zweischichtig:

1. **Helm (Deployzeit, fail-fast):** Values-Block `hostRollout` mit
   `enabled`-Toggle in `deploy/helm/guided-ssh/values.yaml`. Bei
   `enabled: true` erzwingt `required` im Template `agentPublicUrl` sowie die
   Werte der gewählten Pin-Quelle (K2) — `helm install/upgrade/lint`
   scheitert beim Rendern mit Klartext-Meldung. Bei `enabled: false` wird
   nichts gerendert und nichts verlangt (Feature optional).
2. **Server (Laufzeit, autoritativ):** `GSSH_AGENT_PUBLIC_URL` ist dritte
   Gate-Bedingung neben eingebetteten Binaries und Pin; fehlt sie ⇒ 503 +
   UI-Button aus. Manifest weist fehlende Bedingungen **einzeln** aus
   (eindeutige Diagnose). Deckt Nicht-Helm-Deployments und Drift ab.

Kein eigenes Server-Feature-Flag: die Gate-Bedingungen sind der Schalter;
der Helm-Toggle steuert nur das Rendern der Envs — kein doppelter Zustand.
Keine URL-Ableitung in keinem Codepfad.

### K5 🟠 Download-Limiter: XFF-Verhalten und 3/min-Default

**Befund.** Zweite `RateLimiter`-Instanz, Default 3 Downloads/IP/min
(Burst 3). Nicht spezifiziert: `TrustProxyHeader` der neuen Instanz.

**Risiko.** (a) Hinter Ingress ohne `GSSH_RATE_TRUST_XFF=true` sehen alle
Requests wie die Proxy-IP aus ⇒ 3/min **global** — Parallel-Rollout ab Host 4
gedrosselt, schwer diagnostizierbar. (b) Umgekehrt: 50 Hosts hinter
Firmen-NAT (eine IP, Ansible-Loop) sind legitim und werden ausgebremst —
3/min ist dafür zu eng.

**Vorschlag.** Download-Limiter erbt dieselbe `TrustProxyHeader`-Config
(gleiche Env wie der reguläre Limiter). Default anheben auf **10/min,
Burst 5** — bei 15–20 MB Binary ≈ 25–35 Mbit/s Worst-Case pro IP, als
Flood-Schutz weiter ausreichend, Bulk-Rollouts laufen durch.
`GSSH_AGENT_DOWNLOAD_RPM` bleibt.

**Entscheidung.** (2026-07-25) Angenommen: Download-Limiter erbt
`TrustProxyHeader` aus `GSSH_RATE_TRUST_XFF` — eine Wahrheit für die
Client-IP-Ermittlung, keine zweite Config. Default 10/min, Burst 5
(Per-IP-Limits stoppen ohnehin nur Einzelquellen; 10/min leistet das genauso
wie 3/min, ohne NAT-Bulk-Rollouts zu würgen). Failure-Budget der zweiten
Instanz bleibt ungenutzt (keine 401/403 auf öffentlichen Downloads).
Token-gebundener Download verworfen (kollidiert mit „Download
öffentlich“-Entscheidung, Token in Logs/URLs). Plantext (Abschnitt B,
Security, Entschieden, Phase B) auf 10/5 aktualisiert.

### K6 🟠 E2E-Smoke: Fixture hat kein systemd

**Befund.** Phase E will `install.sh` in der sshd-Testfixture
(`internal/agentd/testdata/sshd`) ausführen. Deren `entrypoint.sh` startet
sshd direkt, kein systemd — `systemctl enable --now` schlägt fehl; die
Checkbox ist so nicht ausführbar.

**Vorschlag.** Script-Flag `--no-systemd`: Binary + Enroll + Unit-Datei
schreiben, Start überspringen (Ausgabe nennt die übersprungenen Schritte).
E2E nutzt das Flag und startet den Agenten wie bisher selbst. Nützt zudem
echten Hosts ohne systemd-PID-1 (Container-Hosts mit eigenem Supervisor).
Alternative systemctl-Stub im Fixture-PATH: mehr Magie, weniger realistisch.

**Entscheidung.** (2026-07-25) Angenommen: `install.sh` bekommt
`--no-systemd` — alles außer `systemctl enable --now` läuft (inkl.
Unit-Datei schreiben); Ausgabe benennt übersprungene Schritte + manuelles
Aktivierungskommando. E2E nutzt das Flag, Fixture startet den Agenten selbst
→ Smoke-Test deckt Token → Script → Download → Hash → Enroll → laufender
Agent ab. Verworfen: systemctl-Stub (täuscht Verhalten vor, schluckt echte
Fehler), privilegierter systemd-Container (CI-flaky/verboten). Restlücke
bewusst: systemctl-Pfad selbst bleibt CI-ungetestet, wird dokumentiert.
Nebeneffekt: Flag nützt Hosts mit eigenem Supervisor.

### K7 🟠 Teilfehler nach Token-Verbrauch: Re-Run bricht

**Befund.** Token ist einmalig. Scheitert das Script **nach** Schritt 6
(Enroll ok, Token verbraucht), z. B. bei `systemctl`, schlägt der Re-Run
derselben Zeile mit „Token ungültig“ fehl — das „Ein Kommando“-Versprechen
bricht genau im Fehlerfall.

**Vorschlag.** Script resümierbar machen: existiert ein Enrollment
(`/var/lib/guided-ssh/config.yaml`), Enroll überspringen (Hinweis ausgeben)
und mit Unit/Start fortfahren. Zusätzlich vor dem Binary-Kopieren: läuft die
Unit bereits (Upgrade/Re-Enroll), `systemctl stop` — sonst „text file busy“
beim Überschreiben von `/usr/bin/gssh-agentd`.

**Entscheidung.** (2026-07-25) Angenommen in verfeinerter Fassung (ersetzt
den Vorschlag oben in zwei Details):

1. **Enroll-Fehler-Degradation statt Skip:** Enroll läuft immer; schlägt er
   fehl *und* `config.yaml` existiert ⇒ Warnung „bestehendes Enrollment
   weiterverwendet“ + weitermachen (Abschlussmeldung nennt es unübersehbar);
   ohne `config.yaml` ⇒ harter Abbruch. Deckt Re-Run nach Teilfehler
   (verbrauchtes Token) und echtes Re-Enroll (frisches Token, idempotentes
   Überschreiben) ohne neues Flag ab. Skip-Variante verworfen (bräuchte
   `--force-reenroll`-Flag, blockiert Re-Enroll-Default).
2. **Kein `systemctl stop` vor dem Kopieren:** Binary nach
   Same-Dir-Tempfile (`/usr/bin/.gssh-agentd.tmp.XXXX`, gleiche Partition —
   nicht `/tmp`, sonst Cross-Device-Copy) + Hash-Check + `chmod` + atomarem
   `mv -f`. `rename(2)` ersetzt auch laufende Binaries ohne ETXTBSY; Daemon
   behält altes Inode, keine Downtime.
3. **systemd zustandsabhängig:** Unit aktiv ⇒ `systemctl restart` (Upgrade
   lädt neues Binary — `enable --now` auf aktiver Unit startet nicht neu),
   sonst `enable --now`.

Verworfen: Mehrfach-Token (Sicherheits-Rückschritt, Einmalverbrauch trägt
K14), Reissue-Endpoint (API-Surface für seltenen Fall). Bewusste Kante:
gewolltes Re-Enroll, das aus anderem Grund scheitert, läuft mit altem
Enrollment weiter — Warnung muss prominent sein; Host endet immer
funktionsfähig.

### K8 🟠 Dockerfile: Cross-Build-Stage braucht `--platform=$BUILDPLATFORM`

**Befund.** Plan sagt „von TARGETARCH entkoppelt“, nennt aber den Mechanismus
nicht; das aktuelle Dockerfile nutzt kein `$BUILDPLATFORM`.

**Risiko.** Bei buildx-Multi-Arch läuft die Agent-Build-Stage je
Ziel-Plattform unter QEMU — emuliertes Go-Compile ist um ein Vielfaches
langsamer, Build-Zeit explodiert.

**Vorschlag.** `FROM --platform=$BUILDPLATFORM golang:1.26 AS agentbuild` +
GOOS/GOARCH-Schleife (nativer Compiler, Cross via Go, `CGO_ENABLED=0`).
Dasselbe wäre für die bestehende Server-Build-Stage sinnvoll (separates
Thema, nicht Teil dieses Plans).

**Entscheidung.** (2026-07-25) Angenommen: Agent-Cross-Build-Stage als
`FROM --platform=$BUILDPLATFORM golang:1.26 AS agentbuild` mit
GOOS/GOARCH-Schleife (`CGO_ENABLED=0`, gleiche `-ldflags` wie Server).
Nativer Compiler, Cross via Go; Stage ist plattform-invariant ⇒ BuildKit
dedupliziert, Agenten werden pro Multi-Arch-Build effektiv einmal gebaut.
CI-Artefakt-`COPY` verworfen (bricht Single-Build-Lockstep). Optimierung der
bestehenden Server-Build-Stage als separates Thema notiert, nicht Teil
dieses Plans.

### K9 🟡 Cert-Rotation: Stale-Fenster und Dual-Cert-Proxies

**Befund.** Pin-Cache bis `GSSH_PUBLIC_PIN_REFRESH` (5 min) stale. Rotiert
der Proxy im Fenster zwischen `install.sh`-Abruf und Enroll-Dial, trägt das
Script einen alten Pin ⇒ Enroll scheitert einmalig (fail-closed; Retry nach
Refresh hilft). Let’s-Encrypt-Renewals erzeugen standardmäßig neue Keys, das
Fenster tritt also planmäßig alle ~60–90 Tage auf. Dual-Cert-Proxies
(RSA+ECDSA) liefern je nach Client ein anderes Leaf — hier sind beide Seiten
Go-TLS, praktisch dieselbe Auswahl.

**Vorschlag.** (a) Lazy-Refresh: beim Servieren von `install.sh` und beim
Token-Mint Pin synchron nachziehen, wenn der Cache älter als das Intervall
ist. (b) Nur falls nötig: Multi-Pin `--pin a,b` (Verifier prüft Menge —
alte+neue Pins während Rotation gültig). Dual-Cert: eine Doku-Zeile, kein
Code.

**Entscheidung.** (2026-07-25) Angenommen, differenziert nach K2-Quelle:
Datei-Quelle **ungecacht** (bei jedem Servieren frisch gelesen — Parse kostet
Mikrosekunden, Stale-Fenster = nur Kubelet-Sync); Dial-Quelle behält
Background-Loop **plus** Lazy-Refresh beim Servieren, wenn der Cache älter
als das Intervall ist; statische Quelle Operator-Sache. Multi-Pin
verschoben (YAGNI: Restfenster Sekunden–1 min alle ~60–90 Tage; später
abwärtskompatibel als Komma-Liste nachrüstbar — Future-Note). Dual-Cert
bleibt Doku-Zeile (beide Pin-Konsumenten Go-TLS, gleiche Auswahl; bei
Datei-Quelle gegenstandslos). Entschärfend festgehalten: Pin-Mismatch
scheitert im TLS-Handshake **vor** dem Request ⇒ Token wird nicht
verbraucht, Retry gratis (mit K7 sicher).

### K10 🟡 `Cache-Control: no-store` für `install.sh` + Manifest

**Befund.** Das getemplatete Script enthält Pin + Hashes; zwischengeschaltete
Caches (CDN, Corporate-Proxy) könnten stale Kopien servieren — stale Pin ⇒
fehlschlagende Enrollments, schwer zu debuggen.

**Vorschlag.** `Cache-Control: no-store` auf `/install.sh` und `/v1/agents`.
Binary-Downloads dürfen cachen.

**Entscheidung.** (2026-07-25) Angenommen, verschärft: `no-store` auf
**allen drei** Endpoint-Typen — `install.sh`, Manifest **und**
Binary-Download. Begründung der Verschärfung: Binary-Caching hat keinen
Nutzen (ein Download pro Host-Lebenszeit), aber reales Schadpotenzial —
nach Server-Upgrade liefert ein Cache das alte Binary zur neuen
`install.sh` ⇒ Hash-Mismatch als Phantom-Fehler. Eine Regel statt drei.
ETag/`no-cache`-Revalidierung verworfen (Maschinerie ohne
Wiederholungs-Traffic).

### K11 🟡 Script-Härtung gegen Truncation/Teilzustände

**Befund.** curl|sh führt bei abgebrochener Übertragung ein halbes Script aus.

**Vorschlag.** (a) Gesamtes Script als `main() { … }; main "$@"` — Truncation
führt nichts aus. (b) Binary nach `mktemp` laden, Hash prüfen, dann atomisch
`mv` + `chmod 0755`. (c) `trap`-Cleanup für tmp-Dateien. (d) `set -eu`.
Standard-Praxis, kostet nichts.

**Entscheidung.** (2026-07-25) Angenommen: (a) `main()`-Wrapper, letzte
Zeile `main "$@"` — Truncation führt nichts aus statt die Hälfte (einziger
struktureller Baustein, Rest Hygiene). (b) präzisiert durch K7:
Same-Dir-Tempfile in `/usr/bin`, nicht `/tmp`-mktemp. (c) `trap`-Cleanup
(EXIT) für das Tempfile. (d) `set -eu`; **kein** `pipefail` (in POSIX-sh/dash
nicht verlässlich) — Pipe-Fehler werden explizit über Exit-Codes geprüft.
Selbst-Hash-Prüfung des Scripts verworfen (Bootstrap-Zirkel).

### K12 🟡 systemd-Unit: eine Quelle statt Here-Doc-Duplikat

**Befund.** `deploy/packaging/gssh-agentd.service` existiert bereits
(deb/rpm-Pfad). Plan lässt „Server serviert Unit oder Here-Doc“ offen — ein
Duplikat driftet zwangsläufig.

**Vorschlag.** Dieselbe Datei via `go:embed` einbetten und vom Script
beziehen (im getemplateten Script inline oder als eigener Endpoint). Eine
Quelle für beide Installationswege. Dazu README-Zeile: Script-Install und
deb/rpm nicht mischen (dpkg-fremde Datei in `/usr/bin`).

**Entscheidung.** (2026-07-25) Angenommen: kanonische Datei zieht um nach
`internal/agentdist/gssh-agentd.service` (`go:embed` kann nicht über das
Package-Verzeichnis hinausgreifen — deshalb Umzug statt Referenz);
`nfpm.yaml`-src zeigt auf den neuen Pfad, deb/rpm unverändert. Server inlined
den Inhalt beim Templaten als quoted Here-Doc (`<<'EOF'`, keine Expansion);
Datei ist statisch, kein Unit-Templating. Verworfen: `go:generate`-Kopie
(committetes Duplikat = Drift), eigener Endpoint (Round-Trip ohne Gewinn),
Go-Package in `deploy/packaging` (Konzeptvermischung). Plus README-Zeile:
Script- und deb/rpm-Install nicht mischen.

### K13 🟡 Manifest verrät Server-Version unauthentifiziert

**Befund.** `GET /v1/agents` (öffentlich) enthält `version` ⇒ exaktes
CVE-Targeting für Angreifer bequem.

**Vorschlag.** Bewusst entscheiden: akzeptieren (Version ggf. ohnehin über
UI-Assets ableitbar) **oder** `version` aus dem öffentlichen Manifest
streichen und nur in der Admin-Antwort (`install_command`-Response) führen.
Das Script braucht die Version nicht — der SHA-256 gate’t das Binary.

**Entscheidung.** (2026-07-25) **Behalten + Risiko akzeptieren.** Das
öffentliche Binary ist ohnehin version-identifizierbar (SHA-256-Abgleich mit
Release-Checksums, `gssh-agentd version` nach Download) — Streichen wäre
Scheinschutz gegen gezielte Angreifer und nähme nur Massen-Scannern einen
JSON-Read ab. Gegenwert des Felds: Operator-Diagnose per `curl`, UI-Anzeige
ohne Zusatz-Call. Als bewusste Entscheidung in Security-Sektion vermerkt.

### K14 🟡 Token in argv/Shell-History: Residualrisiko dokumentieren

**Befund.** `--token` steht kurzzeitig in `ps`/`/proc/*/cmdline` des
Zielhosts und dauerhaft in der Shell-History des Operators.

**Vorschlag.** Akzeptieren — Einmalverbrauch + kurze TTL entwerten das Token
nach Gebrauch; auf dem Zielhost ist ein Angreifer mit ps-Zugriff vor dem
Enrollment ohnehin Game-over. Als bewusstes Residualrisiko in die
Sicherheits-Sektion aufnehmen, kein Umbau.

**Entscheidung.** (2026-07-25) Akzeptiert, nur Doku: Security-Sektion nennt
argv/History-Exposition als bewusstes Residualrisiko. Alternativen geprüft
und verworfen: Env-Prefix steht genauso in der History, `sudo` strippt Envs
(Friktion), Gewinn nur root-lesbares `/proc/environ` statt argv — marginal
auf frisch provisionierten Hosts; stdin-Prompt geht bei `curl | sh` nicht
(stdin = Pipe), `sh -c "$(curl …)"`-Variante verschlechtert Copy-UX ohne die
History-Exposition zu beheben. Tragende Kontrolle: Einmalverbrauch + kurze
TTL (in K7 bewusst verteidigt); Rest deckt K16 (Revoke, Future) ab.

### K15 🟡 `pintls`: Berechnungs-Helper fehlt

**Befund.** Plan sagt „Wiederverwendung `internal/pintls`“ — das Paket bietet
`DecodePin`/`Transport`/`Verifier`, aber keinen Helper zur Pin-Berechnung aus
einem Zertifikat.

**Vorschlag.** Kleiner Neuzugang `pintls.FromCertificate(*x509.Certificate)
string` (SHA-256 über `RawSubjectPublicKeyInfo`, Base64) — nutzen
Pin-Provider und Tests gemeinsam. Plan-Formulierung anpassen.

**Entscheidung.** (2026-07-25) Angenommen: `pintls.FromCertificate` kommt
als Helper ins Paket; Nutzer sind Pin-Provider (Dial- und Datei-Quelle,
K2/K9) sowie der bestehende handgestrickte Test-Helper `spkiPin()` in
`internal/cli/client_test.go`, der auf den Helper migriert.
Inline-Berechnung an drei Stellen verworfen.

### K16 🟡 Offene Enroll-Tokens: Liste/Revoke fehlt (Future)

**Befund.** UI-Mint erzeugt Tokens mit 1 h TTL; es gibt keinen UI-Weg, ein
vor Gebrauch geleaktes Token zu widerrufen.

**Vorschlag.** Nicht in diesem Scope (kurze TTL, Einmalverbrauch). Als
Future-Note: `GET/DELETE /v1/admin/enroll-tokens` + UI-Liste offener Tokens.

**Entscheidung.** (2026-07-25) Bewusst **außerhalb** dieses Scopes:
Leak-Fenster durch 1-h-TTL + Einmalverbrauch klein (K14), Liste+Revoke wäre
eigener Feature-Block (API, UI-Tabelle, Audit-Events) für einen Randfall
ohne Bedarf. Future-Note bleibt hier dokumentiert; gebaut bei Bedarf.

### K17 🟡 Erfolgsmeldung ohne Health-Check

**Befund.** Script meldet Erfolg direkt nach `systemctl enable --now` — ob
der Daemon wirklich läuft (z. B. falsche Agent-URL, siehe K4), sieht der
Operator nicht.

**Vorschlag.** Schritt 8 erweitern: kurz warten, `systemctl is-active`
prüfen; bei Fehlschlag klare Meldung + Hinweis auf
`journalctl -u gssh-agentd`, Exit ≠ 0. Erst dann Erfolgsmeldung.

**Entscheidung.** (2026-07-25) Angenommen, verstärkt um Readiness-Signal:
(1) `systemctl is-active --quiet` nach kurzer Wartezeit (fängt
Crash-on-Start); (2) Warten auf `/var/lib/guided-ssh/agentd.sock` (≤ 10 s) —
der Daemon legt den Socket erst bei Bereitschaft an (dasselbe Signal nutzt
die Testfixture), stärker als `is-active` bei `Type=simple`. Fehlschlag ⇒
Meldung + `journalctl -u gssh-agentd -n 20`-Hinweis, Exit ≠ 0; entfällt bei
`--no-systemd`. Dokumentierte Grenze: falsche Agent-URL fällt hier nicht
zwingend auf (Dial ggf. erst bei Zertifikats-Erneuerung) — dagegen schützt
das K4-Gate, nicht dieser Check.
