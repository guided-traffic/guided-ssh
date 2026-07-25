# One-Command Host-Install — Umsetzungsplan

> **Stand 2026-07-25.** Die Review-Kritik vom 2026-07-25 (K1–K17) ist in diese
> Fassung **vollständig eingearbeitet** — jede Kritik ist an der Stelle
> aufgelöst, an der sie umzusetzen ist. Die frühere separate Review-Sektion ist
> damit aufgegangen; die alte Fassung steht in der Git-Historie. Das
> Entscheidungs-Log am Ende fasst alle Review-Entscheidungen nachvollziehbar
> zusammen.
>
> Dieser Plan ist so geschrieben, dass er ohne Vorwissen über die
> Review-Diskussion umsetzbar ist. Jedes Arbeitspaket nennt **Dateien**,
> **Schritte**, **Nicht tun** (bewusst verworfene Wege — bitte wirklich nicht
> tun, die Gründe stehen dabei) und **Fertig, wenn** (Prüfkriterien).

Ziel: Auf der Web-Seite **Hosts** ein Button „Host hinzufügen“. Klick zeigt ein
einmaliges Enrollment-Token plus **eine Kommandozeile**, die man auf einem
Linux-Host einfügt und die den Agenten **vollständig installiert** — Binary,
systemd-Unit, Enrollment, Dienststart. Die Agent-Binaries liegen **im
Server-Container** (versionsgleich zum laufenden Server), der Download läuft
rein intern — kein Umweg über GitHub-Releases, air-gap-tauglich.

---

## Begriffe (für Einsteiger)

| Begriff | Bedeutung |
|---|---|
| **Public-Listener** | Der normale HTTP-Listener des Servers (UI, Admin-API, `/v1/enroll`, `/v1/sign/*`). Aufgebaut in `internal/api/server.go` → `New(deps)`. TLS terminiert **davor** am Reverse-Proxy/Ingress, nicht im Server. |
| **Agent-Listener** | Separater mTLS-Listener für enrollte Agenten (`/v1/agent/…`, Singular!). Aufgebaut via `NewAgent`. **Wird in diesem Plan nicht angefasst.** |
| **Enrollment-Token** | Einmaliges Bearer-Secret `gssh-et-…` (32 Zufallsbytes, base64url). In der DB liegt nur der SHA-256-Hash (`store.EnrollmentToken`), der Klartext existiert genau einmal in der Antwort. |
| **SPKI-Pin** | Base64(SHA-256(SubjectPublicKeyInfo)) des TLS-Zertifikats, das der Host beim Enrollment sieht. Der Agent (`gssh-agentd enroll --pin`) verweigert dann jede andere Gegenstelle. Werkzeuge dazu: `internal/pintls`. |
| **fail-closed** | Bei fehlender Voraussetzung oder Fehler wird **abgebrochen bzw. abgeschaltet** — niemals still mit unsicherem Fallback weitergemacht. Leitprinzip dieses Plans. |
| **Hairpin** | Der Server ruft seinen **eigenen externen** URL auf (durch den Reverse-Proxy zurück zu sich selbst). Scheitert in manchen Umgebungen (Cloud-LB ohne Hairpin-NAT, NetworkPolicies, Split-Horizon-DNS) — deshalb gibt es alternative Pin-Quellen. |
| **Split-Horizon-DNS** | Derselbe DNS-Name löst intern anders auf als extern. Folge: der Server sieht beim Selbst-Dial u. U. ein **anderes** Zertifikat als die Hosts von außen. |

---

## Machbarkeit: JA

Alle Bausteine existieren, es fehlt Verdrahtung, kein neues Konzept
(gegen den Code verifiziert):

| Baustein | Status heute | Was fehlt |
|---|---|---|
| Web-Bundling ins Server-Binary | `web/embed.go` → `//go:embed all:dist` | zweites Embed für Agent-Binaries |
| Cross-Build Agent (linux/amd64+arm64) | `make cross` baut `bin/gssh-agentd-linux-<arch>` mit `LDFLAGS` | im Dockerfile als eigene Build-Stage |
| Token-Erzeugung | `gssh-server enroll-token` (`cmd/gssh-server/main.go: runEnrollToken`) + `store.CreateEnrollmentToken` | Admin-API-Endpoint statt nur CLI |
| Host-Enrollment | `gssh-agentd enroll --server --agent-url --token [--pin] [--session-audit]` (Flags in `internal/agentd/cli.go`, idempotent) | neues Flag `--require-pin` |
| Manuelles Install-Script | `deploy/packaging/install.sh` (GitHub-Release-Variante) | server-getemplatete Variante, Download vom Server |
| Getrennte Listener | Public-Mux (`New`) und mTLS-Agent-Mux (`NewAgent`) getrennt | neue Public-Routen unter `/v1/agents/` (Plural — kein Konflikt mit `/v1/agent/`) |
| Rate-Limiting | `internal/api/ratelimit.go` (`RateLimiter`, Token-Bucket pro Client-IP, `TrustProxyHeader`) | zweite Instanz für Downloads |
| Pin-Werkzeuge | `internal/pintls` (`DecodePin`, `Transport`, `Verifier`) | Helper `FromCertificate` |
| Externe URL | `GSSH_UI_BASE_URL` | zusätzlich `GSSH_PUBLIC_URL`, `GSSH_AGENT_PUBLIC_URL` |

**Versionsgleichheit ist geschenkt:** Agent-Binaries entstehen im **selben
Docker-Build** wie der Server (gleiche `-ldflags`, gleicher Commit) und liegen
im Server-Image. Der Server serviert exakt das Binary, das zu ihm passt.

**Alle Arches, immer, unabhängig von der Server-Arch.** Der Zielhost kann eine
andere Architektur haben als der Server (amd64-Server, arm64-Host o. u.).
Deshalb werden die Agent-Binaries **für alle unterstützten Ziel-Arches
cross-gebaut und komplett eingebettet**. Cross-Build ist `CGO_ENABLED=0`
statisch, also aus jeder Build-Umgebung möglich. Ziel-Arches (Agent ist
linux-only, systemd): aktuell **linux/amd64, linux/arm64**; erweiterbar durch
einen Eintrag in der Build-Schleife.

---

## Ziel-Ablauf (UX)

1. Admin öffnet **Hosts** → Button **„Host hinzufügen“**.
2. Dialog: optional Hostname-Bindung, Tags (`env=prod,role=web`), TTL
   (Default 1 h), Session-Audit-Checkbox (Default aus).
3. Klick **„Token erzeugen“** → Server mintet einmaliges Token; Antwort enthält
   Token-Klartext (einmalig!), `expires_at` und das fertige `install_command`.
4. Dialog zeigt die **Copy-Zeile** plus **Arch-Auswahl** (Dropdown):
   - Default **„auto (Script erkennt)“** — eine Zeile für alle Arches, das
     Script macht `uname -m`:
     ```
     curl -fsSL https://gssh.example.com/install.sh | sudo sh -s -- --token gssh-et-XXXXXXXX
     ```
   - Explizite Wahl **amd64 / arm64** — pinnt die Arch (nötig bei
     Cross-Provisioning, wo `uname` auf der ausführenden Maschine nicht die
     Ziel-Arch liefert):
     ```
     curl -fsSL https://gssh.example.com/install.sh | sudo sh -s -- --token gssh-et-XXXXXXXX --arch arm64
     ```
   Die Arch-Liste im Dropdown kommt aus dem Manifest (`GET /v1/agents`) — nur
   tatsächlich eingebettete Arches erscheinen.
5. Operator fügt die Zeile auf dem Linux-Host ein. **Ein Kommando**, Ende:
   Binary installiert, Unit aktiv, Host enrolled, sshd konfiguriert.

Das server-servierte `install.sh` ist zur Laufzeit getemplatet und enthält
bereits Server-URL, Agent-URL, Version, per-Arch-SHA-256, systemd-Unit-Inhalt
und den (Pflicht-)SPKI-Pin. Einzige Variablen sind Token und optionale Flags.

---

## Eiserne Regeln (was zu lassen ist)

Diese Regeln gelten für **alle** Arbeitspakete. Sie sind das Kondensat der
Review-Entscheidungen — jede einzelne hat einen konkreten Schadensfall hinter
sich. Im Zweifel: Regel befolgen, nicht „pragmatisch“ abweichen.

1. **Niemals `InsecureSkipVerify`** — nirgends, auch nicht „nur um das
   Zertifikat zu lesen“. Ein unverifizierter Pin-Dial würde einen
   MITM-Angreifer-Pin in jedes `install.sh` templaten und damit den gesamten
   Pinning-Mechanismus aushebeln. Es gibt in diesem Feature **keinen**
   `InsecureSkipVerify`-Codepfad.
2. **Keine URL-Ableitung.** `GSSH_AGENT_PUBLIC_URL` wird niemals aus anderen
   Werten „geraten“ (Host + interner Port ≠ externer Port hinter LB/Ingress).
   Fehlt die Env ⇒ Rollout-Gate zu (503). Eine falsche Agent-URL landet sonst
   unbemerkt in `config.yaml` von N Hosts und knallt erst beim ersten
   Zertifikats-Renew — Korrektur hieße N Hosts anfassen.
3. **Kein ungepinnter Codepfad im Rollout.** Kein Pin ermittelbar ⇒ Endpoints
   503, UI-Button ausgegraut, Script bricht bei leerem Pin ab. Niemals still
   ohne Pin enrollen.
4. **Token-Klartext nie loggen, nie speichern.** In der DB liegt nur der
   SHA-256-Hash; das Audit-Event enthält Tags/TTL/Actor, **nicht** das Token.
5. **`install.sh` ist POSIX-`sh`.** Kein bash, kein `set -o pipefail` (in
   dash/busybox-sh nicht verlässlich) — Pipe-Fehler werden explizit über
   Exit-Codes geprüft. Gesamtes Script in `main() { … }`, letzte Zeile
   `main "$@"` (Schutz gegen abgebrochene Übertragung, die sonst ein halbes
   Script ausführt).
6. **Binary-Tausch atomar, ohne Stop.** Download in ein Tempfile **im selben
   Verzeichnis** (`/usr/bin/.gssh-agentd.XXXXXX`, gleiche Partition — nicht
   `/tmp`!), Hash prüfen, `chmod`, dann `mv -f`. `rename(2)` ersetzt auch
   laufende Binaries ohne „text file busy“. Kein `systemctl stop` vor dem
   Kopieren. Und: `systemctl enable --now` startet eine **bereits aktive**
   Unit nicht neu — bei aktiver Unit stattdessen `systemctl restart`.
7. **Eine Quelle für die systemd-Unit.** Die Datei zieht per `git mv` nach
   `internal/agentdist/gssh-agentd.service` und wird von dort eingebettet
   (`go:embed` kann nicht über das Package-Verzeichnis hinausgreifen — darum
   Umzug statt Referenz). `nfpm.yaml` zeigt auf den neuen Pfad. **Kein**
   zweites Here-Doc-Duplikat im Repo — das driftet zwangsläufig.
8. **`/v1/agents/…` (Plural) nur auf dem Public-Listener.** `/v1/agent/…`
   (Singular) ist der mTLS-Listener — nicht anfassen, nichts dort einhängen.
9. **Eine Wahrheit für die Client-IP.** Der neue Download-Limiter übernimmt
   `TrustProxyHeader` aus derselben Env wie der reguläre Limiter
   (`GSSH_RATE_TRUST_PROXY`). Keine zweite XFF-Konfiguration erfinden.
   (Achtung: die Env heißt wirklich `GSSH_RATE_TRUST_PROXY` — nicht
   `…_TRUST_XFF`, wie eine frühere Planfassung schrieb.)
10. **`Cache-Control: no-store` auf allen drei Endpoints** — `install.sh`,
    Manifest **und** Binary-Download. Ein Cache, der nach einem Server-Upgrade
    das alte Binary zur neuen `install.sh` liefert, erzeugt
    Phantom-Hash-Mismatches. Eine Regel statt drei; Binary-Caching hätte
    ohnehin keinen Nutzen (ein Download pro Host-Lebenszeit).
11. **Agent-Binaries nie committen.** `internal/agentdist/bin/` bleibt im Repo
    leer (`.gitkeep`), `.gitignore`-Eintrag kommt dazu. Befüllt wird das
    Verzeichnis nur im Docker-Build (und lokal für Tests).
12. **Bestehende Install-Pfade unverändert lassen.** deb/rpm und der manuelle
    Weg behalten ihr Verhalten (Pin dort weiterhin optional, kein
    `--require-pin`-Default). Dieses Feature ist ein **zusätzlicher** Pfad.

---

## Neue Umgebungsvariablen (Überblick)

Alle neuen Envs auf einen Blick; Details in den Arbeitspaketen.

| Env | Zweck | Default |
|---|---|---|
| `GSSH_PUBLIC_URL` | Externe Public-URL (Basis für `install_command` und Ziel des Pin-Selbst-Dials) | leer → Fallback `GSSH_UI_BASE_URL` |
| `GSSH_PUBLIC_PIN` | Pin-Quelle 1: statischer Base64-SPKI-Pin (Operator-verwaltet) | leer |
| `GSSH_PUBLIC_PIN_CERT_FILE` | Pin-Quelle 2: Pfad zu PEM-Zertifikat (erster Block = Leaf) | leer |
| `GSSH_PUBLIC_PIN_REFRESH` | Refresh-Intervall des Pin-Selbst-Dials (Go-Duration) | `5m` |
| `GSSH_AGENT_PUBLIC_URL` | Externe mTLS-Agent-URL für `enroll --agent-url` | leer ⇒ **Gate zu** |
| `GSSH_AGENT_DOWNLOAD_RPM` | Download-Limit pro Client-IP und Minute (`0` = aus) | `10` (Burst 5) |

Bestehende, hier relevante Envs: `GSSH_UI_BASE_URL` (externe UI-Basis),
`GSSH_RATE_TRUST_PROXY` (Client-IP aus `X-Forwarded-For` — gilt für **beide**
Limiter).

---

## Umsetzungsreihenfolge

**A → P → B → C → D → E.** A (Binaries) und P (Pin/Gate) sind unabhängig
voneinander und können parallel laufen. B (Endpoints) braucht A **und** P.
C (Mint-API) braucht P (Gate). D (Frontend) braucht B + C. E (Doku, Helm, E2E)
zum Schluss.

---

## Phase A — Agent-Binaries im Container

### A1 — Paket `internal/agentdist`

**Dateien:** `internal/agentdist/agentdist.go` (neu),
`internal/agentdist/bin/.gitkeep` (neu), `.gitignore`.

**Schritte:**

1. Verzeichnis `internal/agentdist/bin/` mit leerer `.gitkeep` anlegen.
   `.gitignore` ergänzen:
   ```
   internal/agentdist/bin/*
   !internal/agentdist/bin/.gitkeep
   ```
2. `agentdist.go` mit Embed und Zugriffs-API:
   ```go
   //go:embed all:bin
   var binFS embed.FS
   ```
   Das `all:`-Präfix ist Pflicht: ohne Binaries enthält `bin/` nur die
   versteckte `.gitkeep`, und ein normales `//go:embed bin` schlägt bei
   „keine einbettbaren Dateien“ fehl. `.gitkeep` wird in der API
   herausgefiltert.
3. Öffentliche API (wird in Phase B vom `api`-Package als Interface
   konsumiert — **nicht** direkt auf `embed.FS` zugreifen, sonst sind die
   Handler nicht testbar):
   ```go
   type Info struct {
       OS     string // "linux"
       Arch   string // "amd64" | "arm64"
       Size   int64
       SHA256 string // Hex, sha256sum-kompatibel
   }

   type Source struct { /* fs.FS + einmal berechnete Infos */ }

   func New() *Source                       // über das Embed
   func NewFromFS(fsys fs.FS) *Source       // für Tests/E2E (fstest.MapFS, os.DirFS)
   func (s *Source) List() []Info           // stabil sortiert; leer im Dev-Build
   func (s *Source) Open(osName, arch string) (io.ReadCloser, Info, error)
   ```
   Dateinamens-Konvention im Embed: `bin/gssh-agentd-linux-<arch>` — exakt
   die Namen, die `make cross` erzeugt. `List()` parst die Namen, ignoriert
   alles andere (insbesondere `.gitkeep`). SHA-256 (Hex!) und Größe werden
   **einmal** beim ersten Zugriff berechnet (`sync.Once`) und gecacht.
4. Die systemd-Unit zieht um (eine Quelle, Regel 7):
   ```
   git mv deploy/packaging/gssh-agentd.service internal/agentdist/gssh-agentd.service
   ```
   In `agentdist.go`: `//go:embed gssh-agentd.service` → `var UnitFile string`.
   In `deploy/packaging/nfpm.yaml` den `src:`-Pfad des Unit-Eintrags auf
   `internal/agentdist/gssh-agentd.service` ändern (deb/rpm-Ziel
   `/lib/systemd/system/…` bleibt unverändert).

**Nicht tun:**
- Binaries per `COPY` in einen Image-Pfad legen und via `os.DirFS` lesen
  (zwei Artefakte, Version-Lockstep nicht mehr garantiert). Entscheidung:
  **Embed**, Tradeoff ~+30–40 MB Server-Binary akzeptiert.
- Die Unit-Datei per `go:generate` kopieren (committetes Duplikat = Drift)
  oder als eigenen Download-Endpoint anbieten (Round-Trip ohne Gewinn).

**Fertig, wenn:** Unit-Tests (mit `NewFromFS` + `fstest.MapFS`) belegen:
`List()` liefert je Fake-Binary korrekte Arch/Größe/Hex-Hash; `Open()` streamt
den Inhalt; unbekannte Arch ⇒ Fehler; leeres FS ⇒ `List()` leer. `make build`
läuft ohne Binaries durch (Dev-Build degradiert sauber). deb/rpm-Build
(`make packages`) funktioniert mit dem neuen Unit-Pfad.

### A2 — Dockerfile: Cross-Build-Stage

**Dateien:** `Dockerfile`.

**Schritte:**

1. Neue Stage **vor** der Server-Build-Stage, zwingend mit
   `--platform=$BUILDPLATFORM`:
   ```dockerfile
   FROM --platform=$BUILDPLATFORM golang:1.26 AS agentbuild
   WORKDIR /src
   COPY go.* ./
   RUN go mod download
   COPY . .
   ARG VERSION=dev
   ARG COMMIT=none
   ARG DATE=unknown
   RUN for arch in amd64 arm64; do \
         CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath \
           -ldflags "-s -w \
             -X github.com/guided-traffic/guided-ssh/internal/version.version=${VERSION} \
             -X github.com/guided-traffic/guided-ssh/internal/version.commit=${COMMIT} \
             -X github.com/guided-traffic/guided-ssh/internal/version.date=${DATE}" \
           -o /out/gssh-agentd-linux-$arch ./cmd/gssh-agentd || exit 1; \
       done
   ```
   Warum `--platform=$BUILDPLATFORM`: Bei buildx-Multi-Arch liefe die Stage
   sonst je Ziel-Plattform unter QEMU-Emulation — Go-Compile wird um ein
   Vielfaches langsamer. So läuft der Compiler nativ und crosst via
   GOOS/GOARCH; die Stage ist plattform-invariant, BuildKit dedupliziert sie,
   die Agenten werden pro Multi-Arch-Build effektiv **einmal** gebaut. Jede
   Server-Plattform-Variante bettet den **vollständigen** Agent-Satz ein
   (amd64-Server enthält auch das arm64-Agent-Binary und umgekehrt).
2. In der bestehenden `build`-Stage vor dem `go build` des Servers:
   ```dockerfile
   COPY --from=agentbuild /out/ ./internal/agentdist/bin/
   ```
   Die `-ldflags` der Agent-Stage sind **identisch** zu denen der
   Server-Stage (gleiche `ARG`s durchreichen) — das ist der Versions-Lockstep.

**Nicht tun:**
- Agent-Binaries als CI-Artefakt bauen und ins Image `COPY`en — bricht den
  Single-Build-Lockstep (Server und Agent könnten aus verschiedenen Commits
  stammen).
- Die bestehende Server-Build-Stage jetzt ebenfalls auf `$BUILDPLATFORM`
  umstellen — sinnvoll, aber **separates Thema**, nicht Teil dieses Plans
  (siehe Future-Notes).

**Fertig, wenn:** `docker build` produziert ein Image, in dem
`GET /v1/agents` (nach Phase B) beide Arches mit korrekten Hashes listet.
Bis dahin reicht als Zwischenprüfung: im Build-Log erscheinen beide
`go build`-Läufe, und ein `docker run --entrypoint=`-Blick bestätigt das
Server-Binary wuchs um ~30–40 MB.

---

## Phase P — Pflicht-Pinning & Rollout-Gate

Der einzige Teil, der neu erfunden wird statt Vorhandenes zu verdrahten —
entsprechend präzise umsetzen. Grundsatz: Der SPKI-Pin ist **verpflichtend**;
kein Codepfad gibt je ein ungepinntes Install-Kommando aus. Ist kein Pin
ermittelbar, ist der gesamte Host-Rollout **deaktiviert** (fail-closed) statt
ungepinnt weiterzumachen.

### P1 — `pintls.FromCertificate`

**Dateien:** `internal/pintls/pintls.go`, `internal/cli/client_test.go`.

**Schritte:**

1. Helper ergänzen (das Paket hat `DecodePin`/`Transport`/`Verifier`, aber
   keinen Berechnungs-Helper):
   ```go
   // FromCertificate liefert den Base64-SPKI-SHA-256-Pin eines Zertifikats.
   func FromCertificate(cert *x509.Certificate) string {
       sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
       return base64.StdEncoding.EncodeToString(sum[:])
   }
   ```
2. Den handgestrickten Test-Helper `spkiPin()` in
   `internal/cli/client_test.go:16` auf `pintls.FromCertificate` migrieren.

**Nicht tun:** Die Berechnung an drei Stellen inline duplizieren (Dial-Quelle,
Datei-Quelle, Tests) — genau dafür ist der Helper da.

**Fertig, wenn:** Unit-Test mit bekanntem Zertifikat → erwarteter Pin;
`internal/cli`-Tests laufen unverändert grün.

### P2 — Pin-Provider mit drei Quellen

**Dateien:** `internal/api/pinprovider.go` (neu) + Test,
`cmd/gssh-server/main.go` (Env-Parsing, Konstruktion).

Drei Quellen mit fester Präzedenz, **alle fail-closed**; die aktive Quelle
wird geloggt und im Manifest ausgewiesen. Sind mehrere gesetzt, gewinnt die
höchste Präzedenz, mit Warnung im Log.

**Quelle 1 — `GSSH_PUBLIC_PIN` (statisch, höchste Präzedenz).**
Operator liefert den Pin selbst; Auto-Dial und Refresh sind aus, Rotation
liegt in Operator-Hand. Letzter Ausweg für Fälle, in denen weder Datei noch
Dial funktionieren (z. B. Zertifikat liegt am CDN). Beim Start mit
`pintls.DecodePin` validieren; ungültiger Wert ⇒ **Startabbruch mit klarer
Fehlermeldung** (fail-fast wie bei `GSSH_HOST_CERT_VALIDITY`).
Doku-Snippet für Operatoren (kommt in Phase E ins README/Helm):
```
openssl s_client -connect gssh.example.com:443 </dev/null 2>/dev/null \
  | openssl x509 -pubkey -noout \
  | openssl pkey -pubin -outform DER \
  | openssl dgst -sha256 -binary | base64
```

**Quelle 2 — `GSSH_PUBLIC_PIN_CERT_FILE` (Datei).**
Pfad zu einem PEM-Zertifikat; **erster** `CERTIFICATE`-Block = Leaf
(cert-manager-Konvention bei `tls.crt`). Die Datei wird bei **jedem**
Servieren frisch gelesen — **kein Caching** (Parse kostet Mikrosekunden;
Stale-Fenster reduziert sich damit auf den Kubelet-Sync des Secret-Mounts,
≤ ~1 min). Lese-/Parse-Fehler ⇒ kein Pin ⇒ Gate zu, Grund loggen.
Löst Hairpin- und Split-Horizon-Deployments ohne manuellen Rotationsaufwand:
In K8s wird das TLS-Secret des Ingress als **Volume** gemountet — kein
K8s-API-Zugriff, kein RBAC; Kubelet aktualisiert den Mount bei
Secret-Rotation. Funktioniert auch ohne K8s (bind-mount von `fullchain.pem`).

**Quelle 3 — Auto-Dial (Default).**
Der Server wählt seinen eigenen externen Public-URL per TLS an
(`GSSH_PUBLIC_URL`, Fallback `GSSH_UI_BASE_URL`), liest das Leaf-Zertifikat
(`ConnectionState().PeerCertificates[0]`) und berechnet den Pin via
`pintls.FromCertificate` — exakt der Wert, den ein echter Host beim
Enrollment sieht. **Zwingend:** Der Dial verifiziert die Zertifikatskette
fail-closed mit **Standard-`tls.Config` gegen System-Roots** — keinerlei
Sonderbehandlung, kein `InsecureSkipVerify`-Codepfad (Regel 1).
Verifikationsfehler ⇒ kein Pin ⇒ Gate zu; Grund in Log und Manifest.
Das Runtime-Image `distroless/static` enthält das CA-Bundle — kein
Image-Umbau. Unternehmens-/Private-CA: CA-Bundle mounten und
`SSL_CERT_FILE`/`SSL_CERT_DIR` setzen (Go liest beide; Achtung:
`SSL_CERT_FILE` **ersetzt** das Standard-Bundle — bei Mischbetrieb
konkatenieren). Self-signed ohne CA ⇒ Quelle 1 oder 2 verwenden.

**Refresh-Verhalten (nur Dial-Quelle):**
- Hintergrund-Loop, Intervall `GSSH_PUBLIC_PIN_REFRESH` (Go-Duration,
  Default `5m`; ungültiger Wert ⇒ Startabbruch).
- **Plus Lazy-Refresh beim Servieren:** Ist der Cache beim Ausliefern von
  `install.sh` oder beim Token-Mint älter als das Intervall, wird synchron
  nachgezogen. Grund: Let’s-Encrypt-Renewals erzeugen standardmäßig neue
  Keys — ohne Lazy-Refresh trüge ein Script im Rotationsfenster planmäßig
  alle ~60–90 Tage einen alten Pin.
- Schlägt ein Refresh fehl, bleibt der **letzte erfolgreich gelesene** Pin
  aktiv (mit Warn-Log). Nur „noch nie ein Pin gelesen“ hält das Gate zu.
- Entschärfung, die man wissen muss: Ein Pin-Mismatch scheitert beim Agenten
  im TLS-Handshake **vor** dem Request — das Token wird dabei **nicht**
  verbraucht, ein Retry ist gratis (zusammen mit B3 ohnehin abgesichert).

**API-Skizze:**
```go
type PinStatus struct {
    Pin    string // leer = kein Pin
    Source string // "static" | "file" | "dial" | ""
    Err    string // letzter Fehler, für Log/Manifest
}
func NewPinProvider(cfg PinProviderConfig, logger *slog.Logger) *PinProvider
func (p *PinProvider) Status(ctx context.Context) PinStatus // wendet Lazy-Refresh an
```
Konstruktion und Env-Parsing in `cmd/gssh-server/main.go` analog zu den
bestehenden Envs; Übergabe an `api.New` via neuem `Deps`-Feld.

**Nicht tun:**
- Multi-Pin (`--pin a,b` während Rotation) — verschoben, YAGNI: Restfenster
  ist Sekunden bis ~1 min alle ~60–90 Tage; später abwärtskompatibel als
  Komma-Liste nachrüstbar (Future-Note).
- Die Datei-Quelle cachen — bewusst ungecacht (s. o.).
- Bei Dial-Fehlern einen ungepinnten Zustand „durchlassen“.

**Fertig, wenn:** Tests belegen: Präzedenz (statisch schlägt Datei schlägt
Dial, Warnung bei Mehrfach-Setzung); Datei-Quelle liest Änderungen sofort;
Dial gegen `httptest`-Server mit nicht vertrauter CA ⇒ kein Pin (kein
Insecure-Fallback); ungültiger statischer Pin ⇒ Startfehler.

### P3 — Rollout-Gate (Server, autoritativ)

**Dateien:** `internal/api/server.go` (+ neue Handler-Dateien Phase B/C).

Das Gate prüft **vier** Bedingungen; solange eine fehlt, antworten
Binary-Download, `install.sh` und Token-Mint mit **503** und die UI graut den
Button aus. Das Manifest (`GET /v1/agents`) bleibt dabei **erreichbar (200)**
und weist die fehlenden Bedingungen **einzeln** aus — eindeutige Diagnose
statt Rätselraten:

| Bedingung | `missing`-Eintrag |
|---|---|
| Agent-Binaries eingebettet (`Source.List()` nicht leer) | `"binaries"` |
| Pin verfügbar (`PinStatus.Pin != ""`) | `"pin"` |
| `GSSH_AGENT_PUBLIC_URL` gesetzt | `"agent_public_url"` |
| Public-Basis-URL bekannt (`GSSH_PUBLIC_URL` oder `GSSH_UI_BASE_URL`) | `"public_url"` |

Die 503-Antworten nennen die fehlenden Bedingungen im Body (gleiche Liste).
Kein eigenes Server-Feature-Flag: **die Gate-Bedingungen sind der Schalter.**

**Nicht tun:** Ein zusätzliches `GSSH_HOST_ROLLOUT_ENABLED`-Flag einführen —
doppelter Zustand, der mit den realen Bedingungen driften kann.

**Fertig, wenn:** Handler-Tests: jede fehlende Einzelbedingung erzeugt 503
mit korrektem `missing`-Eintrag auf Download/Script/Mint, Manifest bleibt 200
und listet dieselben Einträge.

### P4 — Client: `--require-pin`

**Dateien:** `internal/agentd/cli.go` (Enroll-Flagset, Z. 77 ff.),
`internal/agentd/enroll.go` (nur falls nötig), Tests.

**Schritte:**

1. Neues Flag `--require-pin` (bool) im `gssh-agentd enroll`-Flagset plus
   Env-Äquivalent `GSSH_ENROLL_REQUIRE_PIN=1` (Env gesetzt wirkt wie Flag).
2. Verhalten: Ist require-pin aktiv und `--pin` leer/fehlend ⇒ Abbruch mit
   klarer Meldung **vor** jedem Netzwerk-Call.
3. Das getemplatete `install.sh` setzt das Flag **immer** (Phase B3).
   Der manuelle und der deb/rpm-Pfad bleiben unverändert (Default false).

**Ehrliche Einordnung (so auch in Doku und Code-Kommentar formulieren):**
Das ist **Bedienfehler-Schutz, kein MITM-Schutz.** Es verhindert, dass ein
Operator die enroll-Zeile aus dem Script herauskopiert, `--pin` weglässt und
still ungepinnt enrollt. Wer das gepipte Script manipulieren kann, entfernt
auch dieses Flag — dagegen schützen HTTPS-Abruf und die Pin-Quellen (P2),
nicht dieses Flag. Formulierungen wie „Client-Zwang“ oder „erzwingt Pinning“
sind falsch und werden nicht verwendet.

**Fertig, wenn:** Test: `enroll --require-pin` ohne `--pin` bricht ab (kein
Request abgesetzt); mit `--pin` läuft es wie bisher; Env-Variante gleich.

---

## Phase B — Public-Endpoints

Alle neuen Routen liegen im Public-Mux (`internal/api/server.go`, Funktion
`New`), registriert im Go-1.22-Muster (`mux.HandleFunc("GET /v1/agents", …)`).
`Deps` wird erweitert um: `Agents` (Interface über `agentdist.Source`),
`Pins *PinProvider`, `AgentPublicURL string`, `PublicBaseURL string`,
`DownloadRateLimit *RateLimiter`.

### B1 — Manifest `GET /v1/agents`

**Verhalten:** Immer 200 (auch bei geschlossenem Gate — Diagnosefunktion,
siehe P3), `Cache-Control: no-store`, auf dem **regulären** Limiter
(`deps.RateLimit.limit(…)`), unauthentifiziert. Antwort:

```json
{
  "version": "v2.1.1",
  "rollout_ready": false,
  "missing": ["pin"],
  "pin_source": "",
  "agents": [
    { "os": "linux", "arch": "amd64", "size": 15728640, "sha256": "<hex>" },
    { "os": "linux", "arch": "arm64", "size": 14680064, "sha256": "<hex>" }
  ]
}
```

`version` kommt aus `internal/version.String()`. **Bewusste Entscheidung —
Version bleibt im öffentlichen Manifest:** Das öffentliche Binary ist ohnehin
version-identifizierbar (SHA-256-Abgleich mit Release-Checksums,
`gssh-agentd version` nach Download); Streichen wäre Scheinschutz gegen
gezielte Angreifer und nähme nur Massen-Scannern einen JSON-Read ab.
Gegenwert: Operator-Diagnose per `curl`, UI-Anzeige ohne Zusatz-Call.

### B2 — Binary-Download `GET /v1/agents/{os}/{arch}`

**Verhalten:** Unauthentifiziert (der Host hat noch keine Credentials; das
Binary ist ein öffentliches Artefakt — **das Token gated das Enrollment,
nicht den Binary-Zugriff**). Gate geschlossen ⇒ 503. Unbekannte oder nicht
eingebettete os/arch ⇒ 404 mit Klartext. Sonst Stream mit
`Content-Type: application/octet-stream`, `Content-Length`,
`Cache-Control: no-store`.

**Eigener, engerer Rate-Limiter** (Binary ist 15–40 MB — der reguläre
60/min-Limiter der Sign-/Enroll-Endpunkte ist als Flood-Schutz zu locker):

- Zweite `RateLimiter`-Instanz (`api.NewRateLimiter`), nur für diese Route.
- Env `GSSH_AGENT_DOWNLOAD_RPM`, **Default 10/min, Burst 5**, `0` = aus
  (gleiche Semantik wie `GSSH_SIGN_RATE_PER_MINUTE`). Begründung der 10:
  Per-IP-Limits stoppen ohnehin nur Einzelquellen; 10/min leistet das genauso
  wie ein engerer Wert, würgt aber Bulk-Rollouts hinter Firmen-NAT (eine IP,
  Ansible-Loop über 50 Hosts) nicht ab. Worst-Case-Bandbreite pro IP bei
  15–20 MB Binary ≈ 25–35 Mbit/s — als Flood-Schutz ausreichend.
- `TrustProxyHeader` **erbt** aus `GSSH_RATE_TRUST_PROXY` (Regel 9). Sonst
  sähen hinter dem Ingress alle Requests wie die Proxy-IP aus ⇒ 10/min
  **global** — ein Parallel-Rollout wäre ab Host 6 gedrosselt und schwer zu
  diagnostizieren.
- Das Failure-Budget der Instanz bleibt ungenutzt (öffentlicher Endpoint,
  keine 401/403) — Defaults einfach stehen lassen.

### B3 — Install-Script `GET /install.sh`

**Verhalten:** Unauthentifiziert, Gate geschlossen ⇒ 503,
`Cache-Control: no-store`, `Content-Type: text/x-shellscript`. Serverseitig
per `text/template` getemplatet; Template-Werte: Public-Basis-URL,
`GSSH_AGENT_PUBLIC_URL`, Version, per-Arch-SHA-256 (Hex), Pin (Base64),
verfügbare Arch-Liste, Unit-Inhalt (`agentdist.UnitFile`, eingebettet als
quoted Here-Doc `<<'UNIT_EOF'` — keine Shell-Expansion; die Datei ist
statisch, es gibt **kein** Unit-Templating).

**Script-Spezifikation** (POSIX-`sh`; Regeln 5 und 6 gelten vollständig):

Struktur: `set -eu` (kein `pipefail`!), alles in `main() { … }`, letzte Zeile
`main "$@"`; `trap 'rm -f "$tmp"' EXIT` fürs Tempfile.

Flags: `--token <t>` (Pflicht), `--arch <amd64|arm64>` (optional, hat Vorrang
vor `uname -m`), `--session-audit` (optional, Passthrough an enroll),
`--no-systemd` (optional, s. u.).

Ablauf:

1. **Vorbedingungen:** `id -u` = 0, sonst Abbruch („mit sudo ausführen“).
   `command -v curl`, sonst Abbruch („curl installieren“). `command -v sshd`,
   sonst Abbruch („openssh-server installieren“). Fehlt
   `/etc/ssh/ssh_host_ed25519_key.pub` ⇒ `ssh-keygen -A`.
2. **Pin-Guard:** Ist der getemplatete Pin leer ⇒ Abbruch. (Darf durch das
   Server-Gate nie vorkommen — doppelter Boden, Regel 3.)
3. **Arch bestimmen:** `--arch` falls gesetzt, sonst `uname -m` mappen
   (`x86_64`→amd64, `aarch64`→arm64). Unbekannte oder nicht eingebettete
   Arch ⇒ Abbruch, Meldung nennt die verfügbaren Arches (getemplatete Liste).
4. **Binary laden (atomar):** Tempfile im Zielverzeichnis anlegen
   (`mktemp /usr/bin/.gssh-agentd.XXXXXX` — gleiche Partition, **nicht**
   `/tmp`, sonst wird das spätere `mv` ein nicht-atomarer Cross-Device-Copy).
   `curl -fsSL "<base>/v1/agents/linux/$arch" -o "$tmp"`. Hash prüfen:
   `echo "<sha256-hex>  $tmp" | sha256sum -c -` (zwei Leerzeichen!);
   Mismatch ⇒ Abbruch. `chmod 0755 "$tmp"`, dann `mv -f "$tmp"
   /usr/bin/gssh-agentd`. Kein `systemctl stop` vorher — `rename(2)` ersetzt
   auch das Binary eines laufenden Daemons ohne ETXTBSY; der Daemon behält
   sein altes Inode, keine Downtime.
5. **State-Verzeichnis:** `mkdir -p /var/lib/guided-ssh`, `chmod 700`.
6. **Unit schreiben:** Inhalt aus dem Here-Doc nach
   `/etc/systemd/system/gssh-agentd.service` (bewusst `/etc/…`, nicht
   `/lib/…` — `/lib` gehört den Paketen; Script- und deb/rpm-Install dürfen
   ohnehin nicht gemischt werden, README-Hinweis in Phase E). Wird auch bei
   `--no-systemd` geschrieben.
7. **Enroll (mit Degradation statt Skip):**
   ```
   gssh-agentd enroll --server <base> --agent-url <agent-url> \
     --token "$token" --pin <pin> --require-pin [--session-audit]
   ```
   Enroll läuft **immer** (kein „skip wenn schon enrolled“). Schlägt er fehl
   **und** `/var/lib/guided-ssh/config.yaml` existiert ⇒ deutliche Warnung
   „bestehendes Enrollment wird weiterverwendet“, Merker setzen,
   **weitermachen**. Ohne `config.yaml` ⇒ harter Abbruch. Das deckt beides
   ab: Re-Run derselben Zeile nach Teilfehler (Token schon verbraucht ⇒
   Enroll scheitert, altes Enrollment trägt) und echtes Re-Enroll mit
   frischem Token (Enroll gelingt, idempotentes Überschreiben) — ohne
   zusätzliches Flag. Bewusste Kante: Ein gewolltes Re-Enroll, das aus
   anderem Grund scheitert, läuft mit dem alten Enrollment weiter — darum
   muss die Warnung unübersehbar sein (auch in der Abschlussmeldung
   wiederholen); der Host endet immer funktionsfähig.
8. **systemd (zustandsabhängig):** Bei `--no-systemd`: alle
   `systemctl`-Schritte und den Health-Check überspringen; am Ende explizit
   auflisten, was übersprungen wurde, plus manuelles Aktivierungskommando
   (`systemctl daemon-reload && systemctl enable --now gssh-agentd`).
   Sonst: `systemctl daemon-reload`; ist die Unit bereits aktiv
   (`systemctl is-active --quiet gssh-agentd`) ⇒ `systemctl restart
   gssh-agentd` (Upgrade lädt das neue Binary — `enable --now` würde eine
   aktive Unit **nicht** neu starten), sonst ⇒ `systemctl enable --now
   gssh-agentd`.
9. **Health-Check (entfällt bei `--no-systemd`):** Bis zu 10 s warten auf
   **beides**: `systemctl is-active --quiet gssh-agentd` **und** Existenz von
   `/var/lib/guided-ssh/agentd.sock` — der Daemon legt den Socket erst bei
   Bereitschaft an (dasselbe Signal nutzt die Testfixture); das ist bei
   `Type=simple` stärker als `is-active` allein. Fehlschlag ⇒ Meldung mit
   Hinweis `journalctl -u gssh-agentd -n 20`, Exit ≠ 0. Dokumentierte
   Grenze: Eine falsche Agent-URL fällt hier nicht zwingend auf (der Agent
   dialt sie ggf. erst zur Zertifikats-Erneuerung) — dagegen schützt das
   Gate aus P3/Regel 2, nicht dieser Check.
10. **Erfolgsmeldung** — inklusive Wiederholung der
    „Enrollment weiterverwendet“-Warnung, falls Schritt 7 degradiert hat.

**Warum `--no-systemd` existiert:** Die E2E-Fixture
(`internal/agentd/testdata/sshd`, alpine) hat kein systemd — ohne das Flag
wäre der Smoke-Test nicht ausführbar (Phase E4). Nebeneffekt: nützt echten
Hosts ohne systemd-PID-1 (Container-Hosts mit eigenem Supervisor).

**Nicht tun:**
- `set -o pipefail` (Regel 5), bash-Syntax, `mktemp` unter `/tmp`.
- Selbst-Hash-Prüfung des Scripts (Bootstrap-Zirkel — wer das Script
  manipuliert, manipuliert den Prüfwert mit).
- Ein `--force-reenroll`-Flag oder „Enroll skippen wenn config existiert“ —
  die Degradations-Logik aus Schritt 7 deckt beide Fälle ohne Flag ab.
- Mehrfach nutzbare Tokens oder ein Token-Reissue-Endpoint als
  Re-Run-Lösung — Sicherheits-Rückschritt bzw. API-Surface für einen
  Randfall; der Einmalverbrauch ist tragende Sicherheitskontrolle.
- systemctl-Stub in der Fixture (täuscht Verhalten vor, schluckt echte
  Fehler) oder privilegierter systemd-Container im CI (flaky/verboten).

**Fertig, wenn:** Handler-Tests: korrekte Content-Types, `no-store` auf allen
drei Routen, 503-Pfade je Gate-Bedingung, 404 bei unbekannter Arch,
Script-Inhalt enthält Pin/Hashes/URLs/Unit; `sh -n` (Syntax-Check) über das
gerenderte Script läuft in einem Test. Die Ablauf-Logik selbst deckt Phase E4
ab.

---

## Phase C — Token-Minting-API

### C1 — Mint-Logik teilen (CLI + API identisch)

**Dateien:** `internal/store/enrollment.go`, `cmd/gssh-server/main.go`.

Die Token-Erzeugung aus `runEnrollToken` (`cmd/gssh-server/main.go:296`) in
einen gemeinsamen, netz­freien Helper extrahieren, damit CLI und API garantiert
identisch minten:

```go
// in internal/store:
// NewEnrollmentToken erzeugt Klartext ("gssh-et-" + 32 Byte base64url) und
// den zugehörigen Record (nur Hash). Der Aufrufer persistiert via
// CreateEnrollmentToken und zeigt den Klartext genau einmal an.
func NewEnrollmentToken(hostname string, tags map[string]string, ttl time.Duration) (plaintext string, rec *EnrollmentToken, err error)
```

`runEnrollToken` auf den Helper umstellen — Verhalten der CLI (Defaults,
Ausgabeformat, TTL-Default **24 h**) bleibt unverändert.

### C2 — `POST /v1/admin/enroll-tokens`

**Dateien:** `internal/api/admin_ui.go` (Route + Handler), `internal/store`
(Audit-Konstante).

**Schritte:**

1. Route im Admin-Muster registrieren:
   `mux.HandleFunc("POST /v1/admin/enroll-tokens", admin.authorized(roleAdmin, admin.handleCreateEnrollToken))`.
2. Request-Body:
   ```json
   { "hostname": "web-01", "tags": {"env":"prod"}, "ttl_seconds": 3600, "session_audit": false }
   ```
   Alle Felder optional. `ttl_seconds`: Default **3600** (bewusst kürzer als
   der 24-h-CLI-Default — UI-Tokens entstehen unmittelbar vor Gebrauch);
   validiert auf 60 ≤ ttl ≤ 86400, sonst 400. `session_audit` wird **nicht**
   am Token gespeichert (das Token-Schema kennt es nicht) — es steuert nur
   das `--session-audit`-Flag im `install_command`.
3. Gate-Prüfung wie in P3 (fehlende Bedingung ⇒ 503 mit `missing`).
4. Antwort (Klartext **einmalig** — wird nirgends geloggt oder gespeichert):
   ```json
   {
     "token": "gssh-et-…",
     "expires_at": "2026-07-25T13:37:00Z",
     "install_command": "curl -fsSL https://gssh.example.com/install.sh | sudo sh -s -- --token gssh-et-… [--session-audit]"
   }
   ```
   Basis-URL des Kommandos: `GSSH_PUBLIC_URL`, Fallback `GSSH_UI_BASE_URL`
   (durch das Gate garantiert vorhanden). Die `--arch`-Varianten baut das
   Frontend selbst aus dem Manifest (D2).
5. Audit-Event: Konstante `EventEnrollTokenCreated = "host.enroll_token.created"`
   in `internal/store` (analog `EventHostEnrolled`); schreiben via
   `AppendAuditEvent` mit Actor (Session-User), Payload
   `{hostname, tags, ttl_seconds, expires_at}` — **ohne** Token, ohne Hash
   (Regel 4).

**Fertig, wenn:** Handler-Tests: Nicht-Admin ⇒ 403; Gate zu ⇒ 503; Erfolg ⇒
Token-Prefix `gssh-et-`, `expires_at` ≈ jetzt+TTL, `install_command` enthält
Token und (nur bei `session_audit: true`) das Flag; Tags/Hostname landen im
Record; Audit-Event vorhanden und token-frei; CLI-Test von `enroll-token`
weiterhin grün.

---

## Phase D — Frontend

**Dateien:** `web/src/app/features/hosts.ts`,
`web/src/app/features/host-add-dialog.ts` (neu), `api/openapi.yaml`,
`web/src/app/api/…` (generierter Client).

### D1 — Button + Gate-Anzeige

In den `page-header` von `hosts.ts` (neben „Aktualisieren“) ein
`mat-flat-button` **„Host hinzufügen“**. Beim Laden der Seite zusätzlich
`GET /v1/agents` abrufen: `rollout_ready: false` ⇒ Button **disabled** mit
Hinweistext, der die `missing`-Einträge menschenlesbar aufzählt (z. B.
„Pin noch nicht ermittelt“, „GSSH_AGENT_PUBLIC_URL fehlt“, „Server-Build ohne
Agent-Binaries“). Kein stilles Verstecken des Buttons — der Operator soll
sehen, **warum** es nicht geht.

### D2 — Dialog

Neue Standalone-Dialog-Komponente im Muster von `grants.ts` (MatDialog).

**Formular-Ansicht:** Hostname (optional, Text), Tags (Text,
`env=prod,role=web`), TTL (Select: 15 min / **1 h Default** / 4 h / 24 h),
Session-Audit-Checkbox (Default **aus**) mit Erklärtext:
> Aktiviert Host-Session-/sudo-Audit: Der Agent hängt `pam_exec`-Hooks an die
> PAM-Stacks von sshd und sudo (`/etc/pam.d/*`) und korreliert Sessions mit
> Zertifikaten (sshd `LogLevel VERBOSE`). Meldet Session-Start/-Ende und
> sudo-Aktionen an die Plattform. Ändert die PAM-Konfiguration des Hosts —
> deshalb Opt-in.

Submit → `POST /v1/admin/enroll-tokens`.

**Ergebnis-Ansicht:**
- Token maskiert + Copy-Button; Hinweis „Token wird nur einmal angezeigt,
  TTL läuft bereits“.
- **Arch-Dropdown**: „auto (Script erkennt)“ + je eine Option pro Arch aus
  dem Manifest. Auswahl passt die Copy-Zeile live an (hängt `--arch <x>` an);
  Copy-Button für die Zeile.
- Agent-Liste (arch, Größe human-readable, SHA-256) aus dem Manifest.
- **Zwei-Schritt-Alternative** ausklappbar, für alle, die kein `curl | sh`
  ausführen wollen (kein Zwang zum Pipe-to-shell):
  ```
  curl -fsSLO https://gssh.example.com/install.sh
  less install.sh          # prüfen
  sudo sh install.sh --token gssh-et-…
  ```

### D3 — OpenAPI + Client

`api/openapi.yaml` (Single Source of Truth der REST-API) um
`/v1/admin/enroll-tokens`, `/v1/agents`, `/v1/agents/{os}/{arch}` und
`/install.sh` erweitern. Client regenerieren wie gehabt (ng-openapi-gen,
devDependency in `web/package.json`; erzeugt `web/src/app/api/fn/…`). Falls
die Generator-Invokation unklar ist: die neuen Request-Funktionen
handschreiben, exakt im Muster der bestehenden Dateien unter
`web/src/app/api/fn/` — nicht die generierten Dateien von Hand editieren.

**Fertig, wenn:** `npm test` grün; manueller Durchstich im Dev-Setup: Button
disabled ohne Pin (Server ohne Envs starten), enabled mit; Dialog mintet,
Copy-Zeile wechselt mit Arch-Auswahl; `ng build` läuft.

---

## Phase E — Doku, Helm, E2E

### E1 — Helm-Chart (Deployzeit-Validierung, fail-fast)

**Dateien:** `deploy/helm/guided-ssh/values.yaml`,
`deploy/helm/guided-ssh/templates/…`, Chart-README.

Neuer Values-Block (jeder Parameter mit **maximal 2 Zeilen** on-point
Kommentar — keine Prosa-Absätze):

```yaml
hostRollout:
  # One-Command-Host-Install (UI-Button "Host hinzufügen"). Bei true werden
  # die Pflicht-Envs verlangt (helm scheitert sonst beim Rendern).
  enabled: false
  # Externe mTLS-Agent-URL für enrollte Agenten (Pflicht bei enabled).
  agentPublicUrl: ""
  # Externe Public-URL (install_command + Pin-Dial); leer = ui.baseUrl.
  publicUrl: ""
  pin:
    # Pin-Quelle: dial (Default) | file | static — siehe Tabelle im README.
    source: dial
    # source=static: Base64-SPKI-Pin (openssl-Snippet im README).
    static: ""
    # source=file: TLS-Secret des Ingress; Chart mountet NUR tls.crt.
    certSecretName: ""
    # Refresh-Intervall des Pin-Dials (Go-Duration).
    refreshInterval: 5m
  # Binary-Downloads pro Client-IP und Minute (0 = aus).
  downloadRpm: 10
```

Template-Logik:
- `enabled: false` ⇒ es wird **nichts** gerendert und nichts verlangt
  (Feature strikt optional).
- `enabled: true` ⇒ `required`-Checks im Template für `agentPublicUrl` und —
  je nach `pin.source` — für `pin.static` bzw. `pin.certSecretName`;
  `helm install/upgrade/lint` scheitert beim Rendern mit Klartext-Meldung.
  Misconfig knallt beim Setup, nicht auf der Flotte. (Zweite Schicht: das
  Server-Gate aus P3 bleibt autoritativ — es deckt Nicht-Helm-Deployments
  und Drift ab. Der Helm-Toggle steuert **nur** das Rendern der Envs, kein
  doppelter Server-Zustand.)
- `pin.source: file` ⇒ Volume aus `certSecretName` mounten. Regeln
  (Begründung: Kubelet aktualisiert Secret-Mounts nur ohne subPath):
  **kein `subPath`**; nur `tls.crt` projizieren (`items:`-Auswahl —
  `tls.key` bleibt draußen, der Server braucht ihn nicht); Secret muss im
  Server-Namespace liegen (Wildcard-Cert in fremdem Namespace: reflector/
  kubed oder eigenes `Certificate`). Env `GSSH_PUBLIC_PIN_CERT_FILE` auf den
  Mount-Pfad setzen.
- Gerenderte Envs: `GSSH_AGENT_PUBLIC_URL`, `GSSH_PUBLIC_URL`,
  `GSSH_PUBLIC_PIN` | `GSSH_PUBLIC_PIN_CERT_FILE`,
  `GSSH_PUBLIC_PIN_REFRESH`, `GSSH_AGENT_DOWNLOAD_RPM`.

Chart-README ergänzt: Mini-Entscheidungstabelle „welche Pin-Quelle wann“
(dial = Default, wenn der Server seinen externen URL erreichen kann; file =
Hairpin/Split-Horizon/cert-manager; static = letzter Ausweg, z. B. CDN),
Volume-Snippet, openssl-Snippet, Hairpin-Hinweis **nur** beim dial-Abschnitt.

### E2 — README / DEVELOPER

- README (englisch — Konvention: neue User-Docs auf Englisch): neuer
  interner Install-Weg mit UI-Flow, Sicherheitsmodell-Kurzfassung,
  Pflicht-Pinning und Pin-Quellen, Zwei-Schritt-Alternative.
- Deutliche Zeile: **Script-Install und deb/rpm nicht mischen** (das Script
  legt eine paketfremde Datei in `/usr/bin` und eine Unit in
  `/etc/systemd/system` ab; `deploy/packaging/install.sh` bleibt als
  GitHub-Fallback bestehen).
- Dual-Cert-Proxies (RSA+ECDSA je nach Client): eine Doku-Zeile — beide
  Pin-Konsumenten (Server-Dial und Agent) sind Go-TLS mit praktisch gleicher
  Cipher-Auswahl; bei der Datei-Quelle gegenstandslos.
- DEVELOPER.md: `internal/agentdist`-Konzept, Dev-Build-Degradation (503),
  wie man lokal Binaries einbettet (`make cross` + Kopie nach
  `internal/agentdist/bin/`), E2E-Aufruf.

### E3 — Sicherheits-Restpunkte dokumentieren

In die Sicherheits-Sektion (unten) aufgenommen und im README zu spiegeln:
- **Token in argv/History (akzeptiert):** `--token` steht kurz in
  `ps`/`/proc/*/cmdline` des Zielhosts und dauerhaft in der Shell-History des
  Operators. Alternativen geprüft und verworfen: Env-Variante steht genauso
  in der History und `sudo` strippt Envs; stdin geht bei `curl | sh` nicht
  (stdin ist die Pipe); `sh -c "$(curl …)"` verschlechtert die Copy-UX ohne
  die History-Exposition zu beheben. Tragende Kontrolle: Einmalverbrauch +
  kurze TTL — nach Gebrauch ist das Token wertlos.
- **Versions-Disclosure (akzeptiert):** siehe B1.
- **systemctl-Pfad im CI ungetestet (bewusste Restlücke):** siehe E4.

### E4 — E2E-Smoke

**Dateien:** neuer Integrationstest (Muster:
`internal/agentd/enroll_integration_test.go` — Build-Tag `integration`,
testcontainers-go), `internal/agentd/testdata/sshd/Dockerfile`.

**Schritte:**

1. Fixture-Dockerfile: `curl` in die `apk add`-Liste aufnehmen (das
   alpine-Image hat keins; das Script verlangt curl).
2. Testablauf: Postgres + API-Server wie im bestehenden Test hochziehen;
   `agentdist.NewFromFS(os.DirFS(<tmpdir>))` mit einem für linux gebauten
   agentd-Binary befüllen (das Embed ist zur Testzeit leer — deshalb existiert
   `NewFromFS`); Pin-Quelle: statisch, berechnet via
   `pintls.FromCertificate` aus dem Test-TLS-Zertifikat (dogfoodet P1);
   Token über die Mint-API (C2) erzeugen; im sshd-Fixture-Container
   `install.sh` per curl holen und mit `--token … --no-systemd` ausführen.
3. Asserts: Script-Exit 0; Binary installiert; `config.yaml` entstanden
   (worauf der Fixture-Entrypoint den Agenten selbst startet und
   `agentd.sock` erscheint — dasselbe Readiness-Signal wie im Script);
   Host-Row enrolled. Damit ist die Kette **Token → Script → Download →
   Hash-Check → Enroll → laufender Agent** abgedeckt.
4. Restlücke explizit dokumentieren (E2/E3): der `systemctl`-Zweig
   (enable/restart/Health-Check) bleibt CI-ungetestet — die Fixture hat kein
   systemd, ein systemd-Container im CI wäre flaky/privilegiert, ein
   systemctl-Stub würde Verhalten vortäuschen.

**Fertig, wenn:** `go test -tags integration ./internal/agentd/ -run
InstallScript` (Name analog Bestand) lokal grün; CI-Job führt ihn aus.

---

## Sicherheitsmodell (Zusammenfassung)

Dies ist `curl … | sudo sh` — die klassische Supply-Chain-Angriffsfläche.
Maßnahmen und bewusst akzeptierte Restrisiken:

- **Nur über HTTPS ausliefern.** TLS terminiert am Ingress/Reverse-Proxy vor
  dem Server; das Script wird über `https://` gezogen.
- **SHA-256 des Binaries ins Script getemplatet.** Manipulation des
  Binary-Downloads fliegt beim Hash-Check auf, Script bricht ab.
- **SPKI-Pin ist Pflicht, kein Opt-in.** Drei fail-closed-Quellen
  (statisch > Datei > verifizierter Selbst-Dial, Phase P2); ohne Pin ist der
  gesamte Rollout deaktiviert (Gate P3). Cert-Rotation wird von Datei-Quelle
  (ungecacht) und Dial-Quelle (Background- + Lazy-Refresh) automatisch
  nachgezogen; ein Pin-Mismatch scheitert im TLS-Handshake **bevor** das
  Token verbraucht ist.
- **`--require-pin` = Bedienfehler-Schutz.** Verhindert versehentlich
  ungepinnte Enrollments (herauskopierte enroll-Zeile). **Kein**
  MITM-Schutz — den leisten HTTPS + Pin-Quellen.
- **Zwei-Schritt-Alternative in der UI** (herunterladen, prüfen, ausführen) —
  kein Zwang zum Pipe-to-shell.
- **Token = einmaliges, kurzlebiges Bearer-Secret.** UI-Default 1 h,
  Einmalverbrauch serverseitig erzwungen (bestehend). Klartext genau einmal
  in der Mint-Antwort; nie in Logs, nie im Audit-Payload. Akzeptierte
  Restexposition: argv/`ps` auf dem Zielhost + Shell-History des Operators
  (Begründung und verworfene Alternativen: E3).
- **Binary-Download öffentlich, aber eng rate-limited** (10/IP/min, Burst 5,
  `GSSH_AGENT_DOWNLOAD_RPM`, XFF-Verhalten geerbt). Das Token gated das
  Enrollment, nicht den Binary-Zugriff.
- **Token-Mint nur roleAdmin, audit-geloggt** (`host.enroll_token.created`).
- **Versions-Disclosure im Manifest akzeptiert** (Begründung: B1).
- **`Cache-Control: no-store` auf Script, Manifest und Binary** — keine
  stale Pins/Hashes/Binaries aus Zwischencaches.

---

## Fahrplan (abhaken)

### Phase A — Agent-Binaries im Container
- [x] A1: Paket `internal/agentdist` (Embed `all:bin`, `Source` mit `New`/`NewFromFS`/`List`/`Open`, Hex-SHA-256, `.gitkeep`-Filter, `.gitignore`) + Unit-Umzug (`git mv` + `nfpm.yaml`-Pfad) + Tests (fstest.MapFS)
- [x] A2: Dockerfile-Stage `agentbuild` (`--platform=$BUILDPLATFORM`, GOOS/GOARCH-Schleife amd64+arm64, identische `-ldflags`) + `COPY` ins Embed-Verzeichnis

### Phase P — Pflicht-Pinning & Rollout-Gate
- [x] P1: `pintls.FromCertificate` + Migration `spkiPin()` in `internal/cli/client_test.go`
- [x] P2: Pin-Provider — Präzedenz `GSSH_PUBLIC_PIN` > `GSSH_PUBLIC_PIN_CERT_FILE` (ungecacht) > Auto-Dial (System-Roots, fail-closed, Background- + Lazy-Refresh via `GSSH_PUBLIC_PIN_REFRESH`); aktive Quelle in Log + Manifest; Tests
- [x] P3: Rollout-Gate — vier Bedingungen (binaries, pin, agent_public_url, public_url); Download/Script/Mint 503 mit `missing`, Manifest immer 200 mit Diagnose; Tests
  (Gate + 503-Antwort implementiert und getestet; die Verdrahtung an
  Download/Script/Mint und die Manifest-Diagnose folgen mit B1–B3/C2)
- [x] P4: `gssh-agentd enroll --require-pin` + `GSSH_ENROLL_REQUIRE_PIN` (fail-closed vor Netz-Call); manueller/deb-Pfad unverändert; Tests

### Phase B — Public-Endpoints
- [ ] B1: `GET /v1/agents` (Manifest mit version/rollout_ready/missing/pin_source/agents, regulärer Limiter, `no-store`)
- [ ] B2: `GET /v1/agents/{os}/{arch}` (Stream, 404/503-Pfade, `no-store`) + zweite `RateLimiter`-Instanz (`GSSH_AGENT_DOWNLOAD_RPM` Default 10, Burst 5, `TrustProxyHeader` aus `GSSH_RATE_TRUST_PROXY`)
- [ ] B3: `GET /install.sh` — Template (Base-URL, Agent-URL, Version, per-Arch-Hash, Pflicht-Pin, Unit-Here-Doc) + Script nach Spezifikation (main()-Wrapper, `set -eu` ohne pipefail, trap, Same-Dir-Tempfile + atomarem `mv`, Enroll-Degradation, restart-vs-enable, Health-Check Socket ≤ 10 s, Flags `--arch`/`--session-audit`/`--no-systemd`) + Handler-/`sh -n`-Tests

### Phase C — Token-Minting-API
- [ ] C1: `store.NewEnrollmentToken` extrahieren, `runEnrollToken` umstellen (CLI-Verhalten unverändert)
- [ ] C2: `POST /v1/admin/enroll-tokens` (roleAdmin, TTL-Default 1 h, Gate-geprüft, `install_command`, Audit `host.enroll_token.created` ohne Token) + Tests

### Phase D — Frontend
- [ ] D1: Button „Host hinzufügen“ in `hosts.ts`, disabled + Klartext-Hinweis aus Manifest-`missing`
- [ ] D2: Dialog (Formular mit TTL/Tags/Hostname/Session-Audit-Erklärtext → Mint; Ergebnis mit Token-Copy, Arch-Dropdown, Agent-Liste, Zwei-Schritt-Alternative)
- [ ] D3: `api/openapi.yaml` + Client (regeneriert oder handgeschrieben im `fn/`-Muster)

### Phase E — Doku, Helm, E2E
- [ ] E1: Helm `hostRollout`-Block (`enabled` + `required`-Checks, Pin-Quellen-Rendering, Secret-Volume nur `tls.crt` ohne `subPath`, je Parameter ≤ 2 Zeilen Doku) + README-Tabelle/Snippets
- [ ] E2: README (en) + DEVELOPER (Install-Weg, Nicht-Mischen-Hinweis, Dual-Cert-Zeile, Dev-Degradation)
- [ ] E3: Restrisiken dokumentiert (argv/History, Version, systemctl-Lücke)
- [ ] E4: E2E-Smoke (Fixture + curl, `NewFromFS`, statischer Pin via `FromCertificate`, Mint → `install.sh --no-systemd` → enrolled + Agent läuft)

---

## Entscheidungs-Log

Kernentscheidungen (alle 2026-07-25, Review K1–K17 vollständig aufgelöst und
oben eingearbeitet):

| # | Thema | Entscheidung |
|---|---|---|
| — | Bundling | **Embed** (`go:embed`) statt Image-Pfad — Single-Artifact, harter Version-Lockstep; +30–40 MB akzeptiert |
| — | Download-Zugriff | Manifest + Binary **öffentlich**; Token gated das Enrollment; Download eng rate-limited |
| — | Session-Audit | Checkbox im Dialog, Default aus, Opt-in mit Erklärtext (ändert PAM-Konfig) |
| K1 | Pin-Selbst-Dial | Verifiziert fail-closed gegen System-Roots; **kein** `InsecureSkipVerify`-Codepfad; Private-CA via `SSL_CERT_FILE`/`SSL_CERT_DIR` |
| K2 | Hairpin-Escape | Drei Pin-Quellen: statisch > Datei (Secret-Volume, rotationsfähig) > Dial; alle fail-closed, aktive Quelle sichtbar |
| K3 | `--require-pin` | Behalten, aber ehrlich als **Bedienfehler-Schutz** deklariert (kein MITM-Schutz) |
| K4 | Agent-URL | **Keine** Ableitung; Helm-`required` (fail-fast) + Server-Gate (autoritativ); Manifest nennt fehlende Bedingungen einzeln; kein Feature-Flag |
| K5 | Download-Limiter | Erbt `TrustProxyHeader` aus `GSSH_RATE_TRUST_PROXY`; Default 10/min Burst 5; token-gebundener Download verworfen |
| K6 | E2E ohne systemd | Script-Flag `--no-systemd`; systemctl-Stub und systemd-Container verworfen; systemctl-Pfad bleibt dokumentierte CI-Lücke |
| K7 | Re-Run nach Teilfehler | Enroll-Degradation (Warnung + weiter, wenn `config.yaml` existiert); Same-Dir-Tempfile + atomarer `mv` statt `systemctl stop`; restart-vs-enable zustandsabhängig; Mehrfach-Token/Reissue verworfen |
| K8 | Dockerfile | Agent-Stage mit `--platform=$BUILDPLATFORM` + GOOS/GOARCH-Schleife; CI-Artefakt-COPY verworfen; Server-Stage-Optimierung = Future |
| K9 | Cert-Rotation | Datei-Quelle ungecacht; Dial mit Background- + Lazy-Refresh; Multi-Pin = Future (YAGNI); Pin-Mismatch verbraucht kein Token |
| K10 | Caching | `no-store` auf **allen drei** Endpoints (auch Binary); ETag-Revalidierung verworfen |
| K11 | Script-Härtung | `main()`-Wrapper, `set -eu` ohne `pipefail`, `trap`-Cleanup; Selbst-Hash verworfen (Bootstrap-Zirkel) |
| K12 | Unit-Quelle | `git mv` nach `internal/agentdist/`, dort embedded, im Script als quoted Here-Doc; `nfpm.yaml` folgt; Duplikat-Varianten verworfen |
| K13 | Version im Manifest | Behalten + Risiko akzeptiert (Binary ohnehin identifizierbar; Streichen = Scheinschutz) |
| K14 | Token in argv/History | Akzeptiert (Einmalverbrauch + TTL tragen); Env-/stdin-Varianten verschieben die Exposition nur |
| K15 | Pin-Berechnung | Neuer Helper `pintls.FromCertificate`; Test-Helper `spkiPin` migriert; Inline-Duplikate verworfen |
| K16 | Token-Liste/Revoke | Bewusst außerhalb des Scopes (Future-Note) |
| K17 | Health-Check | `is-active` **plus** Warten auf `agentd.sock` (≤ 10 s), `journalctl`-Hinweis, Exit ≠ 0; entfällt bei `--no-systemd`; falsche Agent-URL fängt das K4-Gate |

Korrektur gegenüber früherer Planfassung: Die XFF-Vertrauens-Env heißt im
Code `GSSH_RATE_TRUST_PROXY` (nicht `GSSH_RATE_TRUST_XFF`); die
Frontend-Referenz `enrollment/enroll-host.ts` existiert nicht — Dialog-Muster
ist `grants.ts`, Client-Muster `web/src/app/api/fn/`.

## Future-Notes (bewusst nicht in diesem Scope)

- **Token-Verwaltung:** `GET/DELETE /v1/admin/enroll-tokens` + UI-Liste
  offener Tokens (Revoke vor Gebrauch). Leak-Fenster ist durch 1-h-TTL +
  Einmalverbrauch klein; bauen bei Bedarf.
- **Multi-Pin während Rotation:** `--pin a,b` als Komma-Liste,
  abwärtskompatibel nachrüstbar, falls das Sekunden-Restfenster je stört.
- **Server-Build-Stage** ebenfalls auf `--platform=$BUILDPLATFORM` heben
  (Build-Zeit-Optimierung, unabhängig von diesem Feature).
- **Weitere Arches** (386, arm/v7, riscv64): je ein Eintrag in der
  Dockerfile-Schleife (A2) — Manifest, Script-Dropdown und UI ziehen
  automatisch nach.
