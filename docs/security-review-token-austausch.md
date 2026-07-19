# Security-Review: Token-Austausch (Phase 10)

Gegenstand: die unauthentifizierten Austausch-Endpunkte `POST /v1/sign/user`
(ID-Token → Benutzerzertifikat), `POST /v1/sign/ci` (GitLab-Job-Token →
CI-Zertifikat) und `POST /v1/enroll` (Einmal-Token → Host-/mTLS-Zertifikat).
Reviewed: Replay, Audience-Confusion, Clock-Skew, Brute-Force/DoS.
Stand: Phase 10; gefundene Punkte sind entweder behoben (→ Fix) oder als
akzeptiertes Restrisiko begründet.

## Replay

- **ID-Token sind innerhalb ihrer Gültigkeit mehrfach eintauschbar.** Es gibt
  bewusst keinen `jti`-Replay-Cache: der Server ist stateless skalierbar, ein
  verlässlicher Cache bräuchte Shared State über Replikate. Einordnung:
  Transport ist TLS-geschützt; wer ein ID-Token abgreifen kann, kann im
  selben Zugriff meist auch den legitimen Austausch abwarten. Jede
  Ausstellung wird transaktional auditiert (Actor, Serial, Kontext) und ist
  damit nachvollziehbar. **Restrisiko akzeptiert.** Betriebsempfehlung: kurze
  ID-Token-Lifetime im IdP (Minuten — die CLI holt Tokens ohnehin frisch pro
  Login-Flow).
- **CI-Token:** GitLab setzt `exp` auf das Job-Timeout; die
  Zertifikatslaufzeit wird zusätzlich auf `exp` gedeckelt
  (`sign_ci.go`) — nach Job-Ende ist weder Token noch Zertifikat brauchbar.
  Mehrfacheintausch innerhalb desselben Jobs ist möglich, erzeugt aber nur
  weitere Zertifikate derselben Projekt-Identität und volle Audit-Spur
  (`pipeline_id`, `job_id`).
- **Enrollment-Token sind echte Einmal-Token:** Verbrauch ist transaktional
  (Hash-Vergleich in der DB), ein zweiter Versuch trifft ein verbrauchtes
  Token → 403.

## Audience-Confusion

- Benutzer- und CI-Tokens laufen über **getrennte Verifier mit eigenem
  Issuer und eigener Audience** (ADR-019); ein CI-Token am
  Benutzer-Endpunkt scheitert an Audience (und i. d. R. Issuer), umgekehrt
  ebenso.
- **Fix (fail-fast):** `GSSH_OIDC_ISSUER` ohne `GSSH_OIDC_CLIENT_ID` ist
  jetzt ein Startfehler statt einer Laufzeit-Ablehnung aller Tokens —
  vorher lief der Server scheinbar korrekt an und lehnte still jeden
  Sign-Request ab.
- **Fix (Konfigurationsfalle):** Sind Benutzer-OIDC und GitLab-CI auf
  denselben Issuer konfiguriert **und** Audience gleich Client-ID, wären
  Tokens an beiden Endpunkten austauschbar (ein CI-Token könnte einen
  Benutzer anlegen). Der Server verweigert diese Konfiguration jetzt beim
  Start (`checkAudienceSeparation`).
- Die Web-UI verwendet bewusst dieselbe Audience wie die CLI
  (`GSSH_UI_OIDC_CLIENT_ID`, Default `GSSH_OIDC_CLIENT_ID`) — Admin-API und
  Sign-Endpoint akzeptieren dieselbe Token-Klasse; Autorisierung passiert
  dahinter über Gruppen (Rollen) bzw. Grants.

## Clock-Skew

- go-oidc prüft `exp` **ohne Leeway** und `nbf` (falls vorhanden) mit
  **5 min Leeway**. Ein Server, dessen Uhr vorgeht, lehnt frische Tokens ggf.
  als abgelaufen ab — Betriebsvoraussetzung: NTP auf Server und IdP
  (im Kubernetes-Deployment gegeben).
- Zertifikate werden 1 min rückdatiert (`signBackdate`), damit Hosts mit
  leicht nachgehender Uhr frisch ausgestellte Zertifikate akzeptieren; die
  Policy deckelt Rückdatierung auf 5 min. Die Gesamtlaufzeit zählt ab dem
  rückdatierten `ValidAfter` und bleibt so unter dem Policy-Maximum.
- CI: `validBefore` wird auf Token-`exp` gedeckelt; läuft das Token zu bald
  ab, wird die Ausstellung abgelehnt statt ein totgeborenes Zertifikat zu
  liefern (`sign_ci.go`).

## Brute-Force / DoS (Fixes Phase 10)

- **Rate-Limiting pro Client-IP** auf `sign/user`, `sign/ci`, `enroll`:
  Request-Budget (Default 60/min, Burst 20) plus separates, enges
  Failure-Budget (Default 10/min) — 401/403-Antworten zehren es auf, danach
  429. Konfiguration: `GSSH_SIGN_RATE_PER_MINUTE`,
  `GSSH_SIGN_FAIL_PER_MINUTE`, `GSSH_RATE_TRUST_PROXY` (X-Forwarded-For nur
  hinter vertrauenswürdigem Proxy).
- **Body-Limits (64 KiB)** auf allen Austausch-Endpunkten gegen
  Speicher-DoS; die Agent-Session-Ingestion hatte bereits 1 MiB.
- Enrollment-Tokens sind 256 bit Zufall (Base64URL), gespeichert nur als
  SHA-256 — Brute-Force ist rechnerisch aussichtslos, das Rate-Limit
  begrenzt zusätzlich die Versuchsrate.

## Nicht-Befunde (geprüft, in Ordnung)

- Fehlermeldungen der Verifier landen im Log, nie das rohe Token; 401-Antworten
  sind generisch.
- `validity_seconds ≤ 0` fällt auf den Server-Default zurück; Deckelung durch
  Grant-Maximum und Policy ist unabhängig davon wirksam.
- Ein bereits signiertes Zertifikat als `public_key` wird abgelehnt (keine
  Zertifikatsketten).
- mTLS-Agent-Identität stammt ausschließlich aus dem CN des verifizierten
  Client-Zertifikats; CSRs können keine Identität vorgeben (Enrollment wie
  Rotation).
