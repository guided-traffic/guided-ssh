# ADR-021: Session-Audit auf dem Host — pam_exec, Serial-Korrelation, Opt-in

## Status

Akzeptiert (Phase 9). Konkretisiert ADR-005 Stufe 2.

## Kontext

Die Nachvollziehbarkeit endete bislang bei der Zertifikatsausstellung
(serverseitig) und den lokalen sshd-Logs. Was nach dem Login geschieht —
Session-Start/-Ende, `sudo`-Aufrufe — war zentral nicht sichtbar. ADR-005 hat
für die Host-Integration „sshd-nativ zuerst, NSS/PAM später (kein C-Code im
Login-Pfad)" festgelegt. Offene Fragen für Phase 9: Wie werden Session-Events
erfasst und übertragen, wie an die Ausstellung korreliert, und wer entscheidet,
ob ein Host das Feature bekommt?

## Entscheidung

1. **`pam_exec` statt C-PAM-Modul.** Eine `session optional pam_exec.so quiet …
   gssh-agentd pam-session`-Zeile je Stack (`/etc/pam.d/sshd`, `/etc/pam.d/sudo`)
   ruft den Agent bei Session-Open/-Close. `optional` + Helfer-Exit immer 0 ⇒
   **fail-open**: ein Fehler blockiert niemals Login oder sudo. Kein C-Code
   (ADR-005), kein Eingriff in die Authentifizierung selbst (nur `session`).

2. **Serial-Korrelation über sshd-Tokens `%s`/`%i`, nicht journald.** Der
   bestehende `AuthorizedPrincipalsCommand`-Helfer erhält am Login zusätzlich
   `-serial %s -keyid %i`. Er meldet den Serial best-effort an den Daemon
   (`recentAuth`-Ring, TTL 2 min), der die nachfolgende Session-Open desselben
   lokalen Benutzers damit anreichert. Server löst über `certificates.serial` den
   Nutzer auf (`host_sessions.user_id`). Das vermeidet brüchiges Log-Parsing und
   ist unit-testbar. `LogLevel VERBOSE` wird zusätzlich gesetzt (der Serial
   erscheint so auch in den sshd-Logs als Rückfallebene).

3. **Daemon-Spool + asynchroner Flush.** pam-session-Helfer und Principals-Helfer
   sind dünn und reden über den bestehenden Unix-Socket mit dem Daemon; der
   Daemon puffert Events in `sessions-spool.jsonl` (0600, gedeckelt) und flusht
   sie per mTLS an `POST /v1/agent/sessions`. Verlust-tolerant: bei nicht
   erreichbarem Server bleiben die Events im Spool. Session-Ende wird
   serverseitig über `(host, lokaler Benutzer, tty)` der jüngsten offenen Session
   zugeordnet; sudo-Events werden nur als Audit-Event (`session.sudo`) geführt.

4. **Schreibschutz der Socket-Endpunkte per Token.** Die neuen POST-Endpunkte
   (`/auth`, `/session-event`) verlangen ein Token aus `<state>/socket-token`
   (0600, nur root lesbar), damit lokale unprivilegierte Nutzer keine
   Audit-Events fälschen. `GET /principals` bleibt unverändert offen.

5. **Aktivierung host-lokal, Opt-in.** `gssh-agentd enroll --session-audit`
   (Default aus) entscheidet, ob die Verkabelung geschrieben wird. Die invasive
   Änderung am PAM-Stack ist zwangsläufig lokal — nichts kann den Stack aus der
   Ferne editieren, bevor der Agent verdrahtet ist. Kein zentraler Schalter in
   dieser Ausbaustufe.

## Konsequenzen

- Session-/sudo-Events erscheinen ohne UI-Änderung in der Audit-Ansicht (Phase 8)
  als `session.opened`/`session.closed`/`session.sudo`.
- Das **sudo-Kommando ist best-effort** (`SUDO_COMMAND` aus dem Session-Env);
  vollständig zuverlässig nur über ein sudo-Logfile oder -Plugin — spätere
  Härtung, bewusst nicht im MVP.
- Die Serial↔Session-Zuordnung ist eine Heuristik (Benutzer + Zeitfenster); bei
  parallelen Logins desselben lokalen Benutzers innerhalb weniger Sekunden kann
  sie einen Serial vertauschen. Für Audit-Zwecke akzeptiert; der Login selbst ist
  davon unberührt.
- Enrollment ohne `--session-audit` verhält sich exakt wie Phase 5 (kein Token,
  keine PAM-Änderung, sshd-Snippet ohne `-serial`).
- NSS für zentrale Konten und UI-Dashboards (aktive Sessions je Host/Nutzer)
  bleiben offen; das Backend (`host_sessions`, `ListActiveSessions`) steht bereit.
