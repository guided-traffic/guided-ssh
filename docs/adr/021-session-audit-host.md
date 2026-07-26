# ADR-021: Session audit on the host — pam_exec, serial correlation, opt-in

## Status

Accepted (Phase 9). Refines ADR-005 stage 2.

## Context

Traceability previously ended at certificate issuance (server-side) and the
local sshd logs. What happened after login — session start/end, `sudo`
invocations — was not visible centrally. ADR-005 established for host
integration "sshd-native first, NSS/PAM later (no C code in the login
path)." Open questions for Phase 9: how are session events captured and
transmitted, how are they correlated with issuance, and who decides whether a
host gets the feature?

## Decision

1. **`pam_exec` instead of a C PAM module.** A single `session optional
   pam_exec.so quiet … gssh-agentd pam-session` line per stack
   (`/etc/pam.d/sshd`, `/etc/pam.d/sudo`) invokes the agent on session
   open/close. `optional` + the helper always exiting 0 ⇒ **fail-open**: a
   failure never blocks login or sudo. No C code (ADR-005), no interference
   with authentication itself (only `session`).

2. **Serial correlation via sshd tokens `%s`/`%i`, not journald.** The
   existing `AuthorizedPrincipalsCommand` helper additionally receives
   `-serial %s -keyid %i` at login. It reports the serial best-effort to the
   daemon (`recentAuth` ring, TTL 2 min), which enriches the subsequent
   session-open of the same local user with it. The server resolves the
   user via `certificates.serial` (`host_sessions.user_id`). This avoids
   fragile log parsing and is unit-testable. `LogLevel VERBOSE` is
   additionally set (so the serial also appears in the sshd logs as a
   fallback layer).

3. **Daemon spool + asynchronous flush.** The pam-session helper and the
   principals helper are thin and talk to the daemon over the existing Unix
   socket; the daemon buffers events in `sessions-spool.jsonl` (0600,
   capped) and flushes them via mTLS to `POST /v1/agent/sessions`.
   Loss-tolerant: if the server is unreachable, events remain in the spool.
   Session end is resolved server-side against the most recent open session
   for `(host, local user, tty)`; sudo events are recorded only as an audit
   event (`session.sudo`).

4. **Write protection on the socket endpoints via token.** The new POST
   endpoints (`/auth`, `/session-event`) require a token from
   `<state>/socket-token` (0600, root-readable only), so that local
   unprivileged users cannot forge audit events. `GET /principals` remains
   unchanged and open.

5. **Activation is host-local, opt-in.** `gssh-agentd enroll --session-audit`
   (default off) decides whether the wiring is written. The invasive change
   to the PAM stack is necessarily local — nothing can remotely edit the
   stack before the agent is wired up. There is no central switch at this
   stage.

## Consequences

- Session/sudo events appear in the audit view (Phase 8) without any UI
  change, as `session.opened`/`session.closed`/`session.sudo`.
- The **sudo command is best-effort** (`SUDO_COMMAND` from the session
  environment); fully reliable only via a sudo logfile or plugin — future
  hardening, deliberately not in the MVP.
- The serial↔session correlation is a heuristic (user + time window); with
  concurrent logins of the same local user within a few seconds, it can
  mismatch a serial. Accepted for audit purposes; the login itself is
  unaffected.
- Enrollment without `--session-audit` behaves exactly like Phase 5 (no
  token, no PAM change, sshd snippet without `-serial`).
- NSS for centralized accounts and UI dashboards (active sessions per
  host/user) remain open items; the backend (`host_sessions`,
  `ListActiveSessions`) is ready.
