package agentd

import (
	"context"
	"time"
)

// RunPAMSession ist das Ziel des pam_exec-Hooks (session open/close in sshd und
// sudo). Es baut aus der PAM-Umgebung ein Session-Ereignis und liefert es an den
// Daemon-Socket. Der Aufrufer (cli) beendet sich IMMER mit 0 — der Hook ist
// `optional` und darf Login/sudo niemals blockieren (fail-open). Der Serial für
// sshd-Sessions wird erst im Daemon aus den zuvor gemeldeten Login-Daten ergänzt.
//
// env liefert Umgebungsvariablen (os.Getenv bzw. ein Fake in Tests); now erlaubt
// den Zeitstempel in Tests zu fixieren.
func RunPAMSession(ctx context.Context, stateDir string, env func(string) string, now func() time.Time) error {
	token := readSocketToken(stateDir)
	if token == "" {
		// Session-Audit nicht aktiviert (oder Token fehlt) — nichts zu tun.
		return nil
	}
	event, ok := pamEvent(env, now)
	if !ok {
		return nil
	}
	cfg, err := LoadConfig(stateDir)
	if err != nil {
		return err
	}
	postCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	client := newSocketClient(cfg.SocketPath, 3*time.Second)
	return postSocketJSON(postCtx, client, token, "/session-event", event)
}

// pamEvent bildet die PAM-Umgebung auf ein sessionEventWire ab. ok=false, wenn
// Pflichtfelder fehlen (PAM_TYPE/PAM_SERVICE/PAM_USER) — dann wird nichts gesendet.
func pamEvent(env func(string) string, now func() time.Time) (sessionEventWire, bool) {
	phase := pamPhase(env("PAM_TYPE"))
	service := env("PAM_SERVICE")
	user := env("PAM_USER")
	if phase == "" || service == "" || user == "" {
		return sessionEventWire{}, false
	}
	remoteUser := env("PAM_RUSER")
	if remoteUser == "" {
		remoteUser = env("SUDO_USER") // sudo setzt PAM_RUSER nicht immer
	}
	return sessionEventWire{
		Phase:      phase,
		Service:    service,
		LocalUser:  user,
		RemoteUser: remoteUser,
		RemoteAddr: env("PAM_RHOST"),
		TTY:        env("PAM_TTY"),
		// Command ist best-effort: sudo stellt SUDO_COMMAND im Session-Env oft
		// bereit, garantiert ist es nicht (zuverlässig nur via sudo-Logfile/Plugin).
		Command:    env("SUDO_COMMAND"),
		OccurredAt: now(),
	}, true
}

// pamPhase mappt PAM_TYPE (open_session/close_session) auf phase; leer bei
// unbekanntem Typ (z. B. auth/account — dort ist kein pam_exec konfiguriert).
func pamPhase(pamType string) string {
	switch pamType {
	case "open_session":
		return "open"
	case "close_session":
		return "close"
	default:
		return ""
	}
}
