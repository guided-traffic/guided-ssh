package agentd

import (
	"context"
	"time"
)

// RunPAMSession is the target of the pam_exec hook (session open/close in
// sshd and sudo). It builds a session event from the PAM environment and
// delivers it to the daemon socket. The caller (cli) ALWAYS exits with 0 —
// the hook is `optional` and must never block login/sudo (fail-open). The
// serial for sshd sessions is only filled in by the daemon from previously
// reported login data.
//
// env supplies environment variables (os.Getenv, or a fake in tests); now
// lets tests pin the timestamp.
func RunPAMSession(ctx context.Context, stateDir string, env func(string) string, now func() time.Time) error {
	token := readSocketToken(stateDir)
	if token == "" {
		// Session audit not enabled (or token missing) — nothing to do.
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

// pamEvent maps the PAM environment onto a sessionEventWire. ok=false when
// required fields are missing (PAM_TYPE/PAM_SERVICE/PAM_USER) — nothing is
// sent in that case.
func pamEvent(env func(string) string, now func() time.Time) (sessionEventWire, bool) {
	phase := pamPhase(env("PAM_TYPE"))
	service := env("PAM_SERVICE")
	user := env("PAM_USER")
	if phase == "" || service == "" || user == "" {
		return sessionEventWire{}, false
	}
	remoteUser := env("PAM_RUSER")
	if remoteUser == "" {
		remoteUser = env("SUDO_USER") // sudo does not always set PAM_RUSER
	}
	return sessionEventWire{
		Phase:      phase,
		Service:    service,
		LocalUser:  user,
		RemoteUser: remoteUser,
		RemoteAddr: env("PAM_RHOST"),
		TTY:        env("PAM_TTY"),
		// Command is best-effort: sudo often provides SUDO_COMMAND in the
		// session env, but it's not guaranteed (reliable only via the
		// sudo logfile/plugin).
		Command:    env("SUDO_COMMAND"),
		OccurredAt: now(),
	}, true
}

// pamPhase maps PAM_TYPE (open_session/close_session) to phase; empty for
// an unknown type (e.g. auth/account — no pam_exec is configured there).
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
