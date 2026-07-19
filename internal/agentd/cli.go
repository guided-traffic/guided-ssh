package agentd

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/guided-traffic/guided-ssh/internal/version"
)

// Run führt das Agent-CLI aus und liefert den Exit-Code (0 ok, 1 Fehler,
// 2 Aufruffehler).
func Run(stdout, stderr io.Writer, args []string) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	command, rest := args[0], args[1:]
	switch command {
	case "enroll":
		return runEnrollCmd(ctx, rest, stdout, stderr)
	case "run":
		return runDaemonCmd(ctx, rest, stdout, stderr)
	case "principals":
		return runPrincipalsCmd(ctx, rest, stdout, stderr)
	case "pam-session":
		runPAMSessionCmd(ctx, rest, stderr)
		return 0 // fail-open: pam_exec darf niemals blockieren
	case "version":
		fmt.Fprintln(stdout, version.String())
		return 0
	case "help", "-h", "--help":
		usage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "gssh-agentd: unbekanntes kommando %q\n\n", command)
		usage(stderr)
		return 2
	}
}

// usage gibt die Kommandoübersicht aus.
func usage(w io.Writer) {
	fmt.Fprint(w, `gssh-agentd — host-agent von guided-ssh

kommandos:
  enroll --server url --agent-url url --token t [--hostname n] [--tags k=v,…]
         [--pin b64] [--state-dir d] [--ssh-dir d] [--ssh-key pfad] [--session-audit]
         host registrieren: zertifikate holen, sshd-konfiguration schreiben;
         --session-audit aktiviert zusätzlich session-/sudo-audit (pam_exec)
  run [--state-dir d]
         daemon: zertifikat erneuern (2/3 laufzeit), ca-bundle pflegen,
         principals-cache + unix-socket für sshd bedienen
  principals -user <name> [-serial N] [-keyid ID] [-state-dir d]
         AuthorizedPrincipalsCommand-helper (fail-closed); serial/keyid (sshd-
         tokens) nur bei aktivem session-audit (korrelation session↔zertifikat)
  pam-session [-state-dir d]
         pam_exec-ziel (session open/close in sshd/sudo); meldet session-/sudo-
         events an den daemon, beendet sich immer mit 0 (fail-open)
  version
         version ausgeben
`)
}

// runEnrollCmd behandelt gssh-agentd enroll.
func runEnrollCmd(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gssh-agentd enroll", flag.ContinueOnError)
	fs.SetOutput(stderr)
	server := fs.String("server", "", "öffentliche api des gssh-servers (POST /v1/enroll)")
	agentURL := fs.String("agent-url", "", "mtls-agent-api des gssh-servers")
	token := fs.String("token", "", "einmaliges enrollment-token")
	hostname := fs.String("hostname", "", "hostname (default: os.Hostname)")
	tagsFlag := fs.String("tags", "", "host-tags, z. B. env=prod,role=web")
	pin := fs.String("pin", "", "spki-sha-256-pin des enroll-endpoints (base64)")
	stateDir := fs.String("state-dir", DefaultStateDir, "state-verzeichnis des agenten")
	sshDir := fs.String("ssh-dir", DefaultSSHDir, "sshd-konfigurationsverzeichnis")
	sshKey := fs.String("ssh-key", "", "ssh-host-public-key (default: <ssh-dir>/ssh_host_ed25519_key.pub)")
	sessionAudit := fs.Bool("session-audit", false, "host-session-/sudo-audit aktivieren (pam_exec-hooks, opt-in)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	tags, err := parseTags(*tagsFlag)
	if err != nil {
		fmt.Fprintf(stderr, "gssh-agentd: %v\n", err)
		return 2
	}
	opts := EnrollOptions{
		ServerURL: *server, AgentURL: *agentURL, Token: *token,
		Hostname: *hostname, Tags: tags, PinSHA256: *pin,
		StateDir: *stateDir, SSHDir: *sshDir, SSHKeyPath: *sshKey,
		SessionAudit: *sessionAudit,
	}
	if err := Enroll(ctx, opts, stdout); err != nil {
		fmt.Fprintf(stderr, "gssh-agentd: enrollment fehlgeschlagen: %v\n", err)
		return 1
	}
	return 0
}

// runDaemonCmd behandelt gssh-agentd run.
func runDaemonCmd(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gssh-agentd run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	stateDir := fs.String("state-dir", DefaultStateDir, "state-verzeichnis des agenten")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	logger := slog.New(slog.NewJSONHandler(stdout, nil))
	daemon, err := NewDaemon(*stateDir, logger)
	if err != nil {
		fmt.Fprintf(stderr, "gssh-agentd: %v\n", err)
		return 1
	}
	if err := daemon.Run(ctx); err != nil {
		logger.Error("daemon beendet", "error", err)
		return 1
	}
	return 0
}

// runPrincipalsCmd behandelt gssh-agentd principals (sshd-Helper).
func runPrincipalsCmd(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gssh-agentd principals", flag.ContinueOnError)
	fs.SetOutput(stderr)
	stateDir := fs.String("state-dir", DefaultStateDir, "state-verzeichnis des agenten")
	user := fs.String("user", "", "lokaler benutzername (%u aus sshd)")
	serial := fs.Int64("serial", 0, "zertifikats-serial (%s aus sshd); 0 = keiner")
	keyid := fs.String("keyid", "", "zertifikats-key-id (%i aus sshd)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if err := PrintPrincipals(ctx, *stateDir, *user, *serial, *keyid, stdout); err != nil {
		fmt.Fprintf(stderr, "gssh-agentd: %v\n", err)
		return 1
	}
	return 0
}

// runPAMSessionCmd behandelt gssh-agentd pam-session (pam_exec-Ziel). Ein Fehler
// wird nach stderr geloggt; der Aufrufer beendet sich immer mit 0 (fail-open),
// damit der Hook niemals Login oder sudo blockiert.
func runPAMSessionCmd(ctx context.Context, args []string, stderr io.Writer) {
	fs := flag.NewFlagSet("gssh-agentd pam-session", flag.ContinueOnError)
	fs.SetOutput(stderr)
	stateDir := fs.String("state-dir", DefaultStateDir, "state-verzeichnis des agenten")
	if err := fs.Parse(args); err != nil {
		return
	}
	if err := RunPAMSession(ctx, *stateDir, os.Getenv, time.Now); err != nil {
		fmt.Fprintf(stderr, "gssh-agentd: pam-session (ignoriert): %v\n", err)
	}
}

// parseTags parst "k=v,k2=v2" in eine Map (identisch zu gssh-server).
func parseTags(raw string) (map[string]string, error) {
	tags := map[string]string{}
	if raw == "" {
		return tags, nil
	}
	for _, pair := range strings.Split(raw, ",") {
		key, value, found := strings.Cut(pair, "=")
		if !found || key == "" {
			return nil, fmt.Errorf("ungültiges tag %q (erwartet key=value)", pair)
		}
		tags[key] = value
	}
	return tags, nil
}
