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

// Run executes the agent CLI and returns the exit code (0 ok, 1 error,
// 2 usage error).
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
		return 0 // fail-open: pam_exec must never block
	case "version":
		fmt.Fprintln(stdout, version.String())
		return 0
	case "help", "-h", "--help":
		usage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "gssh-agentd: unknown command %q\n\n", command)
		usage(stderr)
		return 2
	}
}

// usage prints the command overview.
func usage(w io.Writer) {
	fmt.Fprint(w, `gssh-agentd — host agent of guided-ssh

commands:
  enroll --server url --agent-url url --token t [--hostname n] [--tags k=v,…]
         [--pin b64] [--require-pin] [--state-dir d] [--ssh-dir d] [--ssh-key path]
         [--session-audit]
         register the host: fetch certificates, write sshd configuration;
         --session-audit additionally enables session/sudo audit (pam_exec);
         --require-pin aborts without --pin (protects against operator mistakes)
  run [--state-dir d]
         daemon: renew certificate (at 2/3 of its validity), maintain ca bundle,
         serve principals cache + unix socket for sshd
  principals -user <name> [-serial N] [-keyid ID] [-state-dir d]
         AuthorizedPrincipalsCommand helper (fail-closed); serial/keyid (sshd
         tokens) only with session audit enabled (correlates session ↔ certificate)
  pam-session [-state-dir d]
         pam_exec target (session open/close in sshd/sudo); reports session/sudo
         events to the daemon, always exits 0 (fail-open)
  version
         print version
`)
}

// envRequirePin is the env equivalent of --require-pin.
const envRequirePin = "GSSH_ENROLL_REQUIRE_PIN"

// requirePinFromEnv reads GSSH_ENROLL_REQUIRE_PIN as the default for
// --require-pin. Any value other than "0"/"false" enables the check: a
// variable that is set but written unexpectedly should not silently have no
// effect (fail-closed).
func requirePinFromEnv() bool {
	switch strings.ToLower(os.Getenv(envRequirePin)) {
	case "", "0", "false":
		return false
	default:
		return true
	}
}

// runEnrollCmd handles gssh-agentd enroll.
func runEnrollCmd(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gssh-agentd enroll", flag.ContinueOnError)
	fs.SetOutput(stderr)
	server := fs.String("server", "", "public api of the gssh server (POST /v1/enroll)")
	agentURL := fs.String("agent-url", "", "mtls agent api of the gssh server")
	token := fs.String("token", "", "one-time enrollment token")
	hostname := fs.String("hostname", "", "hostname (default: os.Hostname)")
	tagsFlag := fs.String("tags", "", "host tags, e.g. env=prod,role=web")
	pin := fs.String("pin", "", "spki sha-256 pin of the enroll endpoint (base64)")
	// --require-pin protects against operator mistakes, not MITM: it prevents
	// someone from copying the enroll line out of the served install.sh,
	// dropping --pin, and enrolling unpinned without noticing. Anyone able to
	// tamper with the piped script can also strip this flag — the HTTPS
	// fetch and the server-side pin sources guard against that, not this flag.
	// The templated install.sh always sets it; the manual and the deb/rpm
	// path stay unchanged (default off).
	requirePin := fs.Bool("require-pin", requirePinFromEnv(), "abort without --pin (protects against operator mistakes, not mitm)")
	stateDir := fs.String("state-dir", DefaultStateDir, "state directory of the agent")
	sshDir := fs.String("ssh-dir", DefaultSSHDir, "sshd configuration directory")
	sshKey := fs.String("ssh-key", "", "ssh host public key (default: <ssh-dir>/ssh_host_ed25519_key.pub)")
	sessionAudit := fs.Bool("session-audit", false, "enable host session/sudo audit (pam_exec hooks, opt-in)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	tags, err := parseTags(*tagsFlag)
	if err != nil {
		fmt.Fprintf(stderr, "gssh-agentd: %v\n", err)
		return 2
	}
	// Abort before any network call: the token stays unused.
	if *requirePin && *pin == "" {
		fmt.Fprintf(stderr, "gssh-agentd: --require-pin set (or %s), but --pin is missing — enrollment aborted\n", envRequirePin)
		return 2
	}
	opts := EnrollOptions{
		ServerURL: *server, AgentURL: *agentURL, Token: *token,
		Hostname: *hostname, Tags: tags, PinSHA256: *pin,
		StateDir: *stateDir, SSHDir: *sshDir, SSHKeyPath: *sshKey,
		SessionAudit: *sessionAudit,
	}
	if err := Enroll(ctx, opts, stdout); err != nil {
		fmt.Fprintf(stderr, "gssh-agentd: enrollment failed: %v\n", err)
		return 1
	}
	return 0
}

// runDaemonCmd handles gssh-agentd run.
func runDaemonCmd(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gssh-agentd run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	stateDir := fs.String("state-dir", DefaultStateDir, "state directory of the agent")
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
		logger.Error("daemon stopped", "error", err)
		return 1
	}
	return 0
}

// runPrincipalsCmd handles gssh-agentd principals (sshd helper).
func runPrincipalsCmd(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gssh-agentd principals", flag.ContinueOnError)
	fs.SetOutput(stderr)
	stateDir := fs.String("state-dir", DefaultStateDir, "state directory of the agent")
	user := fs.String("user", "", "local username (%u from sshd)")
	serial := fs.Int64("serial", 0, "certificate serial (%s from sshd); 0 = none")
	keyid := fs.String("keyid", "", "certificate key id (%i from sshd)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if err := PrintPrincipals(ctx, *stateDir, *user, *serial, *keyid, stdout); err != nil {
		fmt.Fprintf(stderr, "gssh-agentd: %v\n", err)
		return 1
	}
	return 0
}

// runPAMSessionCmd handles gssh-agentd pam-session (pam_exec target). An error
// is logged to stderr; the caller always exits 0 (fail-open) so the hook
// never blocks login or sudo.
func runPAMSessionCmd(ctx context.Context, args []string, stderr io.Writer) {
	fs := flag.NewFlagSet("gssh-agentd pam-session", flag.ContinueOnError)
	fs.SetOutput(stderr)
	stateDir := fs.String("state-dir", DefaultStateDir, "state directory of the agent")
	if err := fs.Parse(args); err != nil {
		return
	}
	if err := RunPAMSession(ctx, *stateDir, os.Getenv, time.Now); err != nil {
		fmt.Fprintf(stderr, "gssh-agentd: pam-session (ignored): %v\n", err)
	}
}

// parseTags parses "k=v,k2=v2" into a map (identical to gssh-server).
func parseTags(raw string) (map[string]string, error) {
	tags := map[string]string{}
	if raw == "" {
		return tags, nil
	}
	for _, pair := range strings.Split(raw, ",") {
		key, value, found := strings.Cut(pair, "=")
		if !found || key == "" {
			return nil, fmt.Errorf("invalid tag %q (expected key=value)", pair)
		}
		tags[key] = value
	}
	return tags, nil
}
