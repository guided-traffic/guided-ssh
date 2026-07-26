package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/guided-traffic/guided-ssh/internal/pintls"
	"github.com/guided-traffic/guided-ssh/internal/version"
)

// Run executes the CLI and returns the exit code: 0 ok, 1 error, 2 usage
// error; for status, 1 means "no valid certificate" (scriptable).
func Run(stdout, stderr io.Writer, args []string) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	command, rest := args[0], args[1:]
	switch command {
	case "login":
		return runLoginCmd(ctx, rest, stdout, stderr)
	case "ci-login":
		return runCILoginCmd(ctx, rest, stdout, stderr)
	case "ssh":
		return runSSHCmd(ctx, rest, stdout, stderr)
	case "status":
		return runStatusCmd(rest, stdout, stderr)
	case "logout":
		return runLogoutCmd(stdout, stderr)
	case "integrate":
		return runIntegrateCmd(rest, stdout, stderr)
	case "version":
		fmt.Fprintln(stdout, version.String())
		return 0
	case "help", "-h", "--help":
		usage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "gssh: unknown command %q\n\n", command)
		usage(stderr)
		return 2
	}
}

// usage prints the command overview.
func usage(w io.Writer) {
	fmt.Fprint(w, `gssh — certificate-based ssh access (guided-ssh)

commands:
  login [--device] [--validity 8h] [--if-needed] [--config path]
        [--api-url url] [--pin-sha256 pin]
        sign in via sso; key pair and certificate go only into the ssh-agent.
        --api-url/--pin-sha256 override the configuration for this run only
        (the file is never modified) — the dns fallback: with an ip api url,
        webpki cannot verify the hostname, so --pin-sha256 is required; the
        pin then replaces chain and hostname verification
  ci-login [--api-url url] [--token-env GSSH_CI_TOKEN] [--validity 1h] [--pin-sha256 pin]
        gitlab ci: exchange the job token (id_tokens) for a ci certificate and
        load it into the job's ssh-agent; api-url also via GSSH_API_URL
  ssh <ssh-arguments…>
        like ssh, but first ensures a valid certificate (auto-login);
        config path optionally via GSSH_CONFIG
  status [--config path]
        show configuration and certificate status; exit code 1 without a valid certificate
  logout
        remove guided-ssh entries from the ssh-agent
  integrate [--hosts pattern]
        print an ssh_config snippet for transparent native ssh
  version
        print the version
`)
}

// loadConfigCmd loads the configuration for a command; if the file is
// missing, it also prints a hint with example content.
func loadConfigCmd(flagValue string, stderr io.Writer) (*Config, bool) {
	path := ResolveConfigPath(flagValue)
	if path == "" {
		fmt.Fprintln(stderr, "gssh: could not determine a configuration path (HOME not set?)")
		return nil, false
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		fmt.Fprintf(stderr, "gssh: %v\n", err)
		if errors.Is(err, os.ErrNotExist) {
			fmt.Fprint(stderr, configHint(path))
		}
		return nil, false
	}
	return cfg, true
}

// runLoginCmd handles gssh login.
func runLoginCmd(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gssh login", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "path to the configuration file")
	device := fs.Bool("device", false, "device flow instead of browser (headless)")
	validity := fs.Duration("validity", 0, "desired validity (0 = default)")
	ifNeeded := fs.Bool("if-needed", false, "only sign in if no valid certificate is in the agent")
	apiURL := fs.String("api-url", "", "override the configured api url for this run (e.g. https://<ip> as a dns fallback)")
	pin := fs.String("pin-sha256", "", "spki-sha-256 pin of the server certificate; required with an ip api url")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	// Fail fast on a mangled copy-paste: before the config file is touched
	// and long before the first network call of the OIDC flow.
	if *pin != "" {
		if _, err := pintls.DecodePin(*pin); err != nil {
			fmt.Fprintf(stderr, "gssh: --pin-sha256: %v\n", err)
			return 1
		}
	}
	cfg, ok := loadConfigCmd(*configPath, stderr)
	if !ok {
		return 1
	}
	// Ephemeral overrides: only this run's in-memory copy, the file stays as
	// it is (a one-off flag must never silently repoint an installed client).
	if *apiURL != "" {
		cfg.APIURL = *apiURL
	}
	if *pin != "" {
		cfg.PinSHA256 = *pin
	}
	opts := loginOptions{device: *device, validity: *validity, ifNeeded: *ifNeeded}
	if err := login(ctx, cfg, opts, stdout, stderr); err != nil {
		fmt.Fprintf(stderr, "gssh: login failed: %v\n", err)
		if *apiURL != "" && *pin == "" {
			fmt.Fprintln(stderr, "hint: an --api-url without a matching dns name needs --pin-sha256 <pin> (webpki cannot verify an ip)")
		}
		return 1
	}
	return 0
}

// runSSHCmd handles gssh ssh. Deliberately no FlagSet: all arguments go
// unchanged to native ssh; the config path comes from GSSH_CONFIG or the
// default path.
func runSSHCmd(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	cfg, ok := loadConfigCmd("", stderr)
	if !ok {
		return 1
	}
	if err := runSSH(ctx, cfg, args, stdout, stderr); err != nil {
		fmt.Fprintf(stderr, "gssh: %v\n", err)
		return 1
	}
	return 0
}

// runStatusCmd handles gssh status: configuration is optional (best
// effort), the agent state decides the exit code.
func runStatusCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gssh status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "path to the configuration file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	path := ResolveConfigPath(*configPath)
	if cfg, err := LoadConfig(path); err == nil {
		fmt.Fprintf(stdout, "configuration: %s (api %s, issuer %s)\n", path, cfg.APIURL, cfg.Issuer)
	} else {
		fmt.Fprintf(stdout, "configuration: %s (error: %v)\n", path, err)
	}

	ag, conn, err := connectAgent()
	if err != nil {
		fmt.Fprintf(stderr, "gssh: %v\n", err)
		return 1
	}
	defer conn.Close()
	certs, err := gsshCerts(ag)
	if err != nil {
		fmt.Fprintf(stderr, "gssh: %v\n", err)
		return 1
	}
	if len(certs) == 0 {
		fmt.Fprintln(stdout, "no guided-ssh certificate in the agent — sign in with: gssh login")
		return 1
	}
	valid := false
	for _, cert := range certs {
		state := "expired"
		if certValid(cert, 0) {
			state = fmt.Sprintf("valid until %s (%s remaining)",
				certTime(cert.ValidBefore).Format(time.RFC3339),
				time.Until(certTime(cert.ValidBefore)).Round(time.Minute))
			valid = true
		}
		fmt.Fprintf(stdout, "certificate %s — principals %s — %s\n",
			cert.KeyId, strings.Join(cert.ValidPrincipals, ", "), state)
	}
	if !valid {
		return 1
	}
	return 0
}

// runLogoutCmd handles gssh logout.
func runLogoutCmd(stdout, stderr io.Writer) int {
	ag, conn, err := connectAgent()
	if err != nil {
		fmt.Fprintf(stderr, "gssh: %v\n", err)
		return 1
	}
	defer conn.Close()
	removed, err := removeGsshKeys(ag)
	if err != nil {
		fmt.Fprintf(stderr, "gssh: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "signed out (%d agent entries removed)\n", removed)
	return 0
}

// runIntegrateCmd prints the ssh_config snippet for transparent integration:
// Match exec triggers the auto-login, native ssh remains the transport.
func runIntegrateCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gssh integrate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	hosts := fs.String("hosts", "*", "host pattern the auto-login should apply to")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	fmt.Fprintf(stdout, `# guided-ssh: auto-login on missing certificate (append to ~/.ssh/config)
# note: ssh suppresses the output of the match-exec command; the browser
# flow still works. for headless use beforehand: gssh login --device
Match host "%s" exec "gssh login --if-needed"
`, *hosts)
	return 0
}
