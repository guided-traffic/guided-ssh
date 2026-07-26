package cli

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Environment variables for gssh ci-login (phase 7): CI jobs have no
// configuration file, everything comes from flags or environment.
const (
	// envCIToken is the default name of the variable holding the GitLab job
	// token (id_tokens feature; --token-env overrides the name).
	envCIToken = "GSSH_CI_TOKEN" //nolint:gosec // name of the env variable, not a secret
	// envAPIURL is the base URL of the gssh server.
	envAPIURL = "GSSH_API_URL"
	// envPin is the optional SPKI SHA-256 pin of the server certificate.
	envPin = "GSSH_PIN_SHA256"
)

// ciLoginOptions control gssh ci-login.
type ciLoginOptions struct {
	apiURL   string
	tokenEnv string
	pin      string
	validity time.Duration
}

// runCILoginCmd handles gssh ci-login.
func runCILoginCmd(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gssh ci-login", flag.ContinueOnError)
	fs.SetOutput(stderr)
	apiURL := fs.String("api-url", os.Getenv(envAPIURL), "base URL of the gssh server (or GSSH_API_URL)")
	tokenEnv := fs.String("token-env", envCIToken, "name of the env variable holding the gitlab job token")
	pin := fs.String("pin-sha256", os.Getenv(envPin), "spki-sha-256 pin of the server certificate (or GSSH_PIN_SHA256)")
	validity := fs.Duration("validity", 0, "desired validity (0 = server default, max. 1h)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	opts := ciLoginOptions{apiURL: *apiURL, tokenEnv: *tokenEnv, pin: *pin, validity: *validity}
	if err := ciLogin(ctx, opts, stdout); err != nil {
		fmt.Fprintf(stderr, "gssh: ci-login failed: %v\n", err)
		return 1
	}
	return 0
}

// ciLogin exchanges the GitLab job token for a short-lived CI certificate
// and loads the key pair and certificate exclusively into the job's
// ssh-agent (like gssh login, but without the browser flow or config file).
func ciLogin(ctx context.Context, opts ciLoginOptions, stdout io.Writer) error {
	if opts.apiURL == "" {
		return fmt.Errorf("--api-url missing (or set %s)", envAPIURL)
	}
	token := os.Getenv(opts.tokenEnv)
	if token == "" {
		return fmt.Errorf("job token missing: env variable %s is empty — define id_tokens in the job (aud: guided-ssh)", opts.tokenEnv)
	}

	ag, conn, err := connectAgent()
	if err != nil {
		return errors.Join(err, errors.New("start it in the job first: eval $(ssh-agent -s)"))
	}
	defer conn.Close()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generating key pair: %w", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return fmt.Errorf("converting public key: %w", err)
	}

	client, err := newAPIClient(&Config{APIURL: opts.apiURL, PinSHA256: opts.pin})
	if err != nil {
		return err
	}
	cert, err := client.signCI(ctx, token, string(ssh.MarshalAuthorizedKey(sshPub)), opts.validity)
	if err != nil {
		return err
	}
	if err := loadIntoAgent(ag, priv, cert); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "ci-login: %s — principals %s, valid until %s\n",
		cert.KeyId, strings.Join(cert.ValidPrincipals, ", "),
		certTime(cert.ValidBefore).Format(time.RFC3339))
	return nil
}
