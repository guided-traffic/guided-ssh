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

// Umgebungsvariablen für gssh ci-login (Phase 7): in CI-Jobs gibt es keine
// Konfigurationsdatei, alles kommt aus Flags bzw. Environment.
const (
	// envCIToken ist der Default-Name der Variable mit dem GitLab-Job-Token
	// (id_tokens-Feature; --token-env übersteuert den Namen).
	envCIToken = "GSSH_CI_TOKEN" //nolint:gosec // Name der Env-Variable, kein Secret
	// envAPIURL ist die Basis-URL des gssh-servers.
	envAPIURL = "GSSH_API_URL"
	// envPin ist der optionale SPKI-SHA-256-Pin des Server-Zertifikats.
	envPin = "GSSH_PIN_SHA256"
)

// ciLoginOptions steuern gssh ci-login.
type ciLoginOptions struct {
	apiURL   string
	tokenEnv string
	pin      string
	validity time.Duration
}

// runCILoginCmd behandelt gssh ci-login.
func runCILoginCmd(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gssh ci-login", flag.ContinueOnError)
	fs.SetOutput(stderr)
	apiURL := fs.String("api-url", os.Getenv(envAPIURL), "basis-url des gssh-servers (oder GSSH_API_URL)")
	tokenEnv := fs.String("token-env", envCIToken, "name der env-variable mit dem gitlab-job-token")
	pin := fs.String("pin-sha256", os.Getenv(envPin), "spki-sha-256-pin des server-zertifikats (oder GSSH_PIN_SHA256)")
	validity := fs.Duration("validity", 0, "gewünschte laufzeit (0 = server-default, max. 1h)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	opts := ciLoginOptions{apiURL: *apiURL, tokenEnv: *tokenEnv, pin: *pin, validity: *validity}
	if err := ciLogin(ctx, opts, stdout); err != nil {
		fmt.Fprintf(stderr, "gssh: ci-login fehlgeschlagen: %v\n", err)
		return 1
	}
	return 0
}

// ciLogin tauscht das GitLab-Job-Token gegen ein kurzlebiges CI-Zertifikat
// und lädt Schlüsselpaar und Zertifikat ausschließlich in den ssh-agent des
// Jobs (wie gssh login, nur ohne Browser-Flow und Konfigurationsdatei).
func ciLogin(ctx context.Context, opts ciLoginOptions, stdout io.Writer) error {
	if opts.apiURL == "" {
		return fmt.Errorf("--api-url fehlt (oder %s setzen)", envAPIURL)
	}
	token := os.Getenv(opts.tokenEnv)
	if token == "" {
		return fmt.Errorf("job-token fehlt: env-variable %s ist leer — id_tokens im job definieren (aud: guided-ssh)", opts.tokenEnv)
	}

	ag, conn, err := connectAgent()
	if err != nil {
		return errors.Join(err, errors.New("im job vorher starten: eval $(ssh-agent -s)"))
	}
	defer conn.Close()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("schlüsselpaar erzeugen: %w", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return fmt.Errorf("public key konvertieren: %w", err)
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
	fmt.Fprintf(stdout, "ci-login: %s — principals %s, gültig bis %s\n",
		cert.KeyId, strings.Join(cert.ValidPrincipals, ", "),
		certTime(cert.ValidBefore).Format(time.RFC3339))
	return nil
}
