package cli

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/guided-traffic/guided-ssh/internal/auth"
)

// openBrowser opens a URL in the default browser (overridden in tests).
var openBrowser = func(url string) error {
	command := "xdg-open"
	if runtime.GOOS == "darwin" {
		command = "open"
	}
	return exec.Command(command, url).Start() //nolint:gosec // url comes from our own OIDC flow
}

// loginOptions control gssh login.
type loginOptions struct {
	// device forces the device flow (headless, no browser/callback).
	device bool
	// validity overrides the desired lifetime (0 = config/server default).
	validity time.Duration
	// ifNeeded skips the login as long as a valid certificate is in the
	// agent (auto-login for gssh ssh and the Match-exec integration).
	ifNeeded bool
}

// login generates an ephemeral Ed25519 key pair, obtains an ID token via
// the OIDC flow, exchanges it at the sign endpoint for a certificate, and
// loads both exclusively into the ssh-agent.
func login(ctx context.Context, cfg *Config, opts loginOptions, stdout, stderr io.Writer) error {
	ag, conn, err := connectAgent()
	if err != nil {
		return err
	}
	defer conn.Close()

	if opts.ifNeeded {
		certs, err := gsshCerts(ag)
		if err != nil {
			return err
		}
		if anyValidCert(certs, renewMargin) {
			return nil
		}
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generating key pair: %w", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return fmt.Errorf("converting public key: %w", err)
	}

	idToken, err := FetchIDToken(ctx, cfg, opts.device, stderr)
	if err != nil {
		return err
	}

	client, err := newAPIClient(cfg)
	if err != nil {
		return err
	}
	validity := opts.validity
	if validity == 0 {
		validity = time.Duration(cfg.Validity)
	}
	cert, err := client.signUser(ctx, idToken, string(ssh.MarshalAuthorizedKey(sshPub)), validity)
	if err != nil {
		return err
	}
	if err := loadIntoAgent(ag, priv, cert); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "signed in: %s — principals %s, valid until %s\n",
		cert.KeyId, strings.Join(cert.ValidPrincipals, ", "),
		certTime(cert.ValidBefore).Format(time.RFC3339))
	return nil
}

// FetchIDToken runs the OIDC flow: authorization code + PKCE with a
// browser (default) or the device flow (--device); also used by gssh-admin.
func FetchIDToken(ctx context.Context, cfg *Config, device bool, stderr io.Writer) (string, error) {
	flow, err := auth.NewFlow(ctx, auth.FlowConfig{
		IssuerURL: cfg.Issuer,
		ClientID:  cfg.ClientID,
		Scopes:    cfg.Scopes,
	})
	if err != nil {
		return "", err
	}
	if device {
		return flow.DeviceFlow(ctx, func(uri, code string) {
			fmt.Fprintf(stderr, "open in browser: %s\nenter code: %s\n", uri, code)
		})
	}
	return flow.AuthCodePKCE(ctx, func(url string) error {
		fmt.Fprintf(stderr, "opening browser — if it doesn't open, visit this url manually:\n%s\n", url)
		if err := openBrowser(url); err != nil {
			// Not fatal: the URL is shown in the terminal.
			fmt.Fprintf(stderr, "opening browser failed: %v\n", err)
		}
		return nil
	})
}

// FetchServiceToken obtains an ID token non-interactively via the
// client-credentials flow (service account, e.g. gssh-admin's GitOps grants
// sync). Empty clientID = the configuration's client_id; the IdP client
// needs the openid scope so the token response includes an id_token.
func FetchServiceToken(ctx context.Context, cfg *Config, clientID, clientSecret string) (string, error) {
	if clientID == "" {
		clientID = cfg.ClientID
	}
	flow, err := auth.NewFlow(ctx, auth.FlowConfig{
		IssuerURL: cfg.Issuer,
		ClientID:  clientID,
		Scopes:    []string{"openid"},
	})
	if err != nil {
		return "", err
	}
	return flow.ClientCredentials(ctx, clientSecret)
}
