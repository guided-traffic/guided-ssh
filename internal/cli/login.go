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

// openBrowser öffnet eine URL im Standard-Browser (in Tests überschrieben).
var openBrowser = func(url string) error {
	command := "xdg-open"
	if runtime.GOOS == "darwin" {
		command = "open"
	}
	return exec.Command(command, url).Start() //nolint:gosec // url kommt vom eigenen OIDC-Flow
}

// loginOptions steuern gssh login.
type loginOptions struct {
	// device erzwingt den Device-Flow (headless, ohne Browser/Callback).
	device bool
	// validity übersteuert die gewünschte Laufzeit (0 = Config/Server-Default).
	validity time.Duration
	// ifNeeded überspringt den Login, solange ein gültiges Zertifikat im
	// Agenten liegt (Auto-Login für gssh ssh und Match-exec-Integration).
	ifNeeded bool
}

// login erzeugt ein ephemerales Ed25519-Schlüsselpaar, holt per OIDC-Flow ein
// ID-Token, tauscht es am Sign-Endpoint gegen ein Zertifikat und lädt beides
// ausschließlich in den ssh-agent.
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
		return fmt.Errorf("schlüsselpaar erzeugen: %w", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return fmt.Errorf("public key konvertieren: %w", err)
	}

	idToken, err := fetchIDToken(ctx, cfg, opts.device, stderr)
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
	fmt.Fprintf(stdout, "angemeldet: %s — principals %s, gültig bis %s\n",
		cert.KeyId, strings.Join(cert.ValidPrincipals, ", "),
		certTime(cert.ValidBefore).Format(time.RFC3339))
	return nil
}

// fetchIDToken führt den OIDC-Flow aus: Authorization Code + PKCE mit
// Browser (Default) oder Device-Flow (--device).
func fetchIDToken(ctx context.Context, cfg *Config, device bool, stderr io.Writer) (string, error) {
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
			fmt.Fprintf(stderr, "im browser öffnen: %s\ncode eingeben: %s\n", uri, code)
		})
	}
	return flow.AuthCodePKCE(ctx, func(url string) error {
		fmt.Fprintf(stderr, "browser wird geöffnet — falls nicht, url manuell öffnen:\n%s\n", url)
		if err := openBrowser(url); err != nil {
			// Nicht fatal: die URL steht im Terminal.
			fmt.Fprintf(stderr, "browser öffnen fehlgeschlagen: %v\n", err)
		}
		return nil
	})
}
