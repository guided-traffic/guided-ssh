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

	"github.com/guided-traffic/guided-ssh/internal/version"
)

// Run führt das CLI aus und liefert den Exit-Code: 0 ok, 1 Fehler, 2
// Aufruffehler; bei status bedeutet 1 „kein gültiges Zertifikat" (skriptbar).
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
		fmt.Fprintf(stderr, "gssh: unbekanntes kommando %q\n\n", command)
		usage(stderr)
		return 2
	}
}

// usage gibt die Kommandoübersicht aus.
func usage(w io.Writer) {
	fmt.Fprint(w, `gssh — zertifikatsbasierter ssh-zugriff (guided-ssh)

kommandos:
  login [--device] [--validity 8h] [--if-needed] [--config pfad]
        per sso anmelden; schlüsselpaar und zertifikat landen nur im ssh-agent
  ssh <ssh-argumente…>
        wie ssh, stellt vorher ein gültiges zertifikat sicher (auto-login);
        konfigurationspfad ggf. über GSSH_CONFIG
  status [--config pfad]
        konfiguration und zertifikatsstatus; exit-code 1 ohne gültiges zertifikat
  logout
        guided-ssh-einträge aus dem ssh-agent entfernen
  integrate [--hosts muster]
        ssh_config-schnipsel für transparentes natives ssh ausgeben
  version
        version ausgeben
`)
}

// loadConfigCmd lädt die Konfiguration für ein Kommando; bei fehlender Datei
// gibt es zusätzlich einen Hinweis mit Beispielinhalt.
func loadConfigCmd(flagValue string, stderr io.Writer) (*Config, bool) {
	path := resolveConfigPath(flagValue)
	if path == "" {
		fmt.Fprintln(stderr, "gssh: kein konfigurationspfad ermittelbar (HOME nicht gesetzt?)")
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

// runLoginCmd behandelt gssh login.
func runLoginCmd(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gssh login", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "pfad zur konfigurationsdatei")
	device := fs.Bool("device", false, "device-flow statt browser (headless)")
	validity := fs.Duration("validity", 0, "gewünschte laufzeit (0 = default)")
	ifNeeded := fs.Bool("if-needed", false, "nur anmelden, wenn kein gültiges zertifikat im agenten liegt")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, ok := loadConfigCmd(*configPath, stderr)
	if !ok {
		return 1
	}
	opts := loginOptions{device: *device, validity: *validity, ifNeeded: *ifNeeded}
	if err := login(ctx, cfg, opts, stdout, stderr); err != nil {
		fmt.Fprintf(stderr, "gssh: login fehlgeschlagen: %v\n", err)
		return 1
	}
	return 0
}

// runSSHCmd behandelt gssh ssh. Bewusst kein FlagSet: alle Argumente gehen
// unverändert an natives ssh; der Konfigurationspfad kommt aus GSSH_CONFIG
// bzw. dem Standardpfad.
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

// runStatusCmd behandelt gssh status: Konfiguration ist optional (bester
// Aufwand), der Agent-Zustand entscheidet über den Exit-Code.
func runStatusCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gssh status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "pfad zur konfigurationsdatei")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	path := resolveConfigPath(*configPath)
	if cfg, err := LoadConfig(path); err == nil {
		fmt.Fprintf(stdout, "konfiguration: %s (api %s, issuer %s)\n", path, cfg.APIURL, cfg.Issuer)
	} else {
		fmt.Fprintf(stdout, "konfiguration: %s (fehler: %v)\n", path, err)
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
		fmt.Fprintln(stdout, "kein guided-ssh-zertifikat im agenten — anmelden mit: gssh login")
		return 1
	}
	valid := false
	for _, cert := range certs {
		state := "abgelaufen"
		if certValid(cert, 0) {
			state = fmt.Sprintf("gültig bis %s (noch %s)",
				certTime(cert.ValidBefore).Format(time.RFC3339),
				time.Until(certTime(cert.ValidBefore)).Round(time.Minute))
			valid = true
		}
		fmt.Fprintf(stdout, "zertifikat %s — principals %s — %s\n",
			cert.KeyId, strings.Join(cert.ValidPrincipals, ", "), state)
	}
	if !valid {
		return 1
	}
	return 0
}

// runLogoutCmd behandelt gssh logout.
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
	fmt.Fprintf(stdout, "abgemeldet (%d agent-einträge entfernt)\n", removed)
	return 0
}

// runIntegrateCmd gibt den ssh_config-Schnipsel für transparente Integration
// aus: Match exec triggert den Auto-Login, natives ssh bleibt der Transport.
func runIntegrateCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gssh integrate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	hosts := fs.String("hosts", "*", "host-muster, für das der auto-login greifen soll")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	fmt.Fprintf(stdout, `# guided-ssh: auto-login bei fehlendem zertifikat (an ~/.ssh/config anhängen)
# hinweis: ssh unterdrückt die ausgaben des match-exec-kommandos; der
# browser-flow funktioniert trotzdem. headless vorher: gssh login --device
Match host "%s" exec "gssh login --if-needed"
`, *hosts)
	return 0
}
