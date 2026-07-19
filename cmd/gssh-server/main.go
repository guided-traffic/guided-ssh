// gssh-server ist der API-Server von guided-ssh (CA, OIDC-Endpunkte, Host-API, UI).
// Phase 2: CA-Bootstrap (Migrationen, CA-Keys) und HTTP-API mit
// CA-Bundle-Endpoint; Sign-Endpoints folgen ab Phase 3.
package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/guided-traffic/guided-ssh/internal/api"
	"github.com/guided-traffic/guided-ssh/internal/ca"
	"github.com/guided-traffic/guided-ssh/internal/store"
	"github.com/guided-traffic/guided-ssh/internal/version"
)

// Umgebungsvariablen des Servers (Werte kommen im Kubernetes-Deployment
// aus Secrets, siehe Plan Phase 11).
const (
	envDSN       = "GSSH_DB_DSN"
	envMasterKey = "GSSH_CA_MASTER_KEY" // Base64, 32 Bytes (AES-256)
)

func main() {
	os.Exit(run(os.Stdout, os.Stderr, os.Args[1:]))
}

// run enthält die eigentliche Logik, damit sie testbar bleibt; main ist nur ein
// dünner Wrapper um Exit-Code-Handling.
func run(stdout, stderr io.Writer, args []string) int {
	fs := flag.NewFlagSet("gssh-server", flag.ContinueOnError)
	fs.SetOutput(stderr)
	showVersion := fs.Bool("version", false, "Version ausgeben und beenden")
	listen := fs.String("listen", "", "Listen-Adresse der HTTP-API (z. B. :8080); leer = nicht starten")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *showVersion {
		fmt.Fprintln(stdout, version.String())
		return 0
	}

	if *listen == "" {
		fmt.Fprintln(stderr, "gssh-server: -listen fehlt (z. B. -listen :8080)")
		return 2
	}

	logger := slog.New(slog.NewJSONHandler(stdout, nil))
	if err := serve(logger, *listen); err != nil {
		logger.Error("serverstart fehlgeschlagen", "error", err)
		return 1
	}
	return 0
}

// serve startet die HTTP-API und blockiert bis SIGINT/SIGTERM.
func serve(logger *slog.Logger, listen string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	certAuthority, st, err := setup(ctx)
	if err != nil {
		return err
	}
	defer st.Close()

	server := &http.Server{
		Addr:              listen,
		Handler:           api.New(certAuthority, logger),
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() { errCh <- server.ListenAndServe() }()
	logger.Info("gssh-server gestartet", "listen", listen, "version", version.String())

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	}
}

// setup liest die Einstellungen aus der Umgebung, migriert die Datenbank und
// bootstrapt die CA (inkl. CA-Keys, falls noch keine existieren).
func setup(ctx context.Context) (*ca.CA, *store.Store, error) {
	dsn := os.Getenv(envDSN)
	if dsn == "" {
		return nil, nil, fmt.Errorf("%s nicht gesetzt", envDSN)
	}
	masterKey, err := base64.StdEncoding.DecodeString(os.Getenv(envMasterKey))
	if err != nil {
		return nil, nil, fmt.Errorf("%s dekodieren: %w", envMasterKey, err)
	}

	if err := store.Migrate(ctx, dsn); err != nil {
		return nil, nil, fmt.Errorf("migrationen: %w", err)
	}
	st, err := store.New(ctx, dsn)
	if err != nil {
		return nil, nil, err
	}
	certAuthority, err := ca.New(st, masterKey, ca.NewPolicyEngine(ca.DefaultPolicies()))
	if err != nil {
		st.Close()
		return nil, nil, err
	}
	if err := certAuthority.EnsureCAKeys(ctx); err != nil {
		st.Close()
		return nil, nil, fmt.Errorf("ca-keys bootstrappen: %w", err)
	}
	return certAuthority, st, nil
}
