// gssh-server ist der API-Server von guided-ssh (CA, OIDC-Endpunkte, Host-API, UI).
// Phase 0: Platzhalter, damit Build, Tests, Coverage-Gate und Container-Image
// von Anfang an real laufen. Serverfunktionalität folgt ab Phase 2.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/guided-traffic/guided-ssh/internal/version"
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
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *showVersion {
		fmt.Fprintln(stdout, version.String())
		return 0
	}

	fmt.Fprintln(stderr, "gssh-server: noch nicht implementiert (folgt ab Phase 2, siehe local_PLAN.md)")
	return 1
}
