// gssh ist das Benutzer-CLI von guided-ssh (Phase 4): SSO-Login, kurzlebige
// Zertifikate ausschließlich im ssh-agent, transparente ssh-Integration.
package main

import (
	"os"

	"github.com/guided-traffic/guided-ssh/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Stdout, os.Stderr, os.Args[1:]))
}
