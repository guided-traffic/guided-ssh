// gssh-agentd is the host agent of guided-ssh (Phase 5): enrollment,
// automatic host certificate renewal, TrustedUserCAKeys maintenance, and
// the AuthorizedPrincipalsCommand helper (fail-closed).
package main

import (
	"os"

	"github.com/guided-traffic/guided-ssh/internal/agentd"
)

func main() {
	os.Exit(agentd.Run(os.Stdout, os.Stderr, os.Args[1:]))
}
