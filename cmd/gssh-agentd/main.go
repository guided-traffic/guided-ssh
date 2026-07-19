// gssh-agentd ist der Host-Agent von guided-ssh (Phase 5): Enrollment,
// automatische Host-Zertifikatserneuerung, TrustedUserCAKeys-Pflege und
// AuthorizedPrincipalsCommand-Helper (fail-closed).
package main

import (
	"os"

	"github.com/guided-traffic/guided-ssh/internal/agentd"
)

func main() {
	os.Exit(agentd.Run(os.Stdout, os.Stderr, os.Args[1:]))
}
