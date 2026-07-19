// gssh-admin ist das Admin-CLI von guided-ssh (Phase 6): Zugriffsregeln
// (Grants) verwalten — CRUD und deklarativer YAML-Abgleich über die Admin-API.
package main

import (
	"os"

	"github.com/guided-traffic/guided-ssh/internal/admincli"
)

func main() {
	os.Exit(admincli.Run(os.Stdout, os.Stderr, os.Args[1:]))
}
