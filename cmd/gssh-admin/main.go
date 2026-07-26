// gssh-admin is the admin CLI of guided-ssh (Phase 6): manages access rules
// (grants) — CRUD and declarative YAML reconciliation via the admin API.
package main

import (
	"os"

	"github.com/guided-traffic/guided-ssh/internal/admincli"
)

func main() {
	os.Exit(admincli.Run(os.Stdout, os.Stderr, os.Args[1:]))
}
