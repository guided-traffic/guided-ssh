// gssh is the user CLI of guided-ssh (Phase 4): SSO login, short-lived
// certificates kept exclusively in the ssh-agent, transparent ssh integration.
package main

import (
	"os"

	"github.com/guided-traffic/guided-ssh/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Stdout, os.Stderr, os.Args[1:]))
}
