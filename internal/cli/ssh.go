package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
)

// execSSH replaces the gssh process with native ssh (overridden in tests).
var execSSH = func(argv []string) error {
	path, err := exec.LookPath("ssh")
	if err != nil {
		return fmt.Errorf("ssh not found: %w", err)
	}
	return syscall.Exec(path, append([]string{"ssh"}, argv...), os.Environ())
}

// runSSH ensures a valid certificate via auto-login and then passes all
// arguments unchanged to native ssh (the certificate comes from the
// ssh-agent).
func runSSH(ctx context.Context, cfg *Config, argv []string, stdout, stderr io.Writer) error {
	if len(argv) == 0 {
		return errors.New("usage: gssh ssh <ssh-arguments…>")
	}
	if err := login(ctx, cfg, loginOptions{ifNeeded: true}, stdout, stderr); err != nil {
		return err
	}
	return execSSH(argv)
}
