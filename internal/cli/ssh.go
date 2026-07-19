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

// execSSH ersetzt den gssh-Prozess durch natives ssh (in Tests überschrieben).
var execSSH = func(argv []string) error {
	path, err := exec.LookPath("ssh")
	if err != nil {
		return fmt.Errorf("ssh nicht gefunden: %w", err)
	}
	return syscall.Exec(path, append([]string{"ssh"}, argv...), os.Environ())
}

// runSSH stellt per Auto-Login ein gültiges Zertifikat sicher und übergibt
// dann alle Argumente unverändert an natives ssh (das Zertifikat kommt aus
// dem ssh-agent).
func runSSH(ctx context.Context, cfg *Config, argv []string, stdout, stderr io.Writer) error {
	if len(argv) == 0 {
		return errors.New("aufruf: gssh ssh <ssh-argumente…>")
	}
	if err := login(ctx, cfg, loginOptions{ifNeeded: true}, stdout, stderr); err != nil {
		return err
	}
	return execSSH(argv)
}
