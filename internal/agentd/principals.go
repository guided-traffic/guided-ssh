package agentd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// PrintPrincipals ist der AuthorizedPrincipalsCommand-Helper: fragt den
// Daemon über den Unix-Socket und schreibt Principals zeilenweise nach
// stdout. Jeder Fehler (Daemon down, Timeout, API+Cache leer) führt zu
// einem Fehler — sshd wertet fehlende Ausgabe als Ablehnung (fail-closed).
func PrintPrincipals(ctx context.Context, stateDir, user string, stdout io.Writer) error {
	if user == "" {
		return fmt.Errorf("aufruf: gssh-agentd principals -user <name>")
	}
	cfg, err := LoadConfig(stateDir)
	if err != nil {
		return err
	}
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: func(dialCtx context.Context, _, _ string) (net.Conn, error) {
				var dialer net.Dialer
				return dialer.DialContext(dialCtx, "unix", cfg.SocketPath)
			},
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://agentd/principals?user="+url.QueryEscape(user), nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("gssh-agentd nicht erreichbar (läuft der dienst?): %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("principals verweigert: %s", string(msg))
	}
	var payload struct {
		Principals []string `json:"principals"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return err
	}
	for _, principal := range payload.Principals {
		fmt.Fprintln(stdout, principal)
	}
	return nil
}
