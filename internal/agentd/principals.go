package agentd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// PrintPrincipals is the AuthorizedPrincipalsCommand helper: it asks the
// daemon over the unix socket and writes the principals to stdout, one per
// line. Any error (daemon down, timeout, empty API+cache) results in an
// error — sshd treats missing output as a denial (fail-closed).
//
// serial/keyid come from the sshd tokens %s/%i (only set with session audit
// enabled): after printing the principals, they are reported to the daemon
// on a best-effort basis so it can correlate a following session open.
// Errors there are irrelevant — the (fail-closed) login outcome is already
// decided.
func PrintPrincipals(ctx context.Context, stateDir, user string, serial int64, keyid string, stdout io.Writer) error {
	if user == "" {
		return fmt.Errorf("usage: gssh-agentd principals -user <name>")
	}
	cfg, err := LoadConfig(stateDir)
	if err != nil {
		return err
	}
	client := newSocketClient(cfg.SocketPath, 10*time.Second)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://agentd/principals?user="+url.QueryEscape(user), nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("gssh-agentd unreachable (is the service running?): %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("principals denied: %s", string(msg))
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

	recordAuthSerial(ctx, cfg.SocketPath, stateDir, user, serial, keyid)
	return nil
}

// recordAuthSerial reports the serial seen at login to the daemon on a
// best-effort basis. Only when a serial is present and the socket token
// exists (session audit active). Any error is swallowed.
func recordAuthSerial(ctx context.Context, socketPath, stateDir, user string, serial int64, keyid string) {
	if serial <= 0 {
		return
	}
	token := readSocketToken(stateDir)
	if token == "" {
		return
	}
	authCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	client := newSocketClient(socketPath, time.Second)
	_ = postSocketJSON(authCtx, client, token, "/auth",
		authRecord{User: user, Serial: serial, KeyID: keyid})
}
