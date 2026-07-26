package agentd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// socketTokenHeader carries the token of the writable socket endpoints.
const socketTokenHeader = "X-GSSH-Token" //nolint:gosec // header name, not a secret

// newSocketClient builds an HTTP client that talks over the daemon's unix
// socket (the address in the request URL is a placeholder).
func newSocketClient(socketPath string, timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(dialCtx context.Context, _, _ string) (net.Conn, error) {
				var dialer net.Dialer
				return dialer.DialContext(dialCtx, "unix", socketPath)
			},
		},
	}
}

// readSocketToken reads the socket token from the state directory (empty if
// it is missing — session audit is then not enabled).
func readSocketToken(stateDir string) string {
	raw, err := os.ReadFile(Paths{StateDir: stateDir}.SocketTokenFile())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

// postSocketJSON sends body as JSON to the daemon socket path with the
// token (the client is already bound to the socket, the URL host is a
// placeholder).
func postSocketJSON(ctx context.Context, client *http.Client, token, path string, body any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://agentd"+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(socketTokenHeader, token)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("gssh-agentd unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("socket %s: %s: %s", path, resp.Status, strings.TrimSpace(string(msg)))
	}
	return nil
}

// sessionEventWire is the wire/spool format of a session/sudo event; it
// matches exactly the body of POST /v1/agent/sessions (serial 0 = none).
type sessionEventWire struct {
	Phase      string    `json:"phase"`
	Service    string    `json:"service"`
	LocalUser  string    `json:"local_user"`
	RemoteUser string    `json:"remote_user"`
	RemoteAddr string    `json:"remote_addr"`
	TTY        string    `json:"tty"`
	Serial     int64     `json:"serial"`
	KeyID      string    `json:"key_id"`
	Command    string    `json:"command"`
	OccurredAt time.Time `json:"occurred_at"`
}

// authRecord reports to the daemon a serial freshly seen at login (from the
// sshd tokens %s/%i), so it can correlate a following session open.
type authRecord struct {
	User   string `json:"user"`
	Serial int64  `json:"serial"`
	KeyID  string `json:"key_id"`
}
