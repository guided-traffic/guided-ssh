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

// socketTokenHeader trägt das Token der schreibenden Socket-Endpunkte.
const socketTokenHeader = "X-GSSH-Token" //nolint:gosec // Header-Name, kein Secret

// newSocketClient baut einen HTTP-Client, der über den Unix-Socket des Daemons
// spricht (die Adresse im Request-URL ist ein Platzhalter).
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

// readSocketToken liest das Socket-Token aus dem State-Verzeichnis (leer, wenn
// es fehlt — Session-Audit ist dann nicht aktiviert).
func readSocketToken(stateDir string) string {
	raw, err := os.ReadFile(Paths{StateDir: stateDir}.SocketTokenFile())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

// postSocketJSON sendet body als JSON an den Daemon-Socket-Pfad mit Token (der
// client ist bereits an den Socket gebunden, die URL-Host ist ein Platzhalter).
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
		return fmt.Errorf("gssh-agentd nicht erreichbar: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("socket %s: %s: %s", path, resp.Status, strings.TrimSpace(string(msg)))
	}
	return nil
}

// sessionEventWire ist das Draht-/Spool-Format eines Session-/sudo-Ereignisses;
// es entspricht exakt dem Body von POST /v1/agent/sessions (Serial 0 = keiner).
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

// authRecord meldet dem Daemon einen frisch am Login gesehenen Serial (aus den
// sshd-Tokens %s/%i), damit er eine nachfolgende Session-Open korrelieren kann.
type authRecord struct {
	User   string `json:"user"`
	Serial int64  `json:"serial"`
	KeyID  string `json:"key_id"`
}
