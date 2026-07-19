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

// PrintPrincipals ist der AuthorizedPrincipalsCommand-Helper: fragt den
// Daemon über den Unix-Socket und schreibt Principals zeilenweise nach
// stdout. Jeder Fehler (Daemon down, Timeout, API+Cache leer) führt zu
// einem Fehler — sshd wertet fehlende Ausgabe als Ablehnung (fail-closed).
//
// serial/keyid stammen aus den sshd-Tokens %s/%i (nur bei aktivem Session-Audit
// gesetzt): nach dem Principals-Druck werden sie best-effort an den Daemon
// gemeldet, damit dieser eine folgende Session-Open korrelieren kann. Fehler
// dabei sind irrelevant — das (fail-closed) Login-Ergebnis steht bereits fest.
func PrintPrincipals(ctx context.Context, stateDir, user string, serial int64, keyid string, stdout io.Writer) error {
	if user == "" {
		return fmt.Errorf("aufruf: gssh-agentd principals -user <name>")
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

	recordAuthSerial(ctx, cfg.SocketPath, stateDir, user, serial, keyid)
	return nil
}

// recordAuthSerial meldet dem Daemon best-effort den am Login gesehenen Serial.
// Nur wenn ein Serial vorliegt und das Socket-Token existiert (Session-Audit
// aktiv). Jeder Fehler wird verschluckt.
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
