package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/guided-traffic/guided-ssh/internal/pintls"
)

// apiClient spricht die REST-API des gssh-servers.
type apiClient struct {
	baseURL string
	http    *http.Client
}

// newAPIClient baut den HTTP-Client. Mit pin_sha256 wird das Serverzertifikat
// ausschließlich über den SPKI-SHA-256-Fingerprint verifiziert; Chain- und
// Hostname-Prüfung entfallen bewusst (der Pin ersetzt das CA-Vertrauen und
// deckt damit auch selbstsignierte Deployments ab).
func newAPIClient(cfg *Config) (*apiClient, error) {
	pin, err := cfg.Pin()
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 30 * time.Second}
	if pin != nil {
		client.Transport = pintls.Transport(pin)
	}
	return &apiClient{baseURL: strings.TrimRight(cfg.APIURL, "/"), http: client}, nil
}

// signUserRequest spiegelt den Body von POST /v1/sign/user (internal/api).
type signUserRequest struct {
	PublicKey       string `json:"public_key"`
	ValiditySeconds int64  `json:"validity_seconds,omitempty"`
}

// signUser tauscht das ID-Token gegen ein signiertes Benutzerzertifikat.
func (c *apiClient) signUser(ctx context.Context, idToken, publicKey string, validity time.Duration) (*ssh.Certificate, error) {
	body, err := json.Marshal(signUserRequest{PublicKey: publicKey, ValiditySeconds: int64(validity / time.Second)})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/sign/user", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+idToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sign-endpoint erreichen: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("sign-endpoint: %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	var signed struct {
		Certificate string `json:"certificate"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&signed); err != nil {
		return nil, fmt.Errorf("sign-antwort dekodieren: %w", err)
	}
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(signed.Certificate))
	if err != nil {
		return nil, fmt.Errorf("zertifikat aus antwort parsen: %w", err)
	}
	cert, ok := parsed.(*ssh.Certificate)
	if !ok {
		return nil, errors.New("antwort enthält kein ssh-zertifikat")
	}
	return cert, nil
}
