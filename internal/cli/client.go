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

// apiClient talks to the gssh server's REST API.
type apiClient struct {
	baseURL string
	http    *http.Client
}

// newAPIClient builds the HTTP client. With pin_sha256, the server
// certificate is verified exclusively via the SPKI SHA-256 fingerprint;
// chain and hostname checks are deliberately skipped (the pin replaces CA
// trust and thus also covers self-signed deployments).
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

// signUserRequest mirrors the body of POST /v1/sign/user (internal/api).
type signUserRequest struct {
	PublicKey       string `json:"public_key"`
	ValiditySeconds int64  `json:"validity_seconds,omitempty"`
}

// signUser exchanges the ID token for a signed user certificate.
func (c *apiClient) signUser(ctx context.Context, idToken, publicKey string, validity time.Duration) (*ssh.Certificate, error) {
	return c.sign(ctx, "/v1/sign/user", idToken, publicKey, validity)
}

// signCI exchanges the GitLab job token for a signed CI certificate.
func (c *apiClient) signCI(ctx context.Context, jobToken, publicKey string, validity time.Duration) (*ssh.Certificate, error) {
	return c.sign(ctx, "/v1/sign/ci", jobToken, publicKey, validity)
}

// sign calls a sign endpoint: bearer token in, certificate out.
func (c *apiClient) sign(ctx context.Context, path, idToken, publicKey string, validity time.Duration) (*ssh.Certificate, error) {
	body, err := json.Marshal(signUserRequest{PublicKey: publicKey, ValiditySeconds: int64(validity / time.Second)})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+idToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("reaching sign endpoint: %w", err)
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
		return nil, fmt.Errorf("decoding sign response: %w", err)
	}
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(signed.Certificate))
	if err != nil {
		return nil, fmt.Errorf("parsing certificate from response: %w", err)
	}
	cert, ok := parsed.(*ssh.Certificate)
	if !ok {
		return nil, errors.New("response does not contain an ssh certificate")
	}
	return cert, nil
}
