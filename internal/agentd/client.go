package agentd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// agentAPI abstracts the agent endpoints of the server (tests use a fake).
type agentAPI interface {
	Renew(ctx context.Context, publicKey string) (string, error)
	RenewMTLS(ctx context.Context, csrPEM string) (string, error)
	Principals(ctx context.Context, user string) ([]string, error)
	Bundle(ctx context.Context) (string, error)
	SendSessions(ctx context.Context, events []sessionEventWire) error
	Heartbeat(ctx context.Context) error
}

// apiClient talks to the mTLS agent API with the client certificate obtained
// during enrollment; the server certificate is verified against the bundled
// CA. The client certificate is swappable (rotation, phase 10) and read per
// TLS handshake via GetClientCertificate.
type apiClient struct {
	baseURL   string
	http      *http.Client
	transport *http.Transport

	mu         sync.Mutex
	clientCert tls.Certificate
}

// newAPIClient loads the mTLS material from the state directory.
func newAPIClient(cfg *Config, paths Paths) (*apiClient, error) {
	clientCert, err := tls.LoadX509KeyPair(paths.AgentCertFile(), paths.AgentKeyFile())
	if err != nil {
		return nil, fmt.Errorf("loading mtls client certificate: %w", err)
	}
	caPEM, err := os.ReadFile(paths.ServerCAFile())
	if err != nil {
		return nil, fmt.Errorf("loading server ca: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("server ca %s: not a valid pem", paths.ServerCAFile())
	}
	c := &apiClient{
		baseURL:    strings.TrimRight(cfg.AgentURL, "/"),
		clientCert: clientCert,
	}
	c.transport = &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    pool,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			c.mu.Lock()
			defer c.mu.Unlock()
			cert := c.clientCert
			return &cert, nil
		},
	}}
	c.http = &http.Client{Timeout: 15 * time.Second, Transport: c.transport}
	return c, nil
}

// setClientCert swaps in the client certificate after a rotation; open
// connections using the old certificate are closed.
func (c *apiClient) setClientCert(cert tls.Certificate) {
	c.mu.Lock()
	c.clientCert = cert
	c.mu.Unlock()
	c.transport.CloseIdleConnections()
}

// Renew exchanges the host public key for a fresh host certificate.
func (c *apiClient) Renew(ctx context.Context, publicKey string) (string, error) {
	body, err := json.Marshal(map[string]string{"public_key": publicKey})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/v1/agent/renew", strings.NewReader(string(body)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	var resp struct {
		Certificate string `json:"certificate"`
	}
	if err := c.doJSON(req, &resp); err != nil {
		return "", err
	}
	if resp.Certificate == "" {
		return "", fmt.Errorf("renew response without certificate")
	}
	return resp.Certificate, nil
}

// RenewMTLS exchanges a CSR for a fresh mTLS client certificate
// (authenticated via the still-valid old certificate).
func (c *apiClient) RenewMTLS(ctx context.Context, csrPEM string) (string, error) {
	body, err := json.Marshal(map[string]string{"csr": csrPEM})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/v1/agent/renew-mtls", strings.NewReader(string(body)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	var resp struct {
		Certificate string `json:"certificate"`
	}
	if err := c.doJSON(req, &resp); err != nil {
		return "", err
	}
	if resp.Certificate == "" {
		return "", fmt.Errorf("renew-mtls response without certificate")
	}
	return resp.Certificate, nil
}

// Principals fetches the authorized principals for a local user.
func (c *apiClient) Principals(ctx context.Context, user string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.baseURL+"/v1/agent/principals?user="+url.QueryEscape(user), nil)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Principals []string `json:"principals"`
	}
	if err := c.doJSON(req, &resp); err != nil {
		return nil, err
	}
	return resp.Principals, nil
}

// Bundle returns the current user CA bundle (TrustedUserCAKeys content).
func (c *apiClient) Bundle(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/agent/bundle/user", nil)
	if err != nil {
		return "", err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("reaching agent api: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("agent api: %s", resp.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// Heartbeat reports liveness (the server stamps last_seen_at from the mTLS
// identity). No request body, no response body — the agent sits on the
// untrusted side and contributes nothing but the connection itself.
func (c *apiClient) Heartbeat(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/agent/heartbeat", nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("reaching agent api: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("agent api: %s", resp.Status)
	}
	return nil
}

// SendSessions delivers a batch of session/sudo events to the server (mTLS).
func (c *apiClient) SendSessions(ctx context.Context, events []sessionEventWire) error {
	body, err := json.Marshal(map[string]any{"events": events})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/v1/agent/sessions", strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("reaching agent api: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("agent api: %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	return nil
}

// doJSON executes the request and decodes the JSON response.
func (c *apiClient) doJSON(req *http.Request, out any) error {
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("reaching agent api: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("agent api: %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
