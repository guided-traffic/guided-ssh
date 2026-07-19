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
	"time"
)

// agentAPI abstrahiert die Agent-Endpunkte des Servers (Tests nutzen einen Fake).
type agentAPI interface {
	Renew(ctx context.Context, publicKey string) (string, error)
	Principals(ctx context.Context, user string) ([]string, error)
	Bundle(ctx context.Context) (string, error)
}

// apiClient spricht die mTLS-Agent-API mit dem beim Enrollment erhaltenen
// Client-Zertifikat; das Serverzertifikat wird gegen die mitgelieferte CA
// verifiziert.
type apiClient struct {
	baseURL string
	http    *http.Client
}

// newAPIClient lädt mTLS-Material aus dem State-Verzeichnis.
func newAPIClient(cfg *Config, paths Paths) (*apiClient, error) {
	clientCert, err := tls.LoadX509KeyPair(paths.AgentCertFile(), paths.AgentKeyFile())
	if err != nil {
		return nil, fmt.Errorf("mtls-client-zertifikat laden: %w", err)
	}
	caPEM, err := os.ReadFile(paths.ServerCAFile())
	if err != nil {
		return nil, fmt.Errorf("server-ca laden: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("server-ca %s: kein gültiges pem", paths.ServerCAFile())
	}
	return &apiClient{
		baseURL: strings.TrimRight(cfg.AgentURL, "/"),
		http: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{
				MinVersion:   tls.VersionTLS12,
				RootCAs:      pool,
				Certificates: []tls.Certificate{clientCert},
			}},
		},
	}, nil
}

// Renew tauscht den Host-Public-Key gegen ein frisches Host-Zertifikat.
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
		return "", fmt.Errorf("renew-antwort ohne zertifikat")
	}
	return resp.Certificate, nil
}

// Principals fragt die autorisierten Principals für einen lokalen Benutzer ab.
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

// Bundle liefert das aktuelle User-CA-Bundle (TrustedUserCAKeys-Inhalt).
func (c *apiClient) Bundle(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/agent/bundle/user", nil)
	if err != nil {
		return "", err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("agent-api erreichen: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("agent-api: %s", resp.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// doJSON führt den Request aus und dekodiert die JSON-Antwort.
func (c *apiClient) doJSON(req *http.Request, out any) error {
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("agent-api erreichen: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("agent-api: %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
