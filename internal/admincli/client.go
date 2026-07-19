// Package admincli implementiert das Admin-CLI gssh-admin (Phase 6):
// Grant-Verwaltung (CRUD) und deklarativer YAML-Abgleich gegen die Admin-API
// des gssh-servers. Authentifizierung wie gssh: OIDC-ID-Token (PKCE bzw.
// Device-Flow), alternativ via GSSH_ID_TOKEN/--token.
package admincli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/guided-traffic/guided-ssh/internal/cli"
	"github.com/guided-traffic/guided-ssh/internal/pintls"
)

// Grant spiegelt die API-Repräsentation einer Zugriffsregel
// (internal/api grantJSON).
type Grant struct {
	ID                 string            `json:"id,omitempty"`
	Group              string            `json:"group,omitempty"`
	Issuer             string            `json:"issuer,omitempty"`
	TagSelector        map[string]string `json:"tag_selector,omitempty"`
	Principals         []string          `json:"principals"`
	Sudo               bool              `json:"sudo,omitempty"`
	MaxValiditySeconds int64             `json:"max_validity_seconds"`
}

// ApplyResult spiegelt die Antwort von POST /v1/admin/grants/apply.
type ApplyResult struct {
	Created   int `json:"created"`
	Updated   int `json:"updated"`
	Deleted   int `json:"deleted"`
	Unchanged int `json:"unchanged"`
}

// client spricht die Admin-API mit Bearer-Token (SPKI-Pinning wie gssh).
type client struct {
	baseURL string
	token   string
	http    *http.Client
}

// newClient baut den API-Client aus der gemeinsamen CLI-Konfiguration.
func newClient(cfg *cli.Config, token string) (*client, error) {
	pin, err := cfg.Pin()
	if err != nil {
		return nil, err
	}
	httpClient := &http.Client{Timeout: 30 * time.Second}
	if pin != nil {
		httpClient.Transport = pintls.Transport(pin)
	}
	return &client{
		baseURL: strings.TrimRight(cfg.APIURL, "/"),
		token:   token,
		http:    httpClient,
	}, nil
}

// do führt einen Admin-API-Call aus und dekodiert die Antwort nach target
// (nil = Antwort verwerfen).
func (c *client) do(ctx context.Context, method, path string, payload, target any) error {
	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("admin-api erreichen: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("admin-api: %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	if target == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(target); err != nil {
		return fmt.Errorf("admin-antwort dekodieren: %w", err)
	}
	return nil
}

func (c *client) listGrants(ctx context.Context) ([]Grant, error) {
	var grants []Grant
	err := c.do(ctx, http.MethodGet, "/v1/admin/grants", nil, &grants)
	return grants, err
}

func (c *client) getGrant(ctx context.Context, id string) (*Grant, error) {
	var grant Grant
	err := c.do(ctx, http.MethodGet, "/v1/admin/grants/"+id, nil, &grant)
	return &grant, err
}

func (c *client) createGrant(ctx context.Context, g *Grant) (*Grant, error) {
	var created Grant
	err := c.do(ctx, http.MethodPost, "/v1/admin/grants", g, &created)
	return &created, err
}

func (c *client) updateGrant(ctx context.Context, id string, g *Grant) (*Grant, error) {
	var updated Grant
	err := c.do(ctx, http.MethodPut, "/v1/admin/grants/"+id, g, &updated)
	return &updated, err
}

func (c *client) deleteGrant(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/v1/admin/grants/"+id, nil, nil)
}

func (c *client) applyGrants(ctx context.Context, grants []Grant) (*ApplyResult, error) {
	var result ApplyResult
	err := c.do(ctx, http.MethodPost, "/v1/admin/grants/apply",
		map[string]any{"grants": grants}, &result)
	return &result, err
}
