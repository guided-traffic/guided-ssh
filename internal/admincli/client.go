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

// Grant mirrors the API representation of an access rule
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

// CIGrant mirrors the API representation of a CI access rule
// (internal/api ciGrantJSON, phase 7).
type CIGrant struct {
	ID                 string            `json:"id,omitempty"`
	Project            string            `json:"project,omitempty"`
	RefPattern         string            `json:"ref_pattern,omitempty"`
	ProtectedOnly      *bool             `json:"protected_only,omitempty"`
	EnvironmentPattern string            `json:"environment_pattern,omitempty"`
	TagSelector        map[string]string `json:"tag_selector,omitempty"`
	Principals         []string          `json:"principals"`
	MaxValiditySeconds int64             `json:"max_validity_seconds"`
}

// ApplyResult mirrors the response of POST /v1/admin/grants/apply.
type ApplyResult struct {
	Created   int `json:"created"`
	Updated   int `json:"updated"`
	Deleted   int `json:"deleted"`
	Unchanged int `json:"unchanged"`
}

// client talks to the admin API with a bearer token (SPKI pinning like gssh).
type client struct {
	baseURL string
	token   string
	http    *http.Client
}

// newClient builds the API client from the shared CLI configuration.
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

// do performs an admin API call and decodes the response into target
// (nil = discard the response).
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
		return fmt.Errorf("reach admin API: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("admin API: %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	if target == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(target); err != nil {
		return fmt.Errorf("decode admin response: %w", err)
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

func (c *client) listCIGrants(ctx context.Context) ([]CIGrant, error) {
	var grants []CIGrant
	err := c.do(ctx, http.MethodGet, "/v1/admin/ci-grants", nil, &grants)
	return grants, err
}

func (c *client) getCIGrant(ctx context.Context, id string) (*CIGrant, error) {
	var grant CIGrant
	err := c.do(ctx, http.MethodGet, "/v1/admin/ci-grants/"+id, nil, &grant)
	return &grant, err
}

func (c *client) createCIGrant(ctx context.Context, g *CIGrant) (*CIGrant, error) {
	var created CIGrant
	err := c.do(ctx, http.MethodPost, "/v1/admin/ci-grants", g, &created)
	return &created, err
}

func (c *client) updateCIGrant(ctx context.Context, id string, g *CIGrant) (*CIGrant, error) {
	var updated CIGrant
	err := c.do(ctx, http.MethodPut, "/v1/admin/ci-grants/"+id, g, &updated)
	return &updated, err
}

func (c *client) deleteCIGrant(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/v1/admin/ci-grants/"+id, nil, nil)
}

func (c *client) applyCIGrants(ctx context.Context, grants []CIGrant) (*ApplyResult, error) {
	var result ApplyResult
	err := c.do(ctx, http.MethodPost, "/v1/admin/ci-grants/apply",
		map[string]any{"ci_grants": grants}, &result)
	return &result, err
}
