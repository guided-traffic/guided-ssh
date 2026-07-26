package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/oauth2/clientcredentials"
)

// keycloakPageSize is the page size when paging through the Admin API.
const keycloakPageSize = 100

// KeycloakConfig configures the directory source for the Keycloak Admin
// API. The client needs a service account with the "view-users" client role
// from "realm-management".
type KeycloakConfig struct {
	// BaseURL is the Keycloak base URL (e.g. https://idp.example.com).
	BaseURL string
	// Realm is the realm whose users are synced.
	Realm string
	// ClientID/ClientSecret are the credentials of the sync service account.
	ClientID     string
	ClientSecret string
}

// KeycloakSource reads users and groups via the Keycloak Admin API
// (the directory API variant of the group sync).
type KeycloakSource struct {
	adminBase string
	issuer    string
	client    *http.Client
}

// NewKeycloakSource builds the source; it fetches tokens via client
// credentials from the realm's token endpoint and renews them automatically.
func NewKeycloakSource(ctx context.Context, cfg KeycloakConfig) *KeycloakSource {
	base := strings.TrimRight(cfg.BaseURL, "/")
	oauthCfg := clientcredentials.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		TokenURL:     fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", base, cfg.Realm),
	}
	return &KeycloakSource{
		adminBase: fmt.Sprintf("%s/admin/realms/%s", base, cfg.Realm),
		issuer:    fmt.Sprintf("%s/realms/%s", base, cfg.Realm),
		client:    oauthCfg.Client(ctx),
	}
}

// Issuer is the realm's issuer URL.
func (k *KeycloakSource) Issuer() string { return k.issuer }

// keycloakUser and keycloakGroup are the fields needed from the Admin API.
type keycloakUser struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Enabled  bool   `json:"enabled"`
}

type keycloakGroup struct {
	Name string `json:"name"`
}

// Users pages through all realm users and loads each user's groups.
func (k *KeycloakSource) Users(ctx context.Context) ([]DirectoryUser, error) {
	var out []DirectoryUser
	for first := 0; ; first += keycloakPageSize {
		var page []keycloakUser
		params := url.Values{
			"first":               {strconv.Itoa(first)},
			"max":                 {strconv.Itoa(keycloakPageSize)},
			"briefRepresentation": {"true"},
		}
		if err := k.get(ctx, "/users?"+params.Encode(), &page); err != nil {
			return nil, err
		}
		for _, ku := range page {
			var groups []keycloakGroup
			if err := k.get(ctx, "/users/"+url.PathEscape(ku.ID)+"/groups", &groups); err != nil {
				return nil, err
			}
			names := make([]string, len(groups))
			for i, g := range groups {
				names[i] = g.Name
			}
			out = append(out, DirectoryUser{
				Subject:  ku.ID,
				Username: ku.Username,
				Email:    ku.Email,
				Groups:   names,
				Active:   ku.Enabled,
			})
		}
		if len(page) < keycloakPageSize {
			return out, nil
		}
	}
}

// get issues a GET against the Admin API and decodes the JSON response.
func (k *KeycloakSource) get(ctx context.Context, path string, target any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.adminBase+path, nil)
	if err != nil {
		return err
	}
	resp, err := k.client.Do(req)
	if err != nil {
		return fmt.Errorf("auth: keycloak admin api %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("auth: keycloak admin api %s: status %d", path, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(target); err != nil {
		return fmt.Errorf("auth: keycloak admin api %s: decoding response: %w", path, err)
	}
	return nil
}
