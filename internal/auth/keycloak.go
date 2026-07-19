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

// keycloakPageSize ist die Seitengröße beim Blättern durch die Admin-API.
const keycloakPageSize = 100

// KeycloakConfig konfiguriert die Directory-Source für die
// Keycloak-Admin-API. Der Client braucht einen Service-Account mit der
// Client-Rolle "view-users" von "realm-management".
type KeycloakConfig struct {
	// BaseURL ist die Keycloak-Basis-URL (z. B. https://idp.example.com).
	BaseURL string
	// Realm ist der Realm, dessen Benutzer synchronisiert werden.
	Realm string
	// ClientID/ClientSecret sind die Credentials des Sync-Service-Accounts.
	ClientID     string
	ClientSecret string
}

// KeycloakSource liest Benutzer und Gruppen über die Keycloak-Admin-API
// (Directory-API-Variante des Gruppen-Syncs).
type KeycloakSource struct {
	adminBase string
	issuer    string
	client    *http.Client
}

// NewKeycloakSource baut die Source; Tokens holt sie per Client-Credentials
// vom Realm-Token-Endpoint und erneuert sie automatisch.
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

// Issuer ist die Issuer-URL des Realms.
func (k *KeycloakSource) Issuer() string { return k.issuer }

// keycloakUser und keycloakGroup sind die benötigten Felder der Admin-API.
type keycloakUser struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Enabled  bool   `json:"enabled"`
}

type keycloakGroup struct {
	Name string `json:"name"`
}

// Users blättert durch alle Realm-Benutzer und lädt je Benutzer die Gruppen.
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

// get führt einen GET gegen die Admin-API aus und dekodiert die JSON-Antwort.
func (k *KeycloakSource) get(ctx context.Context, path string, target any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.adminBase+path, nil)
	if err != nil {
		return err
	}
	resp, err := k.client.Do(req)
	if err != nil {
		return fmt.Errorf("auth: keycloak-admin-api %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("auth: keycloak-admin-api %s: status %d", path, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(target); err != nil {
		return fmt.Errorf("auth: keycloak-admin-api %s: antwort dekodieren: %w", path, err)
	}
	return nil
}
