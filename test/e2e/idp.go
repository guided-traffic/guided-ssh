//go:build e2e

package e2e

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// passwordGrant fetches an ID token from Dex via the resource owner
// password grant (passwordConnector: ldap). The token endpoint does not
// check the Host header, so the local port-forward suffices; the iss claim
// stays the configured in-cluster issuer URL and thus matches the server.
func passwordGrant(dexLocalURL, username, password string) (string, error) {
	form := url.Values{
		"grant_type": {"password"},
		"client_id":  {"gssh-cli"},
		"username":   {username},
		"password":   {password},
		"scope":      {"openid profile email groups"},
	}
	resp, err := http.PostForm(dexLocalURL+"/dex/token", form)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token-endpoint: %s: %s", resp.Status, body)
	}
	var payload struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", err
	}
	if payload.IDToken == "" {
		return "", fmt.Errorf("response without id_token: %s", body)
	}
	return payload.IDToken, nil
}

// jwtClaims decodes the payload of a JWT (without signature verification —
// only for test assertions over claims like groups).
func jwtClaims(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("not a jwt: %d segments", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		return nil, err
	}
	return claims, nil
}

// tokenGroups reads the groups claim of an ID token.
func tokenGroups(token string) ([]string, error) {
	claims, err := jwtClaims(token)
	if err != nil {
		return nil, err
	}
	raw, _ := claims["groups"].([]any)
	groups := make([]string, 0, len(raw))
	for _, g := range raw {
		if s, ok := g.(string); ok {
			groups = append(groups, s)
		}
	}
	return groups, nil
}

var (
	formRe  = regexp.MustCompile(`(?s)<form[^>]*action="([^"]*)"[^>]*>(.*?)</form>`)
	inputRe = regexp.MustCompile(`<input[^>]*name="([^"]+)"[^>]*>`)
	valueRe = regexp.MustCompile(`value="([^"]*)"`)
)

// approveDeviceFlow plays the "browser" of the device flow: the
// verification URI printed by gssh is opened over the local Dex port-forward
// and the HTML forms (user code → LDAP login) are filled in generically.
// The success criterion is not this function but the exit code of
// `gssh login --device` — this just clicks through as best-effort.
func approveDeviceFlow(dexLocalURL, verificationURI, userCode, username, password string) error {
	// Replace the in-cluster host with the local forward, keep path+query.
	parsed, err := url.Parse(verificationURI)
	if err != nil {
		return fmt.Errorf("verification-uri: %w", err)
	}
	local, err := url.Parse(dexLocalURL)
	if err != nil {
		return err
	}
	parsed.Scheme = local.Scheme
	parsed.Host = local.Host

	jar, err := cookiejar.New(nil)
	if err != nil {
		return err
	}
	client := &http.Client{Jar: jar, Timeout: 15 * time.Second}

	resp, err := client.Get(parsed.String())
	if err != nil {
		return err
	}
	current := resp.Request.URL
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	for step := 0; step < 8; step++ {
		match := formRe.FindStringSubmatch(string(body))
		if match == nil {
			return nil // no more forms — flow complete
		}
		// Dex HTML-escapes the action attribute (&amp;) — decode first,
		// otherwise the state parameter is lost.
		action, fields := html.UnescapeString(match[1]), match[2]
		form := url.Values{}
		for _, input := range inputRe.FindAllStringSubmatch(fields, -1) {
			name := input[1]
			value := ""
			if vm := valueRe.FindStringSubmatch(input[0]); vm != nil {
				value = vm[1]
			}
			switch name {
			case "user_code":
				if value == "" {
					value = userCode
				}
			case "login", "username":
				value = username
			case "password":
				value = password
			}
			form.Set(name, value)
		}
		target, err := current.Parse(action)
		if err != nil {
			return fmt.Errorf("form-action %q: %w", action, err)
		}
		target.Scheme = local.Scheme
		target.Host = local.Host
		resp, err := client.PostForm(target.String(), form)
		if err != nil {
			return err
		}
		current = resp.Request.URL
		body, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
	}
	return fmt.Errorf("device flow not complete after 8 forms; last page:\n%s", body)
}
