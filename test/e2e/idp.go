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

// passwordGrant holt ein ID-Token von Dex per Resource-Owner-Password-Grant
// (passwordConnector: ldap). Der Token-Endpoint prüft den Host-Header nicht,
// daher reicht der lokale Port-Forward; der iss-Claim bleibt die konfigurierte
// In-Cluster-Issuer-URL und passt damit zum Server.
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
		return "", fmt.Errorf("antwort ohne id_token: %s", body)
	}
	return payload.IDToken, nil
}

// jwtClaims dekodiert den Payload eines JWT (ohne Signaturprüfung — nur für
// Test-Assertions über Claims wie groups).
func jwtClaims(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("kein jwt: %d segmente", len(parts))
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

// tokenGroups liest den groups-Claim eines ID-Tokens.
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

// approveDeviceFlow spielt den "Browser" des Device-Flows: die von gssh
// ausgegebene Verification-URI wird über den lokalen Dex-Port-Forward geöffnet
// und die HTML-Formulare (User-Code → LDAP-Login) werden generisch ausgefüllt.
// Erfolgskriterium ist nicht diese Funktion, sondern der Exit-Code von
// `gssh login --device` — hier wird nur bestmöglich geklickt.
func approveDeviceFlow(dexLocalURL, verificationURI, userCode, username, password string) error {
	// In-Cluster-Host durch den lokalen Forward ersetzen, Pfad+Query behalten.
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
			return nil // keine Formulare mehr — Flow abgeschlossen
		}
		// Dex escapet das action-Attribut HTML-mäßig (&amp;) — erst dekodieren,
		// sonst geht der state-Parameter verloren.
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
	return fmt.Errorf("device-flow nach 8 formularen nicht abgeschlossen; letzte seite:\n%s", body)
}
