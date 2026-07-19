// Package cli implementiert das Benutzer-CLI gssh (Phase 4): SSO-Login mit
// ephemeralem Schlüsselpaar, Zertifikatsbezug über POST /v1/sign/user und
// transparente ssh-Integration. Schlüssel und Zertifikat leben ausschließlich
// im ssh-agent — nichts wird auf Platte persistiert.
package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/guided-traffic/guided-ssh/internal/pintls"
)

// envConfig übersteuert den Pfad der Konfigurationsdatei (nützlich für
// `gssh ssh`, das keine eigenen Flags entgegennimmt).
const envConfig = "GSSH_CONFIG"

// Config ist die CLI-Konfiguration (~/.config/guided-ssh/config.yaml).
type Config struct {
	// APIURL ist die Basis-URL des gssh-servers, z. B. https://gssh.example.com.
	APIURL string `yaml:"api_url"`
	// Issuer ist die OIDC-Issuer-URL des IdP (Discovery).
	Issuer string `yaml:"issuer"`
	// ClientID ist der öffentliche OIDC-Client der CLI.
	ClientID string `yaml:"client_id"`
	// Scopes; leer = openid, profile, email.
	Scopes []string `yaml:"scopes,omitempty"`
	// PinSHA256 pinnt das TLS-Zertifikat des API-Servers: Base64-kodierter
	// SHA-256 des SubjectPublicKeyInfo. Leer = System-CAs.
	PinSHA256 string `yaml:"pin_sha256,omitempty"`
	// Validity ist die gewünschte Zertifikatslaufzeit (Go-Duration, z. B.
	// "8h"); 0 = Server-Default. Das Policy-Maximum des Servers greift immer.
	Validity Duration `yaml:"validity,omitempty"`
}

// Duration ist time.Duration mit YAML-Unmarshalling aus Strings wie "16h".
type Duration time.Duration

// UnmarshalYAML implementiert yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	parsed, err := time.ParseDuration(node.Value)
	if err != nil {
		return fmt.Errorf("ungültige dauer %q: %w", node.Value, err)
	}
	*d = Duration(parsed)
	return nil
}

// DefaultConfigPath liefert den Standardpfad der Konfigurationsdatei
// (XDG_CONFIG_HOME bzw. ~/.config).
func DefaultConfigPath() string {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "guided-ssh", "config.yaml")
}

// resolveConfigPath löst den Konfigurationspfad auf: Flag vor GSSH_CONFIG
// vor Standardpfad.
func resolveConfigPath(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if env := os.Getenv(envConfig); env != "" {
		return env
	}
	return DefaultConfigPath()
}

// LoadConfig liest und validiert die Konfigurationsdatei.
func LoadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("konfiguration lesen: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("konfiguration %s: %w", path, err)
	}
	var missing []string
	for _, field := range []struct{ name, value string }{
		{"api_url", cfg.APIURL},
		{"issuer", cfg.Issuer},
		{"client_id", cfg.ClientID},
	} {
		if field.value == "" {
			missing = append(missing, field.name)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("konfiguration %s: pflichtfelder fehlen: %s", path, strings.Join(missing, ", "))
	}
	if _, err := cfg.pin(); err != nil {
		return nil, fmt.Errorf("konfiguration %s: %w", path, err)
	}
	return &cfg, nil
}

// pin dekodiert den gepinnten SPKI-Fingerprint (nil = kein Pinning).
func (c *Config) pin() ([]byte, error) {
	if c.PinSHA256 == "" {
		return nil, nil
	}
	pin, err := pintls.DecodePin(c.PinSHA256)
	if err != nil {
		return nil, fmt.Errorf("pin_sha256: %w", err)
	}
	return pin, nil
}

// configHint ist der Hinweistext bei fehlender Konfigurationsdatei.
func configHint(path string) string {
	return fmt.Sprintf(`konfigurationsdatei anlegen: %s

api_url: https://gssh.example.com
issuer: https://idp.example.com/realms/example
client_id: gssh-cli
# optional:
# pin_sha256: <base64-kodierter sha-256 des server-spki>
# validity: 8h
`, path)
}
