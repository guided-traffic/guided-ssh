// Package cli implements the user CLI gssh (phase 4): SSO login with an
// ephemeral key pair, certificate retrieval via POST /v1/sign/user, and
// transparent ssh integration. Key and certificate live exclusively in the
// ssh-agent — nothing is persisted to disk.
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

// envConfig overrides the path of the configuration file (useful for
// `gssh ssh`, which doesn't accept its own flags).
const envConfig = "GSSH_CONFIG"

// Config is the CLI configuration (~/.config/guided-ssh/config.yaml).
type Config struct {
	// APIURL is the base URL of the gssh server, e.g. https://gssh.example.com.
	APIURL string `yaml:"api_url"`
	// Issuer is the OIDC issuer URL of the IdP (discovery).
	Issuer string `yaml:"issuer"`
	// ClientID is the public OIDC client of the CLI.
	ClientID string `yaml:"client_id"`
	// Scopes; empty = openid, profile, email plus groups (the latter only if
	// the issuer's discovery does not rule it out — see auth.defaultScopes).
	// Grants are matched by group, so overriding this without groups yields a
	// token the sign endpoint cannot authorize.
	Scopes []string `yaml:"scopes,omitempty"`
	// PinSHA256 pins the TLS certificate of the API server: base64-encoded
	// SHA-256 of the SubjectPublicKeyInfo. Empty = system CAs.
	PinSHA256 string `yaml:"pin_sha256,omitempty"`
	// Validity is the desired certificate lifetime (Go duration, e.g.
	// "8h"); 0 = server default. The server's policy maximum always applies.
	Validity Duration `yaml:"validity,omitempty"`
}

// Duration is time.Duration with YAML unmarshalling from strings like "16h".
type Duration time.Duration

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	parsed, err := time.ParseDuration(node.Value)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", node.Value, err)
	}
	*d = Duration(parsed)
	return nil
}

// DefaultConfigPath returns the default path of the configuration file
// (XDG_CONFIG_HOME or ~/.config).
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

// ResolveConfigPath resolves the configuration path: flag before
// GSSH_CONFIG before default path (also used by gssh-admin).
func ResolveConfigPath(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if env := os.Getenv(envConfig); env != "" {
		return env
	}
	return DefaultConfigPath()
}

// LoadConfig reads and validates the configuration file.
func LoadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading configuration: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("configuration %s: %w", path, err)
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
		return nil, fmt.Errorf("configuration %s: required fields missing: %s", path, strings.Join(missing, ", "))
	}
	if _, err := cfg.Pin(); err != nil {
		return nil, fmt.Errorf("configuration %s: %w", path, err)
	}
	return &cfg, nil
}

// Pin decodes the pinned SPKI fingerprint (nil = no pinning).
func (c *Config) Pin() ([]byte, error) {
	if c.PinSHA256 == "" {
		return nil, nil
	}
	pin, err := pintls.DecodePin(c.PinSHA256)
	if err != nil {
		return nil, fmt.Errorf("pin_sha256: %w", err)
	}
	return pin, nil
}

// configHint is the hint text shown when the configuration file is missing.
func configHint(path string) string {
	return fmt.Sprintf(`create configuration file: %s

api_url: https://gssh.example.com
issuer: https://idp.example.com/realms/example
client_id: gssh-cli
# optional:
# scopes: [openid, profile, email, groups]   # default; groups drives grant matching
# pin_sha256: <base64-encoded sha-256 of the server spki>
# validity: 8h
`, path)
}
