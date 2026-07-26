// Package agentd implements the host agent gssh-agentd (phase 5):
// enrollment against the gssh server, automatic renewal of the host
// certificate, maintenance of the TrustedUserCAKeys bundle, and the
// AuthorizedPrincipalsCommand helper with a fail-closed cache.
package agentd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Default paths and intervals of the agent.
const (
	DefaultStateDir = "/var/lib/guided-ssh"
	DefaultSSHDir   = "/etc/ssh"
	DefaultPAMDir   = "/etc/pam.d"

	defaultCacheTTL       = 5 * time.Minute
	defaultBundleInterval = time.Hour
	defaultRenewInterval  = 5 * time.Minute
)

// Config is the agent configuration written during enrollment
// (<state-dir>/config.yaml).
type Config struct {
	// AgentURL is the mTLS agent API of the server (https://…).
	AgentURL string `yaml:"agent_url"`
	// HostID is the host UUID assigned during enrollment.
	HostID string `yaml:"host_id"`
	// HostName is the registered hostname.
	HostName string `yaml:"host_name"`
	// SSHKeyPath is the SSH host public key whose certificate is maintained.
	SSHKeyPath string `yaml:"ssh_key_path"`
	// SSHDir is the sshd configuration directory (bundle, certificate, snippet).
	SSHDir string `yaml:"ssh_dir"`
	// SocketPath is the unix socket of the principals helper.
	SocketPath string `yaml:"socket_path"`
	// CacheTTL: how long principals are still served from the cache while the
	// API is unreachable; fail-closed afterward.
	CacheTTL Duration `yaml:"cache_ttl"`
	// BundleInterval is the refresh interval of the CA bundle.
	BundleInterval Duration `yaml:"bundle_interval"`
	// RenewInterval is the check interval for certificate renewal.
	RenewInterval Duration `yaml:"renew_interval"`
	// ReloadCommand runs after writing a new host certificate (e.g.
	// "systemctl reload sshd"); empty = nothing.
	ReloadCommand string `yaml:"reload_command,omitempty"`
	// SessionAudit enables host session/sudo audit (phase 9, opt-in at
	// enroll): writable socket endpoints, spool, and flush to the server.
	// Without the flag the daemon behaves as in phase 5.
	SessionAudit bool `yaml:"session_audit,omitempty"`
}

// Duration is time.Duration with YAML marshalling as a Go duration string
// ("5m") — human-readable in config.yaml (mirrors internal/cli, read-only there).
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

// MarshalYAML implements yaml.Marshaler.
func (d Duration) MarshalYAML() (any, error) {
	return time.Duration(d).String(), nil
}

// Paths are the derived file paths of a state directory.
type Paths struct {
	StateDir string
}

// Files in the state directory.
func (p Paths) ConfigFile() string    { return filepath.Join(p.StateDir, "config.yaml") }
func (p Paths) AgentKeyFile() string  { return filepath.Join(p.StateDir, "agent.key") }
func (p Paths) AgentCertFile() string { return filepath.Join(p.StateDir, "agent.crt") }
func (p Paths) ServerCAFile() string  { return filepath.Join(p.StateDir, "server-ca.pem") }
func (p Paths) CacheFile() string     { return filepath.Join(p.StateDir, "principals-cache.json") }
func (p Paths) DefaultSocket() string { return filepath.Join(p.StateDir, "agentd.sock") }

// SocketTokenFile protects the writable socket endpoints (phase 9): only
// the root helper can read the token and submit events (0600).
func (p Paths) SocketTokenFile() string { return filepath.Join(p.StateDir, "socket-token") }

// SpoolFile is the local, loss-tolerant buffer of session events (JSON
// lines) until the daemon flushes them to the server.
func (p Paths) SpoolFile() string { return filepath.Join(p.StateDir, "sessions-spool.jsonl") }

// HostCertPath derives the certificate path from the public key path
// (ssh_host_ed25519_key.pub → ssh_host_ed25519_key-cert.pub).
func HostCertPath(sshKeyPath string) string {
	return strings.TrimSuffix(sshKeyPath, ".pub") + "-cert.pub"
}

// UserCAPath is the TrustedUserCAKeys file in the sshd directory.
func UserCAPath(sshDir string) string {
	return filepath.Join(sshDir, "guided-ssh-user-ca.pub")
}

// SnippetPath is the generated sshd configuration snippet.
func SnippetPath(sshDir string) string {
	return filepath.Join(sshDir, "sshd_config.d", "guided-ssh.conf")
}

// applyDefaults fills empty intervals with their defaults.
func (c *Config) applyDefaults(paths Paths) {
	if c.CacheTTL <= 0 {
		c.CacheTTL = Duration(defaultCacheTTL)
	}
	if c.BundleInterval <= 0 {
		c.BundleInterval = Duration(defaultBundleInterval)
	}
	if c.RenewInterval <= 0 {
		c.RenewInterval = Duration(defaultRenewInterval)
	}
	if c.SocketPath == "" {
		c.SocketPath = paths.DefaultSocket()
	}
	if c.SSHDir == "" {
		c.SSHDir = DefaultSSHDir
	}
}

// LoadConfig reads the agent configuration from the state directory.
func LoadConfig(stateDir string) (*Config, error) {
	paths := Paths{StateDir: stateDir}
	raw, err := os.ReadFile(paths.ConfigFile())
	if err != nil {
		return nil, fmt.Errorf("reading agent configuration (missing enrollment?): %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("agent configuration %s: %w", paths.ConfigFile(), err)
	}
	if cfg.AgentURL == "" || cfg.HostID == "" || cfg.SSHKeyPath == "" {
		return nil, fmt.Errorf("agent configuration %s incomplete", paths.ConfigFile())
	}
	cfg.applyDefaults(paths)
	return &cfg, nil
}

// writeConfig persists the agent configuration.
func writeConfig(paths Paths, cfg *Config) error {
	raw, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(paths.ConfigFile(), raw, 0o600)
}
