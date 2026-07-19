// Package agentd implementiert den Host-Agenten gssh-agentd (Phase 5):
// Enrollment gegen den gssh-server, automatische Erneuerung des
// Host-Zertifikats, Pflege des TrustedUserCAKeys-Bundles und der
// AuthorizedPrincipalsCommand-Helper mit Fail-closed-Cache.
package agentd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Default-Pfade und -Intervalle des Agenten.
const (
	DefaultStateDir = "/var/lib/guided-ssh"
	DefaultSSHDir   = "/etc/ssh"
	DefaultPAMDir   = "/etc/pam.d"

	defaultCacheTTL       = 5 * time.Minute
	defaultBundleInterval = time.Hour
	defaultRenewInterval  = 5 * time.Minute
)

// Config ist die beim Enrollment geschriebene Agent-Konfiguration
// (<state-dir>/config.yaml).
type Config struct {
	// AgentURL ist die mTLS-Agent-API des Servers (https://…).
	AgentURL string `yaml:"agent_url"`
	// HostID ist die beim Enrollment vergebene Host-UUID.
	HostID string `yaml:"host_id"`
	// HostName ist der registrierte Hostname.
	HostName string `yaml:"host_name"`
	// SSHKeyPath ist der SSH-Host-Public-Key, dessen Zertifikat gepflegt wird.
	SSHKeyPath string `yaml:"ssh_key_path"`
	// SSHDir ist das sshd-Konfigurationsverzeichnis (Bundle, Zertifikat, Snippet).
	SSHDir string `yaml:"ssh_dir"`
	// SocketPath ist der Unix-Socket des Principals-Helpers.
	SocketPath string `yaml:"socket_path"`
	// CacheTTL: solange werden Principals bei nicht erreichbarer API noch aus
	// dem Cache beantwortet; danach fail-closed.
	CacheTTL Duration `yaml:"cache_ttl"`
	// BundleInterval ist das Aktualisierungsintervall des CA-Bundles.
	BundleInterval Duration `yaml:"bundle_interval"`
	// RenewInterval ist das Prüfintervall der Zertifikatserneuerung.
	RenewInterval Duration `yaml:"renew_interval"`
	// ReloadCommand wird nach dem Schreiben eines neuen Host-Zertifikats
	// ausgeführt (z. B. "systemctl reload sshd"); leer = nichts.
	ReloadCommand string `yaml:"reload_command,omitempty"`
	// SessionAudit aktiviert das Host-Session-/sudo-Audit (Phase 9, Opt-in beim
	// Enroll): schreibende Socket-Endpunkte, Spool und Flush an den Server. Ohne
	// das Flag verhält sich der Daemon wie in Phase 5.
	SessionAudit bool `yaml:"session_audit,omitempty"`
}

// Duration ist time.Duration mit YAML-Marshalling als Go-Duration-String
// ("5m") — menschenlesbar in config.yaml (analog internal/cli, dort nur lesend).
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

// MarshalYAML implementiert yaml.Marshaler.
func (d Duration) MarshalYAML() (any, error) {
	return time.Duration(d).String(), nil
}

// Paths sind die abgeleiteten Dateipfade eines State-Verzeichnisses.
type Paths struct {
	StateDir string
}

// Dateien im State-Verzeichnis.
func (p Paths) ConfigFile() string    { return filepath.Join(p.StateDir, "config.yaml") }
func (p Paths) AgentKeyFile() string  { return filepath.Join(p.StateDir, "agent.key") }
func (p Paths) AgentCertFile() string { return filepath.Join(p.StateDir, "agent.crt") }
func (p Paths) ServerCAFile() string  { return filepath.Join(p.StateDir, "server-ca.pem") }
func (p Paths) CacheFile() string     { return filepath.Join(p.StateDir, "principals-cache.json") }
func (p Paths) DefaultSocket() string { return filepath.Join(p.StateDir, "agentd.sock") }

// SocketTokenFile schützt die schreibenden Socket-Endpunkte (Phase 9): nur
// root-Helfer können das Token lesen und Events einliefern (0600).
func (p Paths) SocketTokenFile() string { return filepath.Join(p.StateDir, "socket-token") }

// SpoolFile ist der lokale, verlust-tolerante Puffer der Session-Events
// (JSON-Lines), bis der Daemon sie an den Server flusht.
func (p Paths) SpoolFile() string { return filepath.Join(p.StateDir, "sessions-spool.jsonl") }

// HostCertPath leitet den Zertifikatspfad aus dem Public-Key-Pfad ab
// (ssh_host_ed25519_key.pub → ssh_host_ed25519_key-cert.pub).
func HostCertPath(sshKeyPath string) string {
	return strings.TrimSuffix(sshKeyPath, ".pub") + "-cert.pub"
}

// UserCAPath ist die TrustedUserCAKeys-Datei im sshd-Verzeichnis.
func UserCAPath(sshDir string) string {
	return filepath.Join(sshDir, "guided-ssh-user-ca.pub")
}

// SnippetPath ist der generierte sshd-Konfigurations-Schnipsel.
func SnippetPath(sshDir string) string {
	return filepath.Join(sshDir, "sshd_config.d", "guided-ssh.conf")
}

// applyDefaults füllt leere Intervalle mit den Defaults.
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

// LoadConfig liest die Agent-Konfiguration aus dem State-Verzeichnis.
func LoadConfig(stateDir string) (*Config, error) {
	paths := Paths{StateDir: stateDir}
	raw, err := os.ReadFile(paths.ConfigFile())
	if err != nil {
		return nil, fmt.Errorf("agent-konfiguration lesen (enrollment fehlt?): %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("agent-konfiguration %s: %w", paths.ConfigFile(), err)
	}
	if cfg.AgentURL == "" || cfg.HostID == "" || cfg.SSHKeyPath == "" {
		return nil, fmt.Errorf("agent-konfiguration %s unvollständig", paths.ConfigFile())
	}
	cfg.applyDefaults(paths)
	return &cfg, nil
}

// writeConfig persistiert die Agent-Konfiguration.
func writeConfig(paths Paths, cfg *Config) error {
	raw, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(paths.ConfigFile(), raw, 0o600)
}
