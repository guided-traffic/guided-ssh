package cli

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadConfig(t *testing.T) {
	pin := base64.StdEncoding.EncodeToString(make([]byte, sha256.Size))
	path := writeConfig(t, `api_url: https://gssh.example.com/
issuer: https://idp.example.com/realms/x
client_id: gssh-cli
scopes: [openid, email]
pin_sha256: "`+pin+`"
validity: 8h
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.APIURL != "https://gssh.example.com/" || cfg.Issuer != "https://idp.example.com/realms/x" {
		t.Errorf("unerwartete urls: %+v", cfg)
	}
	if cfg.ClientID != "gssh-cli" || len(cfg.Scopes) != 2 {
		t.Errorf("client_id/scopes falsch: %+v", cfg)
	}
	if time.Duration(cfg.Validity) != 8*time.Hour {
		t.Errorf("validity = %v, erwartet 8h", time.Duration(cfg.Validity))
	}
	decoded, err := cfg.pin()
	if err != nil || len(decoded) != sha256.Size {
		t.Errorf("pin() = %v, %v", decoded, err)
	}
}

func TestLoadConfigFehlt(t *testing.T) {
	_, err := LoadConfig(filepath.Join(t.TempDir(), "nix.yaml"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("erwartete os.ErrNotExist, bekam %v", err)
	}
}

func TestLoadConfigPflichtfelder(t *testing.T) {
	path := writeConfig(t, "api_url: https://gssh.example.com\n")
	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("fehler erwartet (pflichtfelder)")
	}
	for _, want := range []string{"issuer", "client_id"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("fehler %q nennt %q nicht", err, want)
		}
	}
}

func TestLoadConfigKaputtesYAML(t *testing.T) {
	path := writeConfig(t, "api_url: [kein\nstring\n")
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("fehler erwartet (yaml)")
	}
}

func TestLoadConfigUngueltigeDauer(t *testing.T) {
	path := writeConfig(t, "api_url: a\nissuer: b\nclient_id: c\nvalidity: sofort\n")
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("fehler erwartet (dauer)")
	}
}

func TestLoadConfigUngueltigerPin(t *testing.T) {
	base := "api_url: a\nissuer: b\nclient_id: c\n"
	for name, pin := range map[string]string{
		"kein base64":   "pin_sha256: '%%%'",
		"falsche länge": "pin_sha256: " + base64.StdEncoding.EncodeToString([]byte("kurz")),
	} {
		if _, err := LoadConfig(writeConfig(t, base+pin+"\n")); err == nil {
			t.Errorf("%s: fehler erwartet", name)
		}
	}
}

func TestDefaultConfigPathXDG(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/tmp/xdg")
	if got := DefaultConfigPath(); got != filepath.Join("/tmp/xdg", "guided-ssh", "config.yaml") {
		t.Errorf("DefaultConfigPath() = %q", got)
	}
}

func TestDefaultConfigPathHome(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "")
	got := DefaultConfigPath()
	if !strings.HasSuffix(got, filepath.Join(".config", "guided-ssh", "config.yaml")) {
		t.Errorf("DefaultConfigPath() = %q", got)
	}
}

func TestResolveConfigPath(t *testing.T) {
	t.Setenv(envConfig, "/env/config.yaml")
	if got := resolveConfigPath("/flag/config.yaml"); got != "/flag/config.yaml" {
		t.Errorf("flag muss gewinnen, bekam %q", got)
	}
	if got := resolveConfigPath(""); got != "/env/config.yaml" {
		t.Errorf("env muss vor default kommen, bekam %q", got)
	}
	t.Setenv(envConfig, "")
	if got := resolveConfigPath(""); !strings.HasSuffix(got, "config.yaml") {
		t.Errorf("default-pfad fehlt, bekam %q", got)
	}
}
