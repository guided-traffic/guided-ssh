package api

import (
	"bytes"
	_ "embed"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"text/template"

	"github.com/guided-traffic/guided-ssh/internal/agentdist"
	"github.com/guided-traffic/guided-ssh/internal/version"
)

//go:embed install.sh.tmpl
var installScriptTemplateSource string

// installScriptTemplate is parsed at package startup; a syntax error in the
// template is a programming error and should surface immediately.
var installScriptTemplate = template.Must(template.New("install.sh").Parse(installScriptTemplateSource))

// Allowed shape of the templated agent values: arch as a case pattern,
// hash as the comparison value of the sha256sum check.
var (
	archPattern   = regexp.MustCompile(`^[a-z0-9]+$`)
	sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// installScriptData are the values the server templates into the script.
// Everything except token and flags is already fixed — in particular the
// SPKI pin and the binary hashes.
type installScriptData struct {
	BaseURL  string
	AgentURL string
	Version  string
	Pin      string
	ArchList string              // space-separated, for error messages in the script
	Agents   []agentManifestItem // linux only; provides the hash table
	Unit     string              // content of the systemd unit, static (no unit templating)
}

// handleInstallScript returns the templated install.sh. With a closed gate
// it responds with 503 — there is no code path that serves a script
// without a pin or without an agent URL.
func handleInstallScript(gate rolloutGate, agents AgentSource, agentPublicURL, publicBaseURL string, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		st := gate.status(r.Context())
		if len(st.Missing) > 0 {
			writeJSON(w, http.StatusServiceUnavailable, rolloutUnavailable{
				Error:   "host rollout not configured",
				Missing: st.Missing,
			})
			return
		}

		script, err := renderInstallScript(installScriptData{
			BaseURL:  publicBaseURL,
			AgentURL: agentPublicURL,
			Version:  version.String(),
			Pin:      st.Pin.Pin,
			Agents:   linuxAgents(agents),
			Unit:     agentdist.UnitFile,
		})
		if err != nil {
			logger.Error("rendering install.sh failed", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(script)
	}
}

// linuxAgents returns the embeddable linux binaries; the agent is
// systemd-bound and thus linux-only, other OS entries are ignored by the
// script anyway.
func linuxAgents(agents AgentSource) []agentManifestItem {
	var items []agentManifestItem
	if agents == nil {
		return items
	}
	for _, info := range agents.List() {
		if info.OS != "linux" {
			continue
		}
		items = append(items, agentManifestItem{OS: info.OS, Arch: info.Arch, Size: info.Size, SHA256: info.SHA256})
	}
	return items
}

// renderInstallScript fills in the template. The templated values end up
// in the script inside single quotes; a single quote in the value would
// break the quoting, so this fails closed here instead of shipping a
// broken script to N hosts.
func renderInstallScript(data installScriptData) ([]byte, error) {
	arches := make([]string, 0, len(data.Agents))
	for _, agent := range data.Agents {
		arches = append(arches, agent.Arch)
	}
	data.ArchList = strings.Join(arches, " ")

	// The unit comes from the quoted here-doc (<<'UNIT_EOF', no expansion);
	// only the line ending needs to be right so the terminator sits at the
	// start of a line.
	data.Unit = strings.TrimRight(data.Unit, "\n") + "\n"

	for field, value := range map[string]string{
		"public-url": data.BaseURL, "agent-url": data.AgentURL,
		"pin": data.Pin, "version": data.Version, "arch-list": data.ArchList,
	} {
		if strings.ContainsAny(value, "'\n") {
			return nil, fmt.Errorf("value for %s contains a quote or line break: %q", field, value)
		}
	}
	// Arch and hash are build-controlled (filenames from the embed, hex
	// from sha256), but end up unquoted in the case pattern and comparison
	// value respectively — hence a strict check instead of just quotes.
	for _, agent := range data.Agents {
		if !archPattern.MatchString(agent.Arch) {
			return nil, fmt.Errorf("arch %q is not [a-z0-9]+", agent.Arch)
		}
		if !sha256Pattern.MatchString(agent.SHA256) {
			return nil, fmt.Errorf("sha256 for arch %s is not a 64-digit hex value: %q", agent.Arch, agent.SHA256)
		}
	}
	// The terminator also must not appear on the first line — there the
	// leading line break the comparison otherwise assumes is missing.
	if strings.Contains("\n"+data.Unit, "\nUNIT_EOF") {
		return nil, fmt.Errorf("systemd unit contains the here-doc terminator")
	}

	var buf bytes.Buffer
	if err := installScriptTemplate.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("templating install.sh: %w", err)
	}
	return buf.Bytes(), nil
}
