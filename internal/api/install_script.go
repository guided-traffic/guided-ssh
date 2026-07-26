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

// installScriptTemplate wird beim Paket-Start geparst; ein Syntaxfehler im
// Template ist ein Programmierfehler und soll sofort auffallen.
var installScriptTemplate = template.Must(template.New("install.sh").Parse(installScriptTemplateSource))

// Zulässige Form der getemplateten Agent-Werte: Arch als case-Pattern, Hash als
// Vergleichswert der sha256sum-Prüfung.
var (
	archPattern   = regexp.MustCompile(`^[a-z0-9]+$`)
	sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// installScriptData sind die Werte, die der Server in das Script templatet.
// Alles bis auf Token und Flags steht damit schon fest — insbesondere der
// SPKI-Pin und die Binary-Hashes.
type installScriptData struct {
	BaseURL  string
	AgentURL string
	Version  string
	Pin      string
	ArchList string              // Leerzeichen-getrennt, für Fehlermeldungen im Script
	Agents   []agentManifestItem // nur linux; liefert die Hash-Tabelle
	Unit     string              // Inhalt der systemd-Unit, statisch (kein Unit-Templating)
}

// handleInstallScript liefert das getemplatete install.sh. Bei geschlossenem
// Gate antwortet es mit 503 — es gibt keinen Codepfad, der ein Script ohne Pin
// oder ohne Agent-URL ausliefert.
func handleInstallScript(gate rolloutGate, agents AgentSource, agentPublicURL, publicBaseURL string, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		st := gate.status(r.Context())
		if len(st.Missing) > 0 {
			writeJSON(w, http.StatusServiceUnavailable, rolloutUnavailable{
				Error:   "host-rollout nicht konfiguriert",
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
			logger.Error("install.sh rendern fehlgeschlagen", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(script)
	}
}

// linuxAgents liefert die einbettbaren linux-Binaries; der Agent ist
// systemd-gebunden und damit linux-only, andere OS-Einträge ignoriert das
// Script ohnehin.
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

// renderInstallScript füllt das Template. Die getemplateten Werte landen im
// Script in einfachen Anführungszeichen; ein einfaches Anführungszeichen im
// Wert würde das Quoting sprengen, deshalb hier fail-closed abbrechen statt ein
// kaputtes Script an N Hosts auszuliefern.
func renderInstallScript(data installScriptData) ([]byte, error) {
	arches := make([]string, 0, len(data.Agents))
	for _, agent := range data.Agents {
		arches = append(arches, agent.Arch)
	}
	data.ArchList = strings.Join(arches, " ")

	// Die Unit kommt aus dem quoted Here-Doc (<<'UNIT_EOF', keine Expansion);
	// nur der Zeilenabschluss muss stimmen, damit der Terminator am Zeilenanfang
	// steht.
	data.Unit = strings.TrimRight(data.Unit, "\n") + "\n"

	for field, value := range map[string]string{
		"public-url": data.BaseURL, "agent-url": data.AgentURL,
		"pin": data.Pin, "version": data.Version, "arch-liste": data.ArchList,
	} {
		if strings.ContainsAny(value, "'\n") {
			return nil, fmt.Errorf("wert für %s enthält anführungszeichen oder zeilenumbruch: %q", field, value)
		}
	}
	// Arch und Hash sind build-kontrolliert (Dateinamen aus dem Embed, Hex aus
	// sha256), landen aber ungequotet im case-Pattern bzw. im Vergleichswert —
	// deshalb strikt statt nur auf Quotes prüfen.
	for _, agent := range data.Agents {
		if !archPattern.MatchString(agent.Arch) {
			return nil, fmt.Errorf("arch %q ist kein [a-z0-9]+", agent.Arch)
		}
		if !sha256Pattern.MatchString(agent.SHA256) {
			return nil, fmt.Errorf("sha256 für arch %s ist kein 64-stelliger hex-wert: %q", agent.Arch, agent.SHA256)
		}
	}
	// Der Terminator darf auch nicht in der ersten Zeile stehen — dort fehlt der
	// führende Umbruch, den der Vergleich sonst voraussetzt.
	if strings.Contains("\n"+data.Unit, "\nUNIT_EOF") {
		return nil, fmt.Errorf("systemd-unit enthält den here-doc-terminator")
	}

	var buf bytes.Buffer
	if err := installScriptTemplate.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("install.sh templaten: %w", err)
	}
	return buf.Bytes(), nil
}
