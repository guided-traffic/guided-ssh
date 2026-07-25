package api

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/guided-traffic/guided-ssh/internal/agentdist"
	"github.com/guided-traffic/guided-ssh/internal/version"
)

// agentManifest ist die Antwort von GET /v1/agents: welche Agent-Binaries der
// Server ausliefert und ob der Host-Rollout überhaupt bereit ist. Der Endpoint
// antwortet auch bei geschlossenem Gate mit 200 — er ist die Diagnosequelle
// dafür, welche Bedingung fehlt (siehe rolloutGate).
type agentManifest struct {
	Version      string              `json:"version"`
	RolloutReady bool                `json:"rollout_ready"`
	Missing      []string            `json:"missing"`
	PinSource    string              `json:"pin_source"`
	Agents       []agentManifestItem `json:"agents"`
}

// agentManifestItem beschreibt ein ausgeliefertes Binary. Der Hash ist Hex und
// damit direkt sha256sum-kompatibel (das install.sh prüft genau damit).
type agentManifestItem struct {
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// handleAgentManifest liefert das Manifest. Die Version bleibt bewusst im
// öffentlichen Manifest: das Binary ist ohnehin version-identifizierbar
// (SHA-256-Abgleich, `gssh-agentd version`), Streichen wäre Scheinschutz und
// nähme nur die Operator-Diagnose per curl.
func handleAgentManifest(gate rolloutGate, agents AgentSource) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		st := gate.status(r.Context())
		manifest := agentManifest{
			Version:      version.String(),
			RolloutReady: len(st.Missing) == 0,
			Missing:      st.Missing,
			PinSource:    st.Pin.Source,
			Agents:       []agentManifestItem{},
		}
		if manifest.Missing == nil {
			manifest.Missing = []string{}
		}
		if agents != nil {
			for _, info := range agents.List() {
				manifest.Agents = append(manifest.Agents, agentManifestItem{
					OS: info.OS, Arch: info.Arch, Size: info.Size, SHA256: info.SHA256,
				})
			}
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, manifest)
	}
}

// handleAgentDownload streamt ein Agent-Binary. Bewusst unauthentifiziert: der
// Host hat zu diesem Zeitpunkt keine Credentials, und das Binary ist ein
// öffentliches Artefakt — das Enrollment-Token gated das Enrollment, nicht den
// Binary-Zugriff. Der Endpoint hängt am engeren Download-Limiter (15–40 MB je
// Abruf), nicht am regulären Sign-/Enroll-Limiter.
func handleAgentDownload(gate rolloutGate, agents AgentSource, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !gate.allow(w, r) {
			return
		}
		osName, arch := r.PathValue("os"), r.PathValue("arch")
		body, info, err := agents.Open(osName, arch)
		if err != nil {
			if !errors.Is(err, agentdist.ErrNotFound) {
				logger.Error("agent-binary öffnen fehlgeschlagen", "os", osName, "arch", arch, "error", err)
			}
			http.Error(w, "kein agent-binary für "+osName+"/"+arch, http.StatusNotFound)
			return
		}
		defer func() { _ = body.Close() }()

		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.FormatInt(info.Size, 10))
		// no-store auf allen Rollout-Routen: ein Cache, der nach einem
		// Server-Upgrade das alte Binary zur neuen install.sh liefert, erzeugt
		// Phantom-Hash-Mismatches. Nutzen hätte Caching ohnehin keinen
		// (ein Download pro Host-Lebenszeit).
		w.Header().Set("Cache-Control", "no-store")
		if _, err := io.Copy(w, body); err != nil {
			// Header sind raus — bleibt nur das Log (abgebrochener Download).
			logger.Warn("agent-binary streamen abgebrochen", "os", osName, "arch", arch, "error", err)
		}
	}
}
