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

// agentManifest is the response of GET /v1/agents: which agent binaries the
// server serves and whether the host rollout is ready at all. The endpoint
// responds with 200 even when the gate is closed — it is the diagnostic
// source for which condition is missing (see rolloutGate).
type agentManifest struct {
	Version      string   `json:"version"`
	RolloutReady bool     `json:"rollout_ready"`
	Missing      []string `json:"missing"`
	PinSource    string   `json:"pin_source"`
	// PinError is the coarse category of the last pin error (empty = none).
	// Deliberately no full text: the manifest is public and unauthenticated,
	// the raw error text contains internals (container paths, dial details)
	// and stays only in the server log.
	PinError string              `json:"pin_error"`
	Agents   []agentManifestItem `json:"agents"`
}

// agentManifestItem describes a served binary. The hash is hex and thus
// directly sha256sum-compatible (install.sh verifies with exactly that).
type agentManifestItem struct {
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// handleAgentManifest returns the manifest. The version stays deliberately
// in the public manifest: the binary is already version-identifiable
// anyway (SHA-256 comparison, `gssh-agentd version`), stripping it would be
// pseudo-protection and would only take away curl-based operator diagnostics.
func handleAgentManifest(gate rolloutGate, agents AgentSource) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		st := gate.status(r.Context())
		manifest := agentManifest{
			Version:      version.String(),
			RolloutReady: len(st.Missing) == 0,
			Missing:      st.Missing,
			PinSource:    st.Pin.Source,
			PinError:     st.Pin.ErrCode,
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

// handleAgentDownload streams an agent binary. Deliberately unauthenticated:
// the host has no credentials at this point, and the binary is a public
// artifact — the enrollment token gates enrollment, not binary access. The
// endpoint hangs off the tighter download limiter (15-40 MB per fetch), not
// the regular sign/enroll limiter.
func handleAgentDownload(gate rolloutGate, agents AgentSource, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !gate.allow(w, r) {
			return
		}
		osName, arch := r.PathValue("os"), r.PathValue("arch")
		body, info, err := agents.Open(osName, arch)
		if err != nil {
			if !errors.Is(err, agentdist.ErrNotFound) {
				logger.Error("opening agent binary failed", "os", osName, "arch", arch, "error", err)
			}
			http.Error(w, "no agent binary for "+osName+"/"+arch, http.StatusNotFound)
			return
		}
		defer func() { _ = body.Close() }()

		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.FormatInt(info.Size, 10))
		// no-store on all rollout routes: a cache that serves the old binary
		// alongside the new install.sh after a server upgrade produces
		// phantom hash mismatches. Caching would provide no benefit anyway
		// (one download per host lifetime).
		w.Header().Set("Cache-Control", "no-store")
		if _, err := io.Copy(w, body); err != nil {
			// Headers are already out — only the log remains (aborted download).
			logger.Warn("streaming agent binary aborted", "os", osName, "arch", arch, "error", err)
		}
	}
}
