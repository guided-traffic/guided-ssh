package api

import (
	"context"
	"net/http"
	"net/url"
)

// Conditions of the host rollout. If one is missing, the gated endpoints
// (binary download, install.sh, token mint) respond with 503 and name
// exactly these entries; the manifest stays reachable and lists them for
// diagnosis.
const (
	// rolloutMissingBinaries: no agent binary in the image (dev build).
	rolloutMissingBinaries = "binaries"
	// rolloutMissingPin: no pin source returns a pin (see PinProvider).
	rolloutMissingPin = "pin"
	// rolloutMissingAgentURL: GSSH_AGENT_PUBLIC_URL not set. Deliberately
	// never derived (rule 2) — otherwise a wrong agent URL ends up
	// unnoticed in the config.yaml of N hosts.
	rolloutMissingAgentURL = "agent_public_url"
	// rolloutMissingPublicURL: GSSH_PUBLIC_URL not set.
	rolloutMissingPublicURL = "public_url"
	// rolloutMissingAgentURLHTTPS: agent URL set, but not an https URL.
	rolloutMissingAgentURLHTTPS = "agent_public_url_https"
	// rolloutMissingPublicURLHTTPS: public URL set, but not an https URL.
	// Without https, `curl … | sudo sh` would be plaintext HTTP: the
	// SHA-256 check in the script then protects nothing (an MITM tampers
	// with both the script and the hashes), and the SPKI pin only applies
	// during enrollment — not during root code execution by the script.
	// Hence fail-closed instead of allowing http (security model: "only
	// serve over HTTPS").
	rolloutMissingPublicURLHTTPS = "public_url_https"
)

// rolloutGate bundles the four preconditions of the one-command host
// install. There is deliberately no separate feature flag: the conditions
// are the switch (an extra flag would be duplicate state that can drift).
type rolloutGate struct {
	agents         AgentSource
	pins           *PinProvider
	agentPublicURL string
	publicBaseURL  string
}

// rolloutStatus is the result of a gate check: the missing conditions
// (empty ⇒ gate open) and the pin state determined along the way.
type rolloutStatus struct {
	Missing []string
	Pin     PinStatus
}

// newRolloutGate builds the gate from the server dependencies.
func newRolloutGate(deps Deps) rolloutGate {
	return rolloutGate{
		agents:         deps.Agents,
		pins:           deps.Pins,
		agentPublicURL: deps.AgentPublicURL,
		publicBaseURL:  deps.PublicBaseURL,
	}
}

// status checks all four conditions individually — a clear diagnosis
// instead of guessing which configuration is missing.
func (g rolloutGate) status(ctx context.Context) rolloutStatus {
	var st rolloutStatus
	if g.agents == nil || len(g.agents.List()) == 0 {
		st.Missing = append(st.Missing, rolloutMissingBinaries)
	}
	if g.pins != nil {
		st.Pin = g.pins.Status(ctx)
	}
	if st.Pin.Pin == "" {
		st.Missing = append(st.Missing, rolloutMissingPin)
	}
	switch {
	case g.agentPublicURL == "":
		st.Missing = append(st.Missing, rolloutMissingAgentURL)
	case !isHTTPSURL(g.agentPublicURL):
		st.Missing = append(st.Missing, rolloutMissingAgentURLHTTPS)
	}
	switch {
	case g.publicBaseURL == "":
		st.Missing = append(st.Missing, rolloutMissingPublicURL)
	case !isHTTPSURL(g.publicBaseURL):
		st.Missing = append(st.Missing, rolloutMissingPublicURLHTTPS)
	}
	return st
}

// isHTTPSURL checks whether raw is a parsable https URL with a host. The
// dial pin source enforces https anyway (dialPin) — this check closes the
// gap for the static and file sources, where otherwise an http
// install_command would pass the gate.
func isHTTPSURL(raw string) bool {
	parsed, err := url.Parse(raw)
	return err == nil && parsed.Scheme == "https" && parsed.Hostname() != ""
}

// registerRolloutRoutes attaches the three public rollout routes to the
// public mux (plural /v1/agents/… — the mTLS listener with /v1/agent/…
// stays untouched). All three are unauthenticated: the host has no
// credentials before enrollment.
func registerRolloutRoutes(mux *http.ServeMux, deps Deps) {
	gate := newRolloutGate(deps)

	// The manifest stays reachable (200) even with a closed gate — it is
	// the diagnostic source for which condition is missing.
	mux.HandleFunc("GET /v1/agents", deps.RateLimit.limit(handleAgentManifest(gate, deps.Agents)))
	mux.HandleFunc("GET /v1/agents/{os}/{arch}",
		deps.DownloadRateLimit.limit(handleAgentDownload(gate, deps.Agents, deps.Logger)))
	mux.HandleFunc("GET /install.sh",
		deps.RateLimit.limit(handleInstallScript(gate, deps.Agents, deps.AgentPublicURL, deps.PublicBaseURL, deps.Logger)))
}

// rolloutUnavailable is the 503 body of the gated endpoints.
type rolloutUnavailable struct {
	Error   string   `json:"error"`
	Missing []string `json:"missing"`
}

// allow itself answers a gated request with 503 when the gate is closed
// (including the missing conditions) and returns false; true means: all
// preconditions are satisfied, the handler may proceed.
func (g rolloutGate) allow(w http.ResponseWriter, r *http.Request) bool {
	st := g.status(r.Context())
	if len(st.Missing) == 0 {
		return true
	}
	writeJSON(w, http.StatusServiceUnavailable, rolloutUnavailable{
		Error:   "host rollout not configured",
		Missing: st.Missing,
	})
	return false
}
