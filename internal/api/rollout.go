package api

import (
	"context"
	"net/http"
)

// Bedingungen des Host-Rollouts. Fehlt eine, antworten die gateten Endpunkte
// (Binary-Download, install.sh, Token-Mint) mit 503 und nennen genau diese
// Einträge; das Manifest bleibt erreichbar und weist sie zur Diagnose aus.
const (
	// rolloutMissingBinaries: kein Agent-Binary im Image (Dev-Build).
	rolloutMissingBinaries = "binaries"
	// rolloutMissingPin: keine Pin-Quelle liefert einen Pin (siehe PinProvider).
	rolloutMissingPin = "pin"
	// rolloutMissingAgentURL: GSSH_AGENT_PUBLIC_URL nicht gesetzt. Wird bewusst
	// nie abgeleitet (Regel 2) — eine falsche Agent-URL landet sonst unbemerkt
	// in der config.yaml von N Hosts.
	rolloutMissingAgentURL = "agent_public_url"
	// rolloutMissingPublicURL: weder GSSH_PUBLIC_URL noch GSSH_UI_BASE_URL.
	rolloutMissingPublicURL = "public_url"
)

// rolloutGate bündelt die vier Voraussetzungen des One-Command-Host-Installs.
// Es gibt bewusst kein eigenes Feature-Flag: die Bedingungen sind der Schalter
// (ein zusätzliches Flag wäre doppelter Zustand, der davon abdriften kann).
type rolloutGate struct {
	agents         AgentSource
	pins           *PinProvider
	agentPublicURL string
	publicBaseURL  string
}

// rolloutStatus ist das Ergebnis einer Gate-Prüfung: die fehlenden
// Bedingungen (leer ⇒ Gate offen) und der dabei ermittelte Pin-Zustand.
type rolloutStatus struct {
	Missing []string
	Pin     PinStatus
}

// newRolloutGate baut das Gate aus den Server-Abhängigkeiten.
func newRolloutGate(deps Deps) rolloutGate {
	return rolloutGate{
		agents:         deps.Agents,
		pins:           deps.Pins,
		agentPublicURL: deps.AgentPublicURL,
		publicBaseURL:  deps.PublicBaseURL,
	}
}

// status prüft alle vier Bedingungen einzeln — eindeutige Diagnose statt
// Rätselraten, welche Konfiguration fehlt.
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
	if g.agentPublicURL == "" {
		st.Missing = append(st.Missing, rolloutMissingAgentURL)
	}
	if g.publicBaseURL == "" {
		st.Missing = append(st.Missing, rolloutMissingPublicURL)
	}
	return st
}

// rolloutUnavailable ist der 503-Body der gateten Endpunkte.
type rolloutUnavailable struct {
	Error   string   `json:"error"`
	Missing []string `json:"missing"`
}

// allow beantwortet einen gateten Request bei geschlossenem Gate selbst mit
// 503 (inklusive der fehlenden Bedingungen) und liefert false; true bedeutet:
// alle Voraussetzungen erfüllt, der Handler darf weitermachen.
func (g rolloutGate) allow(w http.ResponseWriter, r *http.Request) bool {
	st := g.status(r.Context())
	if len(st.Missing) == 0 {
		return true
	}
	writeJSON(w, http.StatusServiceUnavailable, rolloutUnavailable{
		Error:   "host-rollout nicht konfiguriert",
		Missing: st.Missing,
	})
	return false
}
