package api

import (
	"context"
	"net/http"
	"net/url"
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
	// rolloutMissingAgentURLHTTPS: Agent-URL gesetzt, aber kein https-URL.
	rolloutMissingAgentURLHTTPS = "agent_public_url_https"
	// rolloutMissingPublicURLHTTPS: Public-URL gesetzt, aber kein https-URL.
	// Ohne https wäre `curl … | sudo sh` Klartext-HTTP: der SHA-256-Check im
	// Script schützt dann nichts (ein MITM manipuliert Script samt Hashes),
	// und der SPKI-Pin greift erst beim Enrollment — nicht bei der
	// Root-Code-Ausführung durch das Script. Deshalb fail-closed statt
	// http zuzulassen (Sicherheitsmodell: „Nur über HTTPS ausliefern").
	rolloutMissingPublicURLHTTPS = "public_url_https"
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

// isHTTPSURL prüft, ob raw ein parsbarer https-URL mit Host ist. Die
// Dial-Pin-Quelle erzwingt https ohnehin (dialPin) — diese Prüfung schließt
// die Lücke für die statische und die Datei-Quelle, bei denen sonst ein
// http-install_command das Gate passierte.
func isHTTPSURL(raw string) bool {
	parsed, err := url.Parse(raw)
	return err == nil && parsed.Scheme == "https" && parsed.Hostname() != ""
}

// registerRolloutRoutes hängt die drei öffentlichen Rollout-Routen in den
// Public-Mux (Plural /v1/agents/… — der mTLS-Listener mit /v1/agent/… bleibt
// unangetastet). Alle drei sind unauthentifiziert: der Host hat vor dem
// Enrollment keine Credentials.
func registerRolloutRoutes(mux *http.ServeMux, deps Deps) {
	gate := newRolloutGate(deps)

	// Das Manifest bleibt auch bei geschlossenem Gate erreichbar (200) — es ist
	// die Diagnosequelle dafür, welche Bedingung fehlt.
	mux.HandleFunc("GET /v1/agents", deps.RateLimit.limit(handleAgentManifest(gate, deps.Agents)))
	mux.HandleFunc("GET /v1/agents/{os}/{arch}",
		deps.DownloadRateLimit.limit(handleAgentDownload(gate, deps.Agents, deps.Logger)))
	mux.HandleFunc("GET /install.sh",
		deps.RateLimit.limit(handleInstallScript(gate, deps.Agents, deps.AgentPublicURL, deps.PublicBaseURL, deps.Logger)))
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
