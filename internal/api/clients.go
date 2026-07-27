package api

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/guided-traffic/guided-ssh/internal/bindist"
	"github.com/guided-traffic/guided-ssh/internal/version"
)

// Conditions of the client install. Deliberately its own, smaller gate
// instead of reusing rolloutGate: the client needs neither the mTLS agent
// URL nor a pin — coupling it to those would close the client download for
// deployments that never roll out hosts via the one-command install.
const (
	// clientMissingBinaries: no client binary in the image (dev build).
	clientMissingBinaries = "binaries"
	// clientMissingPublicURL: GSSH_PUBLIC_URL not set — the script would
	// have no api_url to write into the config.
	clientMissingPublicURL = "public_url"
	// clientMissingPublicURLHTTPS: public URL set, but not https. Over
	// plaintext HTTP the SHA-256 check in the script protects nothing (an
	// MITM tampers with script and hashes alike) — hence fail-closed.
	clientMissingPublicURLHTTPS = "public_url_https"
	// clientMissingOIDCIssuer / clientMissingOIDCClientID: without both,
	// LoadConfig rejects the config the script would write — a half-written
	// config is strictly worse than a clear 503.
	clientMissingOIDCIssuer   = "oidc_issuer"
	clientMissingOIDCClientID = "oidc_client_id"
)

// clientGate bundles the preconditions of the client install. The pin is
// deliberately not a condition: the generated config uses WebPKI (see the
// security model), the pin is only ever an opt-in.
type clientGate struct {
	clients       ClientSource
	pins          *PinProvider
	publicBaseURL string
	issuer        string
	clientID      string
}

// clientStatus is the result of a gate check: the missing conditions
// (empty ⇒ gate open) and the pin state determined along the way.
type clientStatus struct {
	Missing []string
	Pin     PinStatus
}

// newClientGate builds the gate from the server dependencies.
func newClientGate(deps Deps) clientGate {
	return clientGate{
		clients:       deps.Clients,
		pins:          deps.Pins,
		publicBaseURL: deps.PublicBaseURL,
		issuer:        deps.UIConfig.OIDCIssuer,
		clientID:      deps.UIConfig.OIDCClientID,
	}
}

// status checks every condition individually — a clear diagnosis instead of
// guessing which configuration is missing.
func (g clientGate) status(ctx context.Context) clientStatus {
	var st clientStatus
	if g.clients == nil || len(g.clients.List()) == 0 {
		st.Missing = append(st.Missing, clientMissingBinaries)
	}
	if g.pins != nil {
		st.Pin = g.pins.Status(ctx)
	}
	switch {
	case g.publicBaseURL == "":
		st.Missing = append(st.Missing, clientMissingPublicURL)
	case !isHTTPSURL(g.publicBaseURL):
		st.Missing = append(st.Missing, clientMissingPublicURLHTTPS)
	}
	if g.issuer == "" {
		st.Missing = append(st.Missing, clientMissingOIDCIssuer)
	}
	if g.clientID == "" {
		st.Missing = append(st.Missing, clientMissingOIDCClientID)
	}
	return st
}

// allow answers a gated request with 503 (naming the missing conditions)
// and returns false; true means the handler may proceed.
func (g clientGate) allow(w http.ResponseWriter, r *http.Request) bool {
	st := g.status(r.Context())
	if len(st.Missing) == 0 {
		return true
	}
	writeClientUnavailable(w, st.Missing)
	return false
}

// writeClientUnavailable writes the 503 body of the gated client routes —
// same shape as rolloutUnavailable, own message.
func writeClientUnavailable(w http.ResponseWriter, missing []string) {
	writeJSON(w, http.StatusServiceUnavailable, rolloutUnavailable{
		Error:   "client install not configured",
		Missing: missing,
	})
}

// offeredPin returns the pin that may be handed to clients: only from an
// operator-controlled source (static/file). A dialed pin is auto-derived
// from whatever certificate the server currently presents and rotates with
// it — as a stored long-term anchor for the DNS fallback it would break
// mid-outage or on the next renewal, so it is never offered. Single
// enforcement point for the manifest, the script, and thus the UI.
func offeredPin(st PinStatus) string {
	switch st.Source {
	case PinSourceStatic, PinSourceFile:
		return st.Pin
	default:
		return ""
	}
}

// pinHint explains why no pin is offered — used by the script (--pin) and,
// via pin_source, by the connect dialog. Empty when a pin is available.
func (g clientGate) pinHint(st PinStatus) string {
	if offeredPin(st) != "" {
		return ""
	}
	if g.pins != nil && g.pins.Source() == PinSourceDial {
		return "server pin source is auto-derived (dial) — set GSSH_PUBLIC_PIN or GSSH_PUBLIC_PIN_CERT_FILE to enable --pin"
	}
	return "no operator-controlled pin source configured on the server"
}

// clientManifest is the response of GET /v1/clients: which client binaries
// the server serves and whether the client install is ready at all. Answers
// 200 even with a closed gate — it is the diagnostic source for which
// condition is missing.
type clientManifest struct {
	Version string   `json:"version"`
	Ready   bool     `json:"ready"`
	Missing []string `json:"missing"`
	// Pin is the SPKI pin for the login-via-IP fallback, populated only
	// from an operator-controlled source (see offeredPin). Public value: it
	// fingerprints the certificate the server presents to every TLS client
	// anyway.
	Pin string `json:"pin"`
	// PinSource is the active source (static|file|dial|""), also when no pin
	// is offered — the UI turns it into a precise explanation.
	PinSource string               `json:"pin_source"`
	Clients   []clientManifestItem `json:"clients"`
}

// clientManifestItem describes a served binary. The hash is hex and thus
// directly sha256sum-compatible (client.sh verifies with exactly that).
type clientManifestItem struct {
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// registerClientRoutes attaches the three public client routes to the
// public mux. All unauthenticated: the binary is a public artifact and the
// config values are already public via GET /v1/ui/config — access to hosts
// is gated by `gssh login` (OIDC + grants), not by binary possession.
func registerClientRoutes(mux *http.ServeMux, deps Deps) {
	gate := newClientGate(deps)

	// The manifest stays reachable (200) even with a closed gate.
	mux.HandleFunc("GET /v1/clients", deps.RateLimit.limit(handleClientManifest(gate, deps.Clients)))
	mux.HandleFunc("GET /v1/clients/{os}/{arch}",
		deps.DownloadRateLimit.limit(handleClientDownload(gate, deps.Clients, deps.Logger)))
	mux.HandleFunc("GET /client.sh",
		deps.RateLimit.limit(handleClientScript(gate, deps.Clients, deps.PublicBaseURL, deps.UIConfig, deps.Logger)))
}

// handleClientManifest returns the manifest. Version disclosure is accepted
// for the same reason as in the agent manifest: the binary is
// version-identifiable anyway (`gssh version`).
func handleClientManifest(gate clientGate, clients ClientSource) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		st := gate.status(r.Context())
		manifest := clientManifest{
			Version:   version.String(),
			Ready:     len(st.Missing) == 0,
			Missing:   st.Missing,
			Pin:       offeredPin(st.Pin),
			PinSource: st.Pin.Source,
			Clients:   clientItems(clients),
		}
		if manifest.Missing == nil {
			manifest.Missing = []string{}
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, manifest)
	}
}

// clientItems converts the embedded binaries into manifest entries.
func clientItems(clients ClientSource) []clientManifestItem {
	items := []clientManifestItem{}
	if clients == nil {
		return items
	}
	for _, info := range clients.List() {
		items = append(items, clientManifestItem{
			OS: info.OS, Arch: info.Arch, Size: info.Size, SHA256: info.SHA256,
		})
	}
	return items
}

// handleClientDownload streams a client binary. Hangs off the existing,
// tighter download limiter (shared bucket with the agent download — both
// are "a person installs once" flows).
func handleClientDownload(gate clientGate, clients ClientSource, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !gate.allow(w, r) {
			return
		}
		osName, arch := r.PathValue("os"), r.PathValue("arch")
		body, info, err := clients.Open(osName, arch)
		if err != nil {
			if !errors.Is(err, bindist.ErrNotFound) {
				logger.Error("opening client binary failed", "os", osName, "arch", arch, "error", err)
			}
			http.Error(w, "no client binary for "+osName+"/"+arch, http.StatusNotFound)
			return
		}
		defer func() { _ = body.Close() }()

		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.FormatInt(info.Size, 10))
		// no-store: a cache serving the old binary alongside the new
		// client.sh after a server upgrade produces phantom hash mismatches.
		w.Header().Set("Cache-Control", "no-store")
		if _, err := io.Copy(w, body); err != nil {
			// Headers are already out — only the log remains (aborted download).
			logger.Warn("streaming client binary aborted", "os", osName, "arch", arch, "error", err)
		}
	}
}
