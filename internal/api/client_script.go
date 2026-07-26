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

	"github.com/guided-traffic/guided-ssh/internal/version"
)

//go:embed client.sh.tmpl
var clientScriptTemplateSource string

// clientScriptTemplate is parsed at package startup; a syntax error in the
// template is a programming error and should surface immediately.
var clientScriptTemplate = template.Must(template.New("client.sh").Parse(clientScriptTemplateSource))

// osPattern is the allowed shape of the templated OS name; it ends up
// unquoted in the script's case pattern (arch and hash reuse archPattern /
// sha256Pattern from install_script.go).
var osPattern = regexp.MustCompile(`^[a-z0-9]+$`)

// clientScriptData are the values the server templates into client.sh.
// Everything the generated config needs is already fixed here — the script
// itself takes no configuration arguments.
type clientScriptData struct {
	BaseURL      string
	Version      string
	Issuer       string
	ClientID     string
	Pin          string // empty unless an operator-controlled source provides one
	PinHint      string // why no pin is available (empty when Pin is set)
	PlatformList string // space-separated "os/arch", for error messages
	Clients      []clientManifestItem
}

// handleClientScript returns the templated client.sh. With a closed gate it
// responds with 503 — there is no code path that serves a script which
// would write a config `gssh` then rejects.
func handleClientScript(gate clientGate, clients ClientSource, publicBaseURL string, uiConfig UIConfig, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		st := gate.status(r.Context())
		if len(st.Missing) > 0 {
			writeClientUnavailable(w, st.Missing)
			return
		}

		script, err := renderClientScript(clientScriptData{
			BaseURL:  publicBaseURL,
			Version:  version.String(),
			Issuer:   uiConfig.OIDCIssuer,
			ClientID: uiConfig.OIDCClientID,
			Pin:      offeredPin(st.Pin),
			PinHint:  gate.pinHint(st.Pin),
			Clients:  clientItems(clients),
		})
		if err != nil {
			logger.Error("rendering client.sh failed", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(script)
	}
}

// renderClientScript fills in the template. The templated values end up in
// the script inside single quotes and — for the config — inside double
// quotes in YAML; a quote or backslash in a value would break either, so
// this fails closed here instead of shipping a broken script.
func renderClientScript(data clientScriptData) ([]byte, error) {
	platforms := make([]string, 0, len(data.Clients))
	for _, client := range data.Clients {
		platforms = append(platforms, client.OS+"/"+client.Arch)
	}
	data.PlatformList = strings.Join(platforms, " ")

	for field, value := range map[string]string{
		"public-url": data.BaseURL, "issuer": data.Issuer, "client-id": data.ClientID,
		"pin": data.Pin, "pin-hint": data.PinHint,
		"version": data.Version, "platform-list": data.PlatformList,
	} {
		// Single quote breaks the shell quoting; double quote and backslash
		// break the double-quoted YAML scalars of the written config.
		if strings.ContainsAny(value, "'\"\\\n\r") {
			return nil, fmt.Errorf("value for %s contains a quote, backslash or line break: %q", field, value)
		}
	}
	// OS, arch and hash are build-controlled (filenames from the embed, hex
	// from sha256), but end up unquoted in the case pattern and comparison
	// value respectively — hence a strict check instead of just quotes.
	for _, client := range data.Clients {
		if !osPattern.MatchString(client.OS) {
			return nil, fmt.Errorf("os %q is not [a-z0-9]+", client.OS)
		}
		if !archPattern.MatchString(client.Arch) {
			return nil, fmt.Errorf("arch %q is not [a-z0-9]+", client.Arch)
		}
		if !sha256Pattern.MatchString(client.SHA256) {
			return nil, fmt.Errorf("sha256 for %s/%s is not a 64-digit hex value: %q", client.OS, client.Arch, client.SHA256)
		}
	}

	var buf bytes.Buffer
	if err := clientScriptTemplate.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("templating client.sh: %w", err)
	}
	return buf.Bytes(), nil
}
