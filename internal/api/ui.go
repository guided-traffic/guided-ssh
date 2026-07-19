package api

import (
	"io/fs"
	"net/http"
	"regexp"
	"strings"
)

// hashedAsset erkennt Angular-Ausgabedateien mit Content-Hash im Namen
// (z. B. main-Q3ZUVLNB.js) — die dürfen unbegrenzt gecacht werden.
var hashedAsset = regexp.MustCompile(`-[A-Z0-9]{8,}\.[a-z0-9]+$`)

// NewUIHandler liefert den SPA-Handler über dem eingebetteten Angular-Build:
// vorhandene Dateien werden direkt ausgeliefert, alle anderen Pfade fallen
// auf index.html zurück (Client-Routing). Ohne gebaute UI (kein index.html
// im FS) antwortet der Handler mit 503, die API bleibt unberührt.
func NewUIHandler(dist fs.FS) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		if strings.HasPrefix(path, "v1/") {
			// API-Pfade fallen nie auf die SPA zurück (auch nicht als 405).
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if path == "" {
			path = "index.html"
		}
		if _, err := fs.Stat(dist, path); err != nil {
			path = "index.html"
		}
		if path == "index.html" {
			if _, err := fs.Stat(dist, "index.html"); err != nil {
				http.Error(w, "web-ui nicht gebaut (make web)", http.StatusServiceUnavailable)
				return
			}
			// index.html referenziert gehashte Assets und muss frisch bleiben.
			w.Header().Set("Cache-Control", "no-store")
		} else if hashedAsset.MatchString(path) {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}
		// G703-Falschmeldung: dist ist ein eingebettetes fs.FS (fs.ValidPath),
		// ServeFileFS lehnt ".."-Elemente in r.URL.Path ab, und path wurde per
		// fs.Stat geprüft — kein Path-Traversal möglich.
		http.ServeFileFS(w, r, dist, path) //nolint:gosec // siehe Kommentar
	})
}
