package api

import (
	"io/fs"
	"net/http"
	"regexp"
	"strings"
)

// hashedAsset recognizes Angular output files with a content hash in the
// name — those may be cached indefinitely. The builder produces two
// formats: uppercase hex (main-Q3ZUVLNB.js) and base64url (chunk-DcHW0dVi.js).
var hashedAsset = regexp.MustCompile(`-[A-Za-z0-9_-]{8,}\.[a-z0-9]+$`)

// NewUIHandler returns the SPA handler over the embedded Angular build:
// existing files are served directly, all other paths fall back to
// index.html (client routing). Without a built UI (no index.html in the
// FS), the handler responds with 503, the API stays unaffected.
func NewUIHandler(dist fs.FS) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		if strings.HasPrefix(path, "v1/") {
			// API paths never fall back to the SPA (not even as 405).
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
				http.Error(w, "web ui not built (make web)", http.StatusServiceUnavailable)
				return
			}
			// index.html references hashed assets and must stay fresh.
			w.Header().Set("Cache-Control", "no-store")
		} else if hashedAsset.MatchString(path) {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}
		// G703 false positive: dist is an embedded fs.FS (fs.ValidPath),
		// ServeFileFS rejects ".." elements in r.URL.Path, and path was
		// checked via fs.Stat — no path traversal possible.
		http.ServeFileFS(w, r, dist, path) //nolint:gosec // see comment
	})
}
