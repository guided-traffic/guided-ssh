package api_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/guided-traffic/guided-ssh/internal/api"
)

// uiDist is a built Angular dist as an in-memory FS.
var uiDist = fstest.MapFS{
	"index.html":        {Data: []byte("<html>guided-ssh ui</html>")},
	"main-Q3ZUVLNB.js":  {Data: []byte("console.log('app')")},
	"chunk-DcHW0dVi.js": {Data: []byte("console.log('chunk')")},
}

func TestUIHandlerServesFilesAndFallback(t *testing.T) {
	handler := api.NewUIHandler(uiDist)

	cases := []struct {
		name, path   string
		wantStatus   int
		wantBody     string
		wantCacheHas string
	}{
		{"index under /", "/", http.StatusOK, "guided-ssh ui", "no-store"},
		{"hashed asset immutable", "/main-Q3ZUVLNB.js", http.StatusOK, "console.log", "immutable"},
		{"base64url hash immutable", "/chunk-DcHW0dVi.js", http.StatusOK, "console.log", "immutable"},
		{"spa fallback on client route", "/audit", http.StatusOK, "guided-ssh ui", "no-store"},
		{"deep client route", "/hosts/detail/42", http.StatusOK, "guided-ssh ui", "no-store"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, nil))
			if rec.Code != tc.wantStatus {
				t.Fatalf("status %d, expected %d", rec.Code, tc.wantStatus)
			}
			if !strings.Contains(rec.Body.String(), tc.wantBody) {
				t.Errorf("body %q does not contain %q", rec.Body.String(), tc.wantBody)
			}
			if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, tc.wantCacheHas) {
				t.Errorf("cache-control %q, expected %q", cc, tc.wantCacheHas)
			}
		})
	}
}

func TestUIHandlerEdgeCases(t *testing.T) {
	handler := api.NewUIHandler(uiDist)

	// API paths never fall back to the SPA.
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/unknown", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("status %d, expected 404 for /v1/ path", rec.Code)
	}

	// Only GET/HEAD.
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status %d, expected 405 for POST", rec.Code)
	}

	// Without a built UI (no index.html) ⇒ 503, API stays unaffected.
	empty := api.NewUIHandler(fstest.MapFS{".gitkeep": {Data: []byte{}}})
	rec = httptest.NewRecorder()
	empty.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status %d, expected 503 without a build", rec.Code)
	}
}
