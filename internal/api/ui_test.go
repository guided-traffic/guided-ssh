package api_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/guided-traffic/guided-ssh/internal/api"
)

// uiDist ist ein gebauter Angular-Dist als In-Memory-FS.
var uiDist = fstest.MapFS{
	"index.html":       {Data: []byte("<html>guided-ssh ui</html>")},
	"main-Q3ZUVLNB.js": {Data: []byte("console.log('app')")},
}

func TestUIHandlerServiertDateienUndFallback(t *testing.T) {
	handler := api.NewUIHandler(uiDist)

	cases := []struct {
		name, path   string
		wantStatus   int
		wantBody     string
		wantCacheHas string
	}{
		{"index unter /", "/", http.StatusOK, "guided-ssh ui", "no-store"},
		{"gehashtes asset immutable", "/main-Q3ZUVLNB.js", http.StatusOK, "console.log", "immutable"},
		{"spa-fallback auf client-route", "/audit", http.StatusOK, "guided-ssh ui", "no-store"},
		{"tiefe client-route", "/hosts/detail/42", http.StatusOK, "guided-ssh ui", "no-store"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, nil))
			if rec.Code != tc.wantStatus {
				t.Fatalf("status %d, erwartet %d", rec.Code, tc.wantStatus)
			}
			if !strings.Contains(rec.Body.String(), tc.wantBody) {
				t.Errorf("body %q enthält nicht %q", rec.Body.String(), tc.wantBody)
			}
			if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, tc.wantCacheHas) {
				t.Errorf("cache-control %q, erwartet %q", cc, tc.wantCacheHas)
			}
		})
	}
}

func TestUIHandlerGrenzfaelle(t *testing.T) {
	handler := api.NewUIHandler(uiDist)

	// API-Pfade fallen nie auf die SPA zurück.
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/unbekannt", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("status %d, erwartet 404 für /v1/-Pfad", rec.Code)
	}

	// Nur GET/HEAD.
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status %d, erwartet 405 für POST", rec.Code)
	}

	// Ohne gebaute UI (kein index.html) ⇒ 503, API bleibt unberührt.
	empty := api.NewUIHandler(fstest.MapFS{".gitkeep": {Data: []byte{}}})
	rec = httptest.NewRecorder()
	empty.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status %d, erwartet 503 ohne build", rec.Code)
	}
}
