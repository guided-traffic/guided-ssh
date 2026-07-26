package api_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guided-traffic/guided-ssh/internal/api"
	"github.com/guided-traffic/guided-ssh/internal/ca"
	"github.com/guided-traffic/guided-ssh/internal/store"
)

// fuzzHandler builds the complete API handler with a real CA (fakeStore)
// for the sign fuzzing targets.
func fuzzHandler(f *testing.F, deps func(*ca.CA, *slog.Logger) api.Deps) http.Handler {
	f.Helper()
	fs := newFakeAuthStore()
	masterKey := make([]byte, ca.MasterKeySize)
	certAuthority, err := ca.New(&fs.fakeStore, masterKey, ca.NewPolicyEngine(ca.DefaultPolicies()))
	if err != nil {
		f.Fatalf("ca.New: %v", err)
	}
	if err := certAuthority.EnsureCAKeys(context.Background()); err != nil {
		f.Fatalf("EnsureCAKeys: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	d := deps(certAuthority, logger)
	if d.Store == nil {
		d.Store = fs
	}
	if d.Grants == nil {
		d.Grants = fs
	}
	return api.New(d)
}

// FuzzSignUser bombards POST /v1/sign/user with arbitrary bodies and
// tokens: never panic, never 500 (bad inputs are always client errors).
func FuzzSignUser(f *testing.F) {
	handler := fuzzHandler(f, func(certAuthority *ca.CA, logger *slog.Logger) api.Deps {
		return api.Deps{
			CA:       certAuthority,
			Verifier: &fakeVerifier{token: testToken, claims: testClaims()},
			Logger:   logger,
		}
	})

	f.Add(`{"public_key":"ssh-ed25519 AAAA"}`, testToken)
	f.Add(`{"public_key":"ssh-ed25519 AAAA","validity_seconds":-1}`, testToken)
	f.Add(`not json`, "wrong-token")
	f.Add(`{"public_key":null}`, "")
	f.Add(`{}`, testToken)

	f.Fuzz(func(t *testing.T, body, token string) {
		req := httptest.NewRequest(http.MethodPost, "/v1/sign/user", strings.NewReader(body))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code == http.StatusInternalServerError {
			t.Fatalf("500 on fuzz input body=%q token=%q: %s", body, token, rec.Body.String())
		}
	})
}

// FuzzSignCI bombards POST /v1/sign/ci analogously.
func FuzzSignCI(f *testing.F) {
	handler := fuzzHandler(f, func(certAuthority *ca.CA, logger *slog.Logger) api.Deps {
		return api.Deps{
			CA:         certAuthority,
			CIVerifier: &fakeCIVerifier{token: ciTestToken, claims: ciTestClaims()},
			CIStore:    &fakeCIStore{grants: []store.CIGrant{ciTestGrant()}},
			Logger:     logger,
		}
	})

	f.Add(`{"public_key":"ssh-ed25519 AAAA"}`, ciTestToken)
	f.Add(`{"public_key":"","validity_seconds":999999999}`, ciTestToken)
	f.Add(`not json`, "wrong-token")
	f.Add(`{"public_key":"ssh-rsa AAAA"}`, "")

	f.Fuzz(func(t *testing.T, body, token string) {
		req := httptest.NewRequest(http.MethodPost, "/v1/sign/ci", strings.NewReader(body))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code == http.StatusInternalServerError {
			t.Fatalf("500 on fuzz input body=%q token=%q: %s", body, token, rec.Body.String())
		}
	})
}
