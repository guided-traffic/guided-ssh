package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// FuzzDecodeSignRequest fuzzes parsing of sign request bodies (JSON +
// authorized_keys format): must never panic, and ok=true implies a usable
// public key.
func FuzzDecodeSignRequest(f *testing.F) {
	f.Add(`{"public_key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKzs comment"}`)
	f.Add(`{"public_key":"not-a-key","validity_seconds":3600}`)
	f.Add(`{"public_key":""}`)
	f.Add(`not json`)
	f.Add(`{"public_key":123}`)
	f.Add(`{"validity_seconds":-9223372036854775808}`)
	f.Add(`{"public_key":"` + strings.Repeat("A", 1000) + `"}`)

	f.Fuzz(func(t *testing.T, body string) {
		r := httptest.NewRequest(http.MethodPost, "/v1/sign/user", strings.NewReader(body))
		w := httptest.NewRecorder()
		publicKey, _, ok := decodeSignRequest(w, r)
		if ok && publicKey == nil {
			t.Fatalf("ok without public key: %q", body)
		}
		if !ok && w.Code != http.StatusBadRequest {
			t.Fatalf("error case without 400 (status %d): %q", w.Code, body)
		}
	})
}

// FuzzBearerToken fuzzes header extraction.
func FuzzBearerToken(f *testing.F) {
	f.Add("Bearer token123")
	f.Add("bearer token123")
	f.Add("Basic dXNlcjpwYXNz")
	f.Add("Bearer ")
	f.Add("")
	f.Add("Bearer a b c")

	f.Fuzz(func(t *testing.T, header string) {
		r := httptest.NewRequest(http.MethodPost, "/", nil)
		r.Header.Set("Authorization", header)
		token, ok := bearerToken(r)
		if ok && token == "" {
			t.Fatalf("ok with empty token: header %q", header)
		}
	})
}
