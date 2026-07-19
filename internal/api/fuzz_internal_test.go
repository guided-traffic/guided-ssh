package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// FuzzDecodeSignRequest fuzzt das Parsen von Sign-Request-Bodies (JSON +
// authorized_keys-Format): darf nie panicen, und ok=true impliziert einen
// nutzbaren Public Key.
func FuzzDecodeSignRequest(f *testing.F) {
	f.Add(`{"public_key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKzs kommentar"}`)
	f.Add(`{"public_key":"kein-key","validity_seconds":3600}`)
	f.Add(`{"public_key":""}`)
	f.Add(`kein json`)
	f.Add(`{"public_key":123}`)
	f.Add(`{"validity_seconds":-9223372036854775808}`)
	f.Add(`{"public_key":"` + strings.Repeat("A", 1000) + `"}`)

	f.Fuzz(func(t *testing.T, body string) {
		r := httptest.NewRequest(http.MethodPost, "/v1/sign/user", strings.NewReader(body))
		w := httptest.NewRecorder()
		publicKey, _, ok := decodeSignRequest(w, r)
		if ok && publicKey == nil {
			t.Fatalf("ok ohne public key: %q", body)
		}
		if !ok && w.Code != http.StatusBadRequest {
			t.Fatalf("fehlerfall ohne 400 (status %d): %q", w.Code, body)
		}
	})
}

// FuzzBearerToken fuzzt die Header-Extraktion.
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
			t.Fatalf("ok mit leerem token: header %q", header)
		}
	})
}
