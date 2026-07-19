package auth_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// fakeIDP ist ein minimaler OIDC-Provider für Unit-Tests: Discovery, JWKS,
// Authorize (leitet sofort mit Code zurück), Token- und Device-Endpoint.
type fakeIDP struct {
	t      *testing.T
	server *httptest.Server
	key    *rsa.PrivateKey

	// deviceStillPending zählt, wie oft der Token-Endpoint im Device-Flow
	// noch "authorization_pending" liefern soll.
	deviceStillPending atomic.Int32
	// lastCodeVerifier ist der zuletzt beim Code-Exchange gesehene
	// PKCE-Verifier.
	lastCodeVerifier atomic.Value
}

const (
	fakeClientID     = "gssh-cli"
	fakeClientSecret = "test-client-secret"
	fakeAuthCode     = "test-auth-code"
	fakeDeviceCode   = "test-device-code"
	fakeUserCode     = "ABCD-EFGH"
)

// newFakeIDP startet den Fake-IdP; Cleanup übernimmt t.
func newFakeIDP(t *testing.T) *fakeIDP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa-key erzeugen: %v", err)
	}
	idp := &fakeIDP{t: t, key: key}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, map[string]any{
			"issuer":                                idp.Issuer(),
			"authorization_endpoint":                idp.Issuer() + "/auth",
			"token_endpoint":                        idp.Issuer() + "/token",
			"jwks_uri":                              idp.Issuer() + "/keys",
			"device_authorization_endpoint":         idp.Issuer() + "/device",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("GET /keys", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key: &key.PublicKey, KeyID: "test-key", Algorithm: "RS256", Use: "sig",
		}}})
	})
	mux.HandleFunc("GET /auth", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		redirect, err := url.Parse(q.Get("redirect_uri"))
		if err != nil {
			http.Error(w, "redirect_uri fehlt", http.StatusBadRequest)
			return
		}
		values := redirect.Query()
		values.Set("code", fakeAuthCode)
		values.Set("state", q.Get("state"))
		redirect.RawQuery = values.Encode()
		http.Redirect(w, r, redirect.String(), http.StatusFound)
	})
	mux.HandleFunc("POST /device", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, map[string]any{
			"device_code":               fakeDeviceCode,
			"user_code":                 fakeUserCode,
			"verification_uri":          idp.Issuer() + "/verify",
			"verification_uri_complete": idp.Issuer() + "/verify?user_code=" + fakeUserCode,
			"expires_in":                300,
			"interval":                  1,
		})
	})
	mux.HandleFunc("POST /token", idp.handleToken)

	idp.server = httptest.NewServer(mux)
	t.Cleanup(idp.server.Close)
	return idp
}

func (idp *fakeIDP) Issuer() string { return idp.server.URL }

// handleToken bedient Code-Exchange und Device-Flow-Polling.
func (idp *fakeIDP) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form ungültig", http.StatusBadRequest)
		return
	}
	switch r.Form.Get("grant_type") {
	case "authorization_code":
		if r.Form.Get("code") != fakeAuthCode {
			http.Error(w, "code ungültig", http.StatusBadRequest)
			return
		}
		idp.lastCodeVerifier.Store(r.Form.Get("code_verifier"))
	case "urn:ietf:params:oauth:grant-type:device_code":
		if r.Form.Get("device_code") != fakeDeviceCode {
			http.Error(w, "device_code ungültig", http.StatusBadRequest)
			return
		}
		if idp.deviceStillPending.Add(-1) >= 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"authorization_pending"}`)
			return
		}
	case "client_credentials":
		id, secret, ok := r.BasicAuth()
		if !ok {
			id, secret = r.Form.Get("client_id"), r.Form.Get("client_secret")
		}
		if id != fakeClientID || secret != fakeClientSecret {
			http.Error(w, "client-credentials ungültig", http.StatusUnauthorized)
			return
		}
	default:
		http.Error(w, "grant_type nicht unterstützt", http.StatusBadRequest)
		return
	}
	writeJSON(idp.t, w, map[string]any{
		"access_token": "test-access-token",
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     idp.IDToken(map[string]any{"sub": "flow-user"}),
	})
}

// IDToken signiert ein ID-Token mit Standard-Claims; overrides überschreibt
// bzw. ergänzt einzelne Claims (Wert nil entfernt den Claim).
func (idp *fakeIDP) IDToken(overrides map[string]any) string {
	idp.t.Helper()
	claims := map[string]any{
		"iss": idp.Issuer(),
		"aud": fakeClientID,
		"sub": "user-1",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Add(-time.Minute).Unix(),
	}
	for k, v := range overrides {
		if v == nil {
			delete(claims, k)
			continue
		}
		claims[k] = v
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		idp.t.Fatalf("claims marshalen: %v", err)
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: idp.key},
		(&jose.SignerOptions{}).WithHeader("kid", "test-key"),
	)
	if err != nil {
		idp.t.Fatalf("signer bauen: %v", err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		idp.t.Fatalf("token signieren: %v", err)
	}
	raw, err := jws.CompactSerialize()
	if err != nil {
		idp.t.Fatalf("token serialisieren: %v", err)
	}
	return raw
}

func writeJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Errorf("json schreiben: %v", err)
	}
}
