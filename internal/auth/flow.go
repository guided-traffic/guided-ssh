package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// ErrNoIDToken: Token-Antwort des IdP enthielt kein id_token.
var ErrNoIDToken = errors.New("auth: token-antwort enthält kein id_token")

// FlowConfig konfiguriert die CLI-Login-Flows.
type FlowConfig struct {
	// IssuerURL ist die OIDC-Issuer-URL (für Discovery).
	IssuerURL string
	// ClientID ist der öffentliche OIDC-Client der CLI.
	ClientID string
	// Scopes; Default: openid, profile, email.
	Scopes []string
}

// Flow führt die OIDC-Login-Flows der CLI aus: Authorization Code + PKCE
// (Default) und Device-Flow (Fallback ohne Browser/Localhost, z. B. via SSH
// auf einer entfernten Maschine).
type Flow struct {
	cfg      FlowConfig
	endpoint oauth2.Endpoint
}

// NewFlow lädt die Discovery des Issuers und baut den Flow.
func NewFlow(ctx context.Context, cfg FlowConfig) (*Flow, error) {
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("auth: oidc-discovery für %s: %w", cfg.IssuerURL, err)
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{oidc.ScopeOpenID, "profile", "email"}
	}
	return &Flow{cfg: cfg, endpoint: provider.Endpoint()}, nil
}

// AuthCodePKCE führt den Authorization-Code-Flow mit PKCE aus: startet einen
// Callback-Listener auf 127.0.0.1 (zufälliger Port), übergibt die
// Authorize-URL an openURL (öffnet den Browser) und tauscht den Code gegen
// Tokens. Rückgabe ist das rohe ID-Token für POST /v1/sign/user.
func (f *Flow) AuthCodePKCE(ctx context.Context, openURL func(url string) error) (string, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("auth: callback-listener starten: %w", err)
	}
	defer listener.Close()

	oauthCfg := oauth2.Config{
		ClientID:    f.cfg.ClientID,
		Endpoint:    f.endpoint,
		RedirectURL: fmt.Sprintf("http://%s/callback", listener.Addr()),
		Scopes:      f.cfg.Scopes,
	}
	state, err := randomToken()
	if err != nil {
		return "", err
	}
	verifier := oauth2.GenerateVerifier()

	type callback struct {
		code string
		err  error
	}
	callbackCh := make(chan callback, 1)
	server := &http.Server{
		ReadHeaderTimeout: 10 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/callback" {
				http.NotFound(w, r)
				return
			}
			query := r.URL.Query()
			result := callback{code: query.Get("code")}
			switch {
			case query.Get("state") != state:
				result.err = errors.New("auth: state-mismatch im callback")
			case query.Get("error") != "":
				result.err = fmt.Errorf("auth: idp-fehler: %s (%s)",
					query.Get("error"), query.Get("error_description"))
			case result.code == "":
				result.err = errors.New("auth: callback ohne code")
			}
			if result.err != nil {
				http.Error(w, "Login fehlgeschlagen — Details im Terminal.", http.StatusBadRequest)
			} else {
				fmt.Fprintln(w, "Login erfolgreich — dieses Fenster kann geschlossen werden.")
			}
			select {
			case callbackCh <- result:
			default:
			}
		}),
	}
	go func() { _ = server.Serve(listener) }()
	defer func() { _ = server.Close() }()

	authURL := oauthCfg.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))
	if err := openURL(authURL); err != nil {
		return "", fmt.Errorf("auth: browser öffnen: %w", err)
	}

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case result := <-callbackCh:
		if result.err != nil {
			return "", result.err
		}
		token, err := oauthCfg.Exchange(ctx, result.code, oauth2.VerifierOption(verifier))
		if err != nil {
			return "", fmt.Errorf("auth: code-exchange: %w", err)
		}
		return idTokenFrom(token)
	}
}

// DeviceFlow führt den Device-Authorization-Flow aus: prompt bekommt
// Verification-URI und User-Code zur Anzeige, danach wird bis zur Bestätigung
// (oder Ablauf) gepollt.
func (f *Flow) DeviceFlow(ctx context.Context, prompt func(verificationURI, userCode string)) (string, error) {
	oauthCfg := oauth2.Config{
		ClientID: f.cfg.ClientID,
		Endpoint: f.endpoint,
		Scopes:   f.cfg.Scopes,
	}
	response, err := oauthCfg.DeviceAuth(ctx)
	if err != nil {
		return "", fmt.Errorf("auth: device-authorization: %w", err)
	}
	uri := response.VerificationURIComplete
	if uri == "" {
		uri = response.VerificationURI
	}
	prompt(uri, response.UserCode)
	token, err := oauthCfg.DeviceAccessToken(ctx, response)
	if err != nil {
		return "", fmt.Errorf("auth: device-token: %w", err)
	}
	return idTokenFrom(token)
}

// ClientCredentials führt den Client-Credentials-Flow aus (Service-Account
// ohne Benutzer, z. B. der GitOps-Grants-Sync): Token-Request mit
// Client-Secret am Token-Endpoint. Rückgabe ist das rohe id_token — der IdP
// muss dem Client dafür den Scope openid ausstellen.
func (f *Flow) ClientCredentials(ctx context.Context, clientSecret string) (string, error) {
	oauthCfg := clientcredentials.Config{
		ClientID:     f.cfg.ClientID,
		ClientSecret: clientSecret,
		TokenURL:     f.endpoint.TokenURL,
		Scopes:       f.cfg.Scopes,
	}
	token, err := oauthCfg.Token(ctx)
	if err != nil {
		return "", fmt.Errorf("auth: client-credentials-token: %w", err)
	}
	return idTokenFrom(token)
}

// idTokenFrom extrahiert das rohe id_token aus der Token-Antwort.
func idTokenFrom(token *oauth2.Token) (string, error) {
	raw, ok := token.Extra("id_token").(string)
	if !ok || raw == "" {
		return "", ErrNoIDToken
	}
	return raw, nil
}

// randomToken erzeugt einen URL-sicheren Zufallswert (state-Parameter).
func randomToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
