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

// ErrNoIDToken: the IdP's token response contained no id_token.
var ErrNoIDToken = errors.New("auth: token response contains no id_token")

// FlowConfig configures the CLI login flows.
type FlowConfig struct {
	// IssuerURL is the OIDC issuer URL (for discovery).
	IssuerURL string
	// ClientID is the CLI's public OIDC client.
	ClientID string
	// Scopes; default: openid, profile, email.
	Scopes []string
}

// Flow runs the CLI's OIDC login flows: Authorization Code + PKCE
// (default) and the Device Flow (fallback without a browser/localhost, e.g.
// via SSH on a remote machine).
type Flow struct {
	cfg      FlowConfig
	endpoint oauth2.Endpoint
}

// NewFlow loads the issuer's discovery document and builds the Flow.
func NewFlow(ctx context.Context, cfg FlowConfig) (*Flow, error) {
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("auth: oidc discovery for %s: %w", cfg.IssuerURL, err)
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{oidc.ScopeOpenID, "profile", "email"}
	}
	return &Flow{cfg: cfg, endpoint: provider.Endpoint()}, nil
}

// AuthCodePKCE runs the Authorization Code flow with PKCE: starts a
// callback listener on 127.0.0.1 (random port), hands the authorize URL to
// openURL (opens the browser), and exchanges the code for tokens. Returns
// the raw ID token for POST /v1/sign/user.
func (f *Flow) AuthCodePKCE(ctx context.Context, openURL func(url string) error) (string, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("auth: starting callback listener: %w", err)
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
				result.err = errors.New("auth: state mismatch in callback")
			case query.Get("error") != "":
				result.err = fmt.Errorf("auth: idp error: %s (%s)",
					query.Get("error"), query.Get("error_description"))
			case result.code == "":
				result.err = errors.New("auth: callback without code")
			}
			if result.err != nil {
				http.Error(w, "Login failed — see terminal for details.", http.StatusBadRequest)
			} else {
				fmt.Fprintln(w, "Login successful — you can close this window.")
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
		return "", fmt.Errorf("auth: opening browser: %w", err)
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
			return "", fmt.Errorf("auth: code exchange: %w", err)
		}
		return idTokenFrom(token)
	}
}

// DeviceFlow runs the Device Authorization flow: prompt receives the
// verification URI and user code to display, then polling continues until
// confirmation (or expiry).
func (f *Flow) DeviceFlow(ctx context.Context, prompt func(verificationURI, userCode string)) (string, error) {
	oauthCfg := oauth2.Config{
		ClientID: f.cfg.ClientID,
		Endpoint: f.endpoint,
		Scopes:   f.cfg.Scopes,
	}
	response, err := oauthCfg.DeviceAuth(ctx)
	if err != nil {
		return "", fmt.Errorf("auth: device authorization: %w", err)
	}
	uri := response.VerificationURIComplete
	if uri == "" {
		uri = response.VerificationURI
	}
	prompt(uri, response.UserCode)
	token, err := oauthCfg.DeviceAccessToken(ctx, response)
	if err != nil {
		return "", fmt.Errorf("auth: device token: %w", err)
	}
	return idTokenFrom(token)
}

// ClientCredentials runs the Client Credentials flow (a service account
// without a user, e.g. the GitOps grants sync): a token request with the
// client secret against the token endpoint. Returns the raw id_token — the
// IdP must issue the openid scope to the client for this to work.
func (f *Flow) ClientCredentials(ctx context.Context, clientSecret string) (string, error) {
	oauthCfg := clientcredentials.Config{
		ClientID:     f.cfg.ClientID,
		ClientSecret: clientSecret,
		TokenURL:     f.endpoint.TokenURL,
		Scopes:       f.cfg.Scopes,
	}
	token, err := oauthCfg.Token(ctx)
	if err != nil {
		return "", fmt.Errorf("auth: client-credentials token: %w", err)
	}
	return idTokenFrom(token)
}

// idTokenFrom extracts the raw id_token from the token response.
func idTokenFrom(token *oauth2.Token) (string, error) {
	raw, ok := token.Extra("id_token").(string)
	if !ok || raw == "" {
		return "", ErrNoIDToken
	}
	return raw, nil
}

// randomToken generates a URL-safe random value (state parameter).
func randomToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
