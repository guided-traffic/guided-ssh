//go:build e2e

package e2e

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// gitlabFake hält den RSA-Schlüssel des simulierten GitLab-OIDC-Issuers.
// Discovery + JWKS liegen als statisches JSON im Cluster (nginx); die
// Job-Tokens signiert die Suite lokal — exakt das Muster des
// Phase-7-Integrationstests, nur mit In-Cluster-Issuer-URL.
type gitlabFake struct {
	issuer string
	key    *rsa.PrivateKey
}

func newGitLabFake(issuer string) (*gitlabFake, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return &gitlabFake{issuer: issuer, key: key}, nil
}

// discoveryJSON liefert das OIDC-Discovery-Dokument.
func (g *gitlabFake) discoveryJSON() string {
	doc, _ := json.Marshal(map[string]any{
		"issuer":                                g.issuer,
		"jwks_uri":                              g.issuer + "/oauth/discovery/keys",
		"authorization_endpoint":                g.issuer + "/oauth/authorize",
		"token_endpoint":                        g.issuer + "/oauth/token",
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
	return string(doc)
}

// jwksJSON liefert den öffentlichen Schlüssel als JWKS.
func (g *gitlabFake) jwksJSON() string {
	doc, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key: &g.key.PublicKey, KeyID: "gitlab-key", Algorithm: "RS256", Use: "sig",
	}}})
	return string(doc)
}

// jobToken signiert ein GitLab-Job-Token; overrides überschreibt Claims.
func (g *gitlabFake) jobToken(overrides map[string]any) (string, error) {
	claims := map[string]any{
		"iss":            g.issuer,
		"aud":            "guided-ssh",
		"sub":            "project_path:platform/deploy:ref_type:branch:ref:main",
		"iat":            time.Now().Add(-time.Minute).Unix(),
		"exp":            time.Now().Add(time.Hour).Unix(),
		"project_path":   "platform/deploy",
		"namespace_path": "platform",
		"ref":            "main",
		"ref_type":       "branch",
		"ref_protected":  "true",
		"pipeline_id":    "4711",
		"job_id":         "815",
		"user_login":     "alice",
	}
	for k, v := range overrides {
		claims[k] = v
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: g.key},
		(&jose.SignerOptions{}).WithHeader("kid", "gitlab-key"),
	)
	if err != nil {
		return "", fmt.Errorf("jose-signer: %w", err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return jws.CompactSerialize()
}
