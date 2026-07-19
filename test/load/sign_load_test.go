//go:build loadtest

// Package load enthält den Lasttest des Sign-Endpoints (Plan Phase 13).
//
// Ziel (docs/teststrategie.md): ≥ 50 Zertifikate/s über 15 s mit 16 parallelen
// Clients, fehlerfrei; gemessen gegen die echte API mit echtem Postgres
// (Testcontainer), Software-Signer und OIDC-Token-Validierung — ohne
// Rate-Limiting (das würde den Test, nicht den Server messen).
//
// Aufruf: make loadtest. Schalter: GSSH_LOAD_TARGET_RATE (Default 50),
// GSSH_LOAD_WORKERS (16), GSSH_LOAD_DURATION (15s).
package load

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"golang.org/x/crypto/ssh"

	"github.com/guided-traffic/guided-ssh/internal/api"
	"github.com/guided-traffic/guided-ssh/internal/auth"
	"github.com/guided-traffic/guided-ssh/internal/ca"
	"github.com/guided-traffic/guided-ssh/internal/store"
)

// fakeIDP ist ein minimaler OIDC-Issuer (Discovery + JWKS + RS256-Tokens).
type fakeIDP struct {
	t      *testing.T
	server *httptest.Server
	key    *rsa.PrivateKey
}

func newFakeIDP(t *testing.T) *fakeIDP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	idp := &fakeIDP{t: t, key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                idp.server.URL,
			"jwks_uri":                              idp.server.URL + "/keys",
			"authorization_endpoint":                idp.server.URL + "/auth",
			"token_endpoint":                        idp.server.URL + "/token",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("GET /keys", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key: &key.PublicKey, KeyID: "load-key", Algorithm: "RS256", Use: "sig",
		}}})
	})
	idp.server = httptest.NewServer(mux)
	t.Cleanup(idp.server.Close)
	return idp
}

// idToken signiert ein ID-Token für einen Lasttest-Benutzer.
func (idp *fakeIDP) idToken(user string) string {
	idp.t.Helper()
	payload, err := json.Marshal(map[string]any{
		"iss":                idp.server.URL,
		"aud":                "gssh-cli",
		"sub":                "sub-" + user,
		"email":              user + "@example.com",
		"preferred_username": user,
		"groups":             []string{"dev"},
		"iat":                time.Now().Add(-time.Minute).Unix(),
		"exp":                time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		idp.t.Fatal(err)
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: idp.key},
		(&jose.SignerOptions{}).WithHeader("kid", "load-key"),
	)
	if err != nil {
		idp.t.Fatal(err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		idp.t.Fatal(err)
	}
	raw, err := jws.CompactSerialize()
	if err != nil {
		idp.t.Fatal(err)
	}
	return raw
}

func TestSignEndpointLast(t *testing.T) {
	ctx := context.Background()

	// ── Postgres + Store + CA (echte Persistenz — jede Signatur schreibt
	// transaktional certificates + audit_events) ─────────────────────────
	pgCtr, err := tcpostgres.Run(ctx, "postgres:17-alpine",
		tcpostgres.WithDatabase("guidedssh"),
		tcpostgres.WithUsername("guidedssh"),
		tcpostgres.WithPassword("guidedssh"),
		tcpostgres.BasicWaitStrategies(),
	)
	if pgCtr != nil {
		t.Cleanup(func() { _ = testcontainers.TerminateContainer(pgCtr) })
	}
	if err != nil {
		t.Fatalf("postgres-container: %v", err)
	}
	dsn, err := pgCtr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx, dsn); err != nil {
		t.Fatalf("migrationen: %v", err)
	}
	st, err := store.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)

	masterKey := make([]byte, ca.MasterKeySize)
	if _, err := rand.Read(masterKey); err != nil {
		t.Fatal(err)
	}
	certAuthority, err := ca.New(st, masterKey, ca.NewPolicyEngine(ca.DefaultPolicies()))
	if err != nil {
		t.Fatal(err)
	}
	if err := certAuthority.EnsureCAKeys(ctx); err != nil {
		t.Fatal(err)
	}

	// ── Fake-IdP + echter Verifier + Grant für Gruppe dev ────────────────
	idp := newFakeIDP(t)
	verifier, err := auth.NewVerifier(ctx, auth.VerifierConfig{IssuerURL: idp.server.URL, ClientID: "gssh-cli"})
	if err != nil {
		t.Fatal(err)
	}
	group := &store.Group{Issuer: idp.server.URL, Name: "dev"}
	if err := st.CreateGroup(ctx, group); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateGrant(ctx, "loadtest", &store.AccessGrant{
		GroupID: group.ID, Principals: []string{"deploy"}, MaxValiditySeconds: 3600,
	}); err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := httptest.NewServer(api.New(api.Deps{
		CA: certAuthority, Store: st, Grants: st, Verifier: verifier, Logger: logger,
	}))
	t.Cleanup(srv.Close)

	workers := envInt("GSSH_LOAD_WORKERS", 16)
	duration := envDuration("GSSH_LOAD_DURATION", 15*time.Second)
	targetRate := envFloat("GSSH_LOAD_TARGET_RATE", 50)

	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{MaxIdleConns: workers * 2, MaxIdleConnsPerHost: workers * 2},
	}

	// Warmup: ein Request pro Worker legt Benutzer/Gruppen an und füllt
	// Verbindungs- und JWKS-Caches — zählt nicht in die Messung.
	tokens := make([]string, workers)
	bodies := make([][]byte, workers)
	for i := range tokens {
		tokens[i] = idp.idToken(fmt.Sprintf("loaduser%02d", i))
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		sshPub, err := ssh.NewPublicKey(pub)
		if err != nil {
			t.Fatal(err)
		}
		bodies[i], err = json.Marshal(map[string]any{
			"public_key":       strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))),
			"validity_seconds": 3600,
		})
		if err != nil {
			t.Fatal(err)
		}
		if status, body := signOnce(t, client, srv.URL, tokens[i], bodies[i]); status != http.StatusOK {
			t.Fatalf("warmup worker %d: status %d: %s", i, status, body)
		}
	}

	// ── Messung ──────────────────────────────────────────────────────────
	var wg sync.WaitGroup
	latencies := make([][]time.Duration, workers)
	errors := make([]int, workers)
	deadline := time.Now().Add(duration)
	start := time.Now()
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for time.Now().Before(deadline) {
				begin := time.Now()
				status, _ := signOnce(t, client, srv.URL, tokens[i], bodies[i])
				if status != http.StatusOK {
					errors[i]++
					continue
				}
				latencies[i] = append(latencies[i], time.Since(begin))
			}
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(start)

	var all []time.Duration
	totalErrors := 0
	for i := range latencies {
		all = append(all, latencies[i]...)
		totalErrors += errors[i]
	}
	sort.Slice(all, func(a, b int) bool { return all[a] < all[b] })
	rate := float64(len(all)) / elapsed.Seconds()
	t.Logf("sign/user: %d zertifikate in %s = %.1f zert/s (%d worker, %d fehler)",
		len(all), elapsed.Round(time.Millisecond), rate, workers, totalErrors)
	if len(all) > 0 {
		t.Logf("latenz: p50 %s, p95 %s, max %s",
			all[len(all)/2].Round(time.Millisecond),
			all[len(all)*95/100].Round(time.Millisecond),
			all[len(all)-1].Round(time.Millisecond))
	}

	if totalErrors > 0 {
		t.Fatalf("%d fehlgeschlagene sign-requests", totalErrors)
	}
	if rate < targetRate {
		t.Fatalf("durchsatz %.1f zert/s unter ziel %.0f zert/s", rate, targetRate)
	}
}

func signOnce(t *testing.T, client *http.Client, baseURL, token string, body []byte) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, baseURL+"/v1/sign/user", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return 0, err.Error()
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw)
}

func envInt(key string, fallback int) int {
	if v, err := strconv.Atoi(os.Getenv(key)); err == nil && v > 0 {
		return v
	}
	return fallback
}

func envFloat(key string, fallback float64) float64 {
	if v, err := strconv.ParseFloat(os.Getenv(key), 64); err == nil && v > 0 {
		return v
	}
	return fallback
}

func envDuration(key string, fallback time.Duration) time.Duration {
	if v, err := time.ParseDuration(os.Getenv(key)); err == nil && v > 0 {
		return v
	}
	return fallback
}
