//go:build integration

// Integration tests for self-managed CA mode (SELF_MANAGED_CA.md, Phase 3):
// the full issue path on mounted key files, the managed → self-managed
// switchover on an existing database, and the "database is derived state"
// success criterion. They wire a real *store.Store into ca.New exactly like
// cmd/gssh-server setup() does and reuse the container harness of
// store_integration_test.go.

package store_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/guided-traffic/guided-ssh/internal/api"
	"github.com/guided-traffic/guided-ssh/internal/auth"
	"github.com/guided-traffic/guided-ssh/internal/ca"
	"github.com/guided-traffic/guided-ssh/internal/store"
)

const (
	selfManagedIssuer  = "https://idp.example.test/realms/gssh"
	selfManagedSubject = "alice-id"
	selfManagedUser    = "alice"
	selfManagedToken   = "self-managed-integration-token" //#nosec G101 -- test value, not a credential
)

// ── helpers ─────────────────────────────────────────────────────────────────

// newMasterKey returns a random GSSH_CA_MASTER_KEY. In self-managed mode it is
// never used for CA material, but ca.New still demands a well-formed key (D7).
func newMasterKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, ca.MasterKeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate master key: %v", err)
	}
	return key
}

// writeExternalCAFiles generates a complete set of self-managed CA material
// (SSH user CA, SSH host CA, agent mTLS CA) into a fresh temp dir — the files
// an operator keeps SOPS-encrypted in Git and mounts as a Secret (D3).
func writeExternalCAFiles(t *testing.T) ca.ExternalKeyPaths {
	t.Helper()
	dir := t.TempDir()
	paths := ca.ExternalKeyPaths{
		UserKeyFile:  filepath.Join(dir, "user-ca"),
		HostKeyFile:  filepath.Join(dir, "host-ca"),
		MTLSKeyFile:  filepath.Join(dir, "mtls-ca.key"),
		MTLSCertFile: filepath.Join(dir, "mtls-ca.crt"),
	}
	writeSSHCAKeyFile(t, paths.UserKeyFile)
	writeSSHCAKeyFile(t, paths.HostKeyFile)
	certPEM, keyPEM, err := ca.GenerateMTLSCA()
	if err != nil {
		t.Fatalf("generate mtls ca: %v", err)
	}
	writeTestFile(t, paths.MTLSKeyFile, keyPEM)
	writeTestFile(t, paths.MTLSCertFile, certPEM)
	return paths
}

// writeSSHCAKeyFile writes an unencrypted OpenSSH private key PEM, the format
// ssh-keygen produces for an ed25519 key without passphrase.
func writeSSHCAKeyFile(t *testing.T, path string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ssh ca key: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "guided-ssh integration test ca")
	if err != nil {
		t.Fatalf("marshal ssh ca key: %v", err)
	}
	writeTestFile(t, path, pem.EncodeToMemory(block))
}

func writeTestFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// newSelfManagedCA loads the mounted key files and adopts them into the real
// store — the self-managed branch of cmd/gssh-server setup().
func newSelfManagedCA(t *testing.T, paths ca.ExternalKeyPaths, masterKey []byte) (*ca.CA, *ca.ExternalKeys) {
	t.Helper()
	keys, err := ca.LoadExternalKeys(paths)
	if err != nil {
		t.Fatalf("LoadExternalKeys: %v", err)
	}
	certAuthority, err := ca.New(testStore, masterKey, ca.NewPolicyEngine(ca.DefaultPolicies()), ca.WithExternalKeys(keys))
	if err != nil {
		t.Fatalf("ca.New: %v", err)
	}
	if !certAuthority.SelfManaged() {
		t.Fatal("WithExternalKeys did not put the ca into self-managed mode")
	}
	if err := certAuthority.AdoptExternalKeys(context.Background()); err != nil {
		t.Fatalf("AdoptExternalKeys: %v", err)
	}
	return certAuthority, keys
}

// countStoredPrivateKeys counts ca_keys rows that still carry key material —
// the number self-managed mode must keep at zero.
func countStoredPrivateKeys(t *testing.T) int {
	t.Helper()
	var n int
	if err := rawPool.QueryRow(context.Background(),
		`SELECT count(*) FROM ca_keys WHERE encrypted_private_key IS NOT NULL`).Scan(&n); err != nil {
		t.Fatalf("count ca_keys with private key: %v", err)
	}
	return n
}

// userCertRequest builds a policy-conforming user certificate request.
func userCertRequest(t *testing.T) ca.CertRequest {
	t.Helper()
	validAfter := time.Now().Add(-time.Minute)
	return ca.CertRequest{
		CertType:    store.CertTypeUser,
		PublicKey:   newCertSubjectKey(t),
		KeyID:       ca.UserKeyID(selfManagedSubject, selfManagedIssuer),
		Principals:  []string{selfManagedUser},
		ValidAfter:  validAfter,
		ValidBefore: validAfter.Add(time.Hour),
		Extensions:  map[string]string{"permit-pty": ""},
	}
}

// assertCertTrustedByBundle checks a certificate the way a host does: the
// signing CA must be one of the bundle's public keys and the signature,
// validity window and principal must hold.
func assertCertTrustedByBundle(t *testing.T, bundle string, cert *ssh.Certificate) {
	t.Helper()
	trusted := map[string]bool{}
	for _, line := range strings.Split(bundle, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			trusted[line] = true
		}
	}
	checker := &ssh.CertChecker{
		IsUserAuthority: func(authority ssh.PublicKey) bool { return trusted[authorizedKey(authority)] },
	}
	if !checker.IsUserAuthority(cert.SignatureKey) {
		t.Errorf("signing ca %q is not in the bundle:\n%s", authorizedKey(cert.SignatureKey), bundle)
	}
	if err := checker.CheckCert(selfManagedUser, cert); err != nil {
		t.Errorf("certificate does not verify: %v", err)
	}
}

// parseSSHCertificate parses an authorized_keys line into a certificate.
func parseSSHCertificate(t *testing.T, encoded string) *ssh.Certificate {
	t.Helper()
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(encoded))
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	cert, ok := parsed.(*ssh.Certificate)
	if !ok {
		t.Fatalf("not a certificate: %T", parsed)
	}
	return cert
}

// staticTokenVerifier accepts exactly one bearer token and returns fixed claims
// — stands in for the OIDC provider, everything behind it is the real thing.
type staticTokenVerifier struct{}

func (v *staticTokenVerifier) Verify(_ context.Context, rawToken string) (*auth.Claims, error) {
	if rawToken != selfManagedToken {
		return nil, fmt.Errorf("%w: unknown token", auth.ErrInvalidToken)
	}
	return &auth.Claims{
		Issuer:            selfManagedIssuer,
		Subject:           selfManagedSubject,
		Email:             "alice@example.test",
		PreferredUsername: selfManagedUser,
		Groups:            []string{"ops"},
	}, nil
}

func httpGet(t *testing.T, url string) (int, []byte) {
	t.Helper()
	resp, err := http.Get(url) //nolint:gosec // test url from httptest
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body of %s: %v", url, err)
	}
	return resp.StatusCode, body
}

func httpPost(t *testing.T, url, bearer string, body []byte) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build request for %s: %v", url, err)
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body of %s: %v", url, err)
	}
	return resp.StatusCode, raw
}

// newEnrollBody builds a valid POST /v1/enroll body (host key + mTLS CSR).
func newEnrollBody(t *testing.T, token, hostname string) []byte {
	t.Helper()
	_, csrPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate csr key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, csrPriv)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}
	body, err := json.Marshal(map[string]any{
		"token":          token,
		"hostname":       hostname,
		"ssh_public_key": newSSHPublicKey(t),
		"mtls_csr":       string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})),
	})
	if err != nil {
		t.Fatalf("marshal enroll body: %v", err)
	}
	return body
}

// ── Phase 3, bullet 3: full issue path in self-managed mode ─────────────────

// TestSelfManagedCAFullIssuePath mirrors the managed-mode coverage of the API
// handlers (internal/api/*_test.go), but against a real database and with all
// CA material coming from mounted files: user certificate, host enrollment
// with host and agent mTLS certificate, and both CA bundle endpoints.
func TestSelfManagedCAFullIssuePath(t *testing.T) {
	cleanDB(t)
	ctx := context.Background()

	paths := writeExternalCAFiles(t)
	certAuthority, keys := newSelfManagedCA(t, paths, newMasterKey(t))
	userCAKey := keys.User.Signer.PublicKey()
	hostCAKey := keys.Host.Signer.PublicKey()

	// Adoption produced exactly one active, private-key-free row per purpose.
	for _, purpose := range []string{store.CertTypeUser, store.CertTypeHost, store.CAPurposeMTLS} {
		rows, err := testStore.ListCAKeys(ctx, purpose)
		mustNoErr(t, err)
		if len(rows) != 1 {
			t.Fatalf("purpose %q: %d ca_keys rows, want 1", purpose, len(rows))
		}
		if rows[0].State != store.CAKeyStateActive {
			t.Errorf("purpose %q: state = %q, want active", purpose, rows[0].State)
		}
	}
	// Each first adoption is audited (ca.key_adopted, SELF_MANAGED_CA.md D4).
	adoptions, err := testStore.ListAuditEvents(ctx, store.AuditFilter{EventType: ca.EventKeyAdopted})
	mustNoErr(t, err)
	if len(adoptions) != 3 {
		t.Errorf("%d %s audit events, want 3", len(adoptions), ca.EventKeyAdopted)
	}

	// Access rules for the signing user — real store, no fakes.
	ops := &store.Group{Issuer: selfManagedIssuer, Name: "ops"}
	mustNoErr(t, testStore.CreateGroup(ctx, ops))
	mustNoErr(t, testStore.CreateGrant(ctx, "test", &store.AccessGrant{
		GroupID: ops.ID, Principals: []string{"deploy"}, MaxValiditySeconds: 3600,
	}))

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := httptest.NewServer(api.New(api.Deps{
		CA: certAuthority, Store: testStore, Hosts: testStore, Grants: testStore,
		Verifier: &staticTokenVerifier{}, Logger: logger,
	}))
	t.Cleanup(srv.Close)

	t.Run("user certificate is signed by the mounted user ca", func(t *testing.T) {
		body, err := json.Marshal(map[string]any{
			"public_key":       newSSHPublicKey(t),
			"validity_seconds": 3600,
		})
		mustNoErr(t, err)
		status, raw := httpPost(t, srv.URL+"/v1/sign/user", selfManagedToken, body)
		if status != http.StatusOK {
			t.Fatalf("POST /v1/sign/user: status %d: %s", status, raw)
		}
		var resp struct {
			Certificate string   `json:"certificate"`
			Serial      int64    `json:"serial"`
			Principals  []string `json:"principals"`
		}
		if err := json.Unmarshal(raw, &resp); err != nil {
			t.Fatalf("decode response: %v", err)
		}

		cert := parseSSHCertificate(t, resp.Certificate)
		if cert.CertType != ssh.UserCert {
			t.Errorf("cert type = %d, want user certificate", cert.CertType)
		}
		if !bytes.Equal(cert.SignatureKey.Marshal(), userCAKey.Marshal()) {
			t.Error("certificate was not signed by the mounted user ca key")
		}
		bundle, err := certAuthority.Bundle(ctx, store.CertTypeUser)
		mustNoErr(t, err)
		assertCertTrustedByBundle(t, bundle, cert)

		// The persisted record points at the adopted, key-less ca_keys row.
		record, err := testStore.GetCertificateBySerial(ctx, resp.Serial)
		mustNoErr(t, err)
		adopted, err := testStore.GetCAKey(ctx, record.CAKeyID)
		mustNoErr(t, err)
		if adopted.PublicKey != authorizedKey(userCAKey) {
			t.Errorf("certificate references ca key %q, want the mounted user ca", adopted.PublicKey)
		}
		if adopted.EncryptedPrivateKey != nil {
			t.Error("referenced ca_keys row carries private key material")
		}
	})

	t.Run("host enrollment issues host and agent mtls certificates", func(t *testing.T) {
		token := "gssh-et-self-managed"
		hash := sha256.Sum256([]byte(token))
		mustNoErr(t, testStore.CreateEnrollmentToken(ctx, &store.EnrollmentToken{
			TokenHash: hash[:],
			Tags:      map[string]string{"env": "prod"},
			ExpiresAt: time.Now().Add(time.Hour),
		}))

		status, raw := httpPost(t, srv.URL+"/v1/enroll", "", newEnrollBody(t, token, "web1.example.test"))
		if status != http.StatusOK {
			t.Fatalf("POST /v1/enroll: status %d: %s", status, raw)
		}
		var resp struct {
			HostID          string `json:"host_id"`
			HostCertificate string `json:"host_certificate"`
			UserCABundle    string `json:"user_ca_bundle"`
			MTLSCertificate string `json:"mtls_certificate"`
			MTLSCA          string `json:"mtls_ca"`
		}
		if err := json.Unmarshal(raw, &resp); err != nil {
			t.Fatalf("decode response: %v", err)
		}

		// Host certificate: signed by the mounted host CA.
		hostCert := parseSSHCertificate(t, resp.HostCertificate)
		if hostCert.CertType != ssh.HostCert {
			t.Errorf("cert type = %d, want host certificate", hostCert.CertType)
		}
		if !bytes.Equal(hostCert.SignatureKey.Marshal(), hostCAKey.Marshal()) {
			t.Error("host certificate was not signed by the mounted host ca key")
		}
		if want := authorizedKey(userCAKey) + "\n"; resp.UserCABundle != want {
			t.Errorf("user_ca_bundle = %q, want %q", resp.UserCABundle, want)
		}

		// Agent mTLS certificate: chains to the mounted mTLS CA, CN = host id.
		block, _ := pem.Decode([]byte(resp.MTLSCertificate))
		if block == nil {
			t.Fatalf("mtls_certificate is not pem: %q", resp.MTLSCertificate)
		}
		mtlsCert, err := x509.ParseCertificate(block.Bytes)
		mustNoErr(t, err)
		if mtlsCert.Subject.CommonName != resp.HostID {
			t.Errorf("mtls cn = %q, host id = %q", mtlsCert.Subject.CommonName, resp.HostID)
		}
		pool := x509.NewCertPool()
		pool.AddCert(keys.MTLS.Certificate)
		if _, err := mtlsCert.Verify(x509.VerifyOptions{
			Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}); err != nil {
			t.Errorf("agent certificate does not chain to the mounted mtls ca: %v", err)
		}
		if resp.MTLSCA != keys.MTLS.CertPEM {
			t.Error("mtls_ca is not the mounted ca certificate")
		}

		// The host really landed in the database, with the token's tags.
		host, err := testStore.GetHostByName(ctx, "web1.example.test")
		mustNoErr(t, err)
		tags, err := testStore.GetHostTags(ctx, host.ID)
		mustNoErr(t, err)
		if tags["env"] != "prod" {
			t.Errorf("host tags = %v, want env=prod", tags)
		}
	})

	t.Run("ca bundle endpoints serve the mounted public keys", func(t *testing.T) {
		for purpose, want := range map[string]string{
			store.CertTypeUser: authorizedKey(userCAKey) + "\n",
			store.CertTypeHost: authorizedKey(hostCAKey) + "\n",
		} {
			status, raw := httpGet(t, srv.URL+"/v1/ca/bundle/"+purpose)
			if status != http.StatusOK {
				t.Fatalf("GET /v1/ca/bundle/%s: status %d", purpose, status)
			}
			if string(raw) != want {
				t.Errorf("GET /v1/ca/bundle/%s = %q, want %q", purpose, raw, want)
			}
			bundle, err := certAuthority.Bundle(ctx, purpose)
			mustNoErr(t, err)
			if bundle != want {
				t.Errorf("Bundle(%q) = %q, want %q", purpose, bundle, want)
			}
		}
		mtlsPEM, err := certAuthority.MTLSCAPEM(ctx)
		mustNoErr(t, err)
		if mtlsPEM != keys.MTLS.CertPEM {
			t.Error("MTLSCAPEM does not return the mounted ca certificate")
		}
	})

	// Success criterion (SELF_MANAGED_CA.md): after the complete issue path no
	// row in ca_keys carries private key material.
	if n := countStoredPrivateKeys(t); n != 0 {
		t.Errorf("%d ca_keys rows carry encrypted_private_key, want 0 in self-managed mode", n)
	}
}

// ── Phase 3, bullet 4: managed → self-managed switchover ────────────────────

// TestManagedToSelfManagedSwitchover boots a database in managed mode, issues a
// certificate, and then restarts "the server" in self-managed mode with freshly
// generated mounted keys against the very same database.
func TestManagedToSelfManagedSwitchover(t *testing.T) {
	cleanDB(t)
	ctx := context.Background()
	masterKey := newMasterKey(t)

	// ── managed bootstrap ────────────────────────────────────────────────
	managed, err := ca.New(testStore, masterKey, ca.NewPolicyEngine(ca.DefaultPolicies()))
	mustNoErr(t, err)
	mustNoErr(t, managed.EnsureCAKeys(ctx))
	mustNoErr(t, managed.EnsureMTLSCA(ctx))

	legacyCert, _, err := managed.Issue(ctx, ca.RequesterUser, userCertRequest(t), ca.IssueRef{Actor: "test"})
	mustNoErr(t, err)

	managedKeys := map[string]store.CAKey{}
	for _, purpose := range []string{store.CertTypeUser, store.CertTypeHost, store.CAPurposeMTLS} {
		rows, err := testStore.ListCAKeys(ctx, purpose)
		mustNoErr(t, err)
		if len(rows) != 1 {
			t.Fatalf("managed bootstrap, purpose %q: %d ca_keys rows, want 1", purpose, len(rows))
		}
		if rows[0].EncryptedPrivateKey == nil {
			t.Fatalf("managed %s key has no encrypted private key", purpose)
		}
		managedKeys[purpose] = rows[0]
	}

	// ── restart in self-managed mode against the same database ───────────
	paths := writeExternalCAFiles(t)
	selfManaged, keys := newSelfManagedCA(t, paths, masterKey)
	mountedUserCA := authorizedKey(keys.User.Signer.PublicKey())

	for purpose, old := range managedKeys {
		state, hasPrivateKey := caKeyRow(t, old.ID)
		if state != store.CAKeyStateRetiring {
			t.Errorf("managed %s key: state = %q, want retiring after the switchover", purpose, state)
		}
		// The old rows keep their key material; only new rows are key-less.
		if !hasPrivateKey {
			t.Errorf("managed %s key lost its encrypted_private_key", purpose)
		}

		rows, err := testStore.ListCAKeys(ctx, purpose)
		mustNoErr(t, err)
		if len(rows) != 2 {
			t.Fatalf("purpose %q: %d ca_keys rows after the switchover, want 2", purpose, len(rows))
		}
		for _, row := range rows {
			if row.ID == old.ID {
				continue
			}
			if row.State != store.CAKeyStateActive {
				t.Errorf("adopted %s key: state = %q, want active", purpose, row.State)
			}
			if row.EncryptedPrivateKey != nil {
				t.Errorf("adopted %s key carries private key material", purpose)
			}
		}
	}

	// The bundle carries both public keys during the transition, so hosts keep
	// trusting certificates issued before the switch.
	bundle, err := selfManaged.Bundle(ctx, store.CertTypeUser)
	mustNoErr(t, err)
	if !strings.Contains(bundle, managedKeys[store.CertTypeUser].PublicKey) {
		t.Errorf("bundle lost the previous managed user ca key:\n%s", bundle)
	}
	if !strings.Contains(bundle, mountedUserCA) {
		t.Errorf("bundle does not contain the mounted user ca key:\n%s", bundle)
	}
	if lines := strings.Split(strings.TrimSpace(bundle), "\n"); len(lines) != 2 {
		t.Errorf("bundle has %d keys, want 2:\n%s", len(lines), bundle)
	}
	assertCertTrustedByBundle(t, bundle, legacyCert)

	// New certificates come from the mounted key.
	fresh, _, err := selfManaged.Issue(ctx, ca.RequesterUser, userCertRequest(t), ca.IssueRef{Actor: "test"})
	mustNoErr(t, err)
	if authorizedKey(fresh.SignatureKey) != mountedUserCA {
		t.Error("certificate issued after the switchover was not signed by the mounted key")
	}
	assertCertTrustedByBundle(t, bundle, fresh)
}

// ── Success criterion: the database is derived state ────────────────────────

// TestSelfManagedCADatabaseIsDerivedState wipes ca_keys and re-adopts the very
// same mounted key files: the bundles must be byte-identical and certificates
// issued before the wipe must still verify — Git is the source of truth, the
// database only derived state (SELF_MANAGED_CA.md, D1).
func TestSelfManagedCADatabaseIsDerivedState(t *testing.T) {
	cleanDB(t)
	ctx := context.Background()
	masterKey := newMasterKey(t)

	paths := writeExternalCAFiles(t)
	before, _ := newSelfManagedCA(t, paths, masterKey)

	userBundleBefore, err := before.Bundle(ctx, store.CertTypeUser)
	mustNoErr(t, err)
	hostBundleBefore, err := before.Bundle(ctx, store.CertTypeHost)
	mustNoErr(t, err)
	mtlsPEMBefore, err := before.MTLSCAPEM(ctx)
	mustNoErr(t, err)

	cert, _, err := before.Issue(ctx, ca.RequesterUser, userCertRequest(t), ca.IssueRef{Actor: "test"})
	mustNoErr(t, err)

	rowsBefore := map[string]store.CAKey{}
	for _, purpose := range []string{store.CertTypeUser, store.CertTypeHost, store.CAPurposeMTLS} {
		list, err := testStore.ListCAKeys(ctx, purpose)
		mustNoErr(t, err)
		if len(list) != 1 {
			t.Fatalf("purpose %q: %d ca_keys rows, want 1", purpose, len(list))
		}
		rowsBefore[purpose] = list[0]
	}

	// Total loss of the database — the mounted files are untouched.
	cleanDB(t)

	// A restarted process re-reads the same files and re-adopts them.
	after, reloaded := newSelfManagedCA(t, paths, masterKey)

	userBundleAfter, err := after.Bundle(ctx, store.CertTypeUser)
	mustNoErr(t, err)
	hostBundleAfter, err := after.Bundle(ctx, store.CertTypeHost)
	mustNoErr(t, err)
	mtlsPEMAfter, err := after.MTLSCAPEM(ctx)
	mustNoErr(t, err)

	if userBundleAfter != userBundleBefore {
		t.Errorf("user bundle changed after the wipe:\n%q\nvs\n%q", userBundleAfter, userBundleBefore)
	}
	if hostBundleAfter != hostBundleBefore {
		t.Errorf("host bundle changed after the wipe:\n%q\nvs\n%q", hostBundleAfter, hostBundleBefore)
	}
	if mtlsPEMAfter != mtlsPEMBefore || mtlsPEMAfter != reloaded.MTLS.CertPEM {
		t.Error("mtls ca certificate changed after the wipe")
	}

	// A certificate issued before the wipe is still trusted by the new bundle.
	assertCertTrustedByBundle(t, userBundleAfter, cert)

	// The rows themselves are new — identity comes from the files, not the DB.
	for purpose, old := range rowsBefore {
		list, err := testStore.ListCAKeys(ctx, purpose)
		mustNoErr(t, err)
		if len(list) != 1 {
			t.Fatalf("purpose %q: %d ca_keys rows after re-adoption, want 1", purpose, len(list))
		}
		if list[0].ID == old.ID {
			t.Errorf("purpose %q: row id survived the wipe (%s) — test did not wipe ca_keys", purpose, old.ID)
		}
		if list[0].PublicKey != old.PublicKey {
			t.Errorf("purpose %q: re-adopted public key differs from the original", purpose)
		}
		if list[0].State != store.CAKeyStateActive {
			t.Errorf("purpose %q: re-adopted state = %q, want active", purpose, list[0].State)
		}
	}
	if n := countStoredPrivateKeys(t); n != 0 {
		t.Errorf("%d ca_keys rows carry encrypted_private_key, want 0", n)
	}
}
