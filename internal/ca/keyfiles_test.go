package ca

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// All fixtures below are generated at runtime: CA key material must never be
// checked into the repository, not even as a test artifact.

// writeKeyFixture writes a fixture file into dir and returns its path.
func writeKeyFixture(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write fixture %s: %v", name, err)
	}
	return path
}

// newSSHKeyFixture writes an unencrypted OpenSSH ed25519 private key — what
// ssh-keygen produces for an empty passphrase — and returns its path plus the
// expected authorized-keys line of the matching public key.
func newSSHKeyFixture(t *testing.T, dir, name string) (path, authorized string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "guided-ssh test")
	if err != nil {
		t.Fatalf("marshal openssh key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer from key: %v", err)
	}
	return writeKeyFixture(t, dir, name, pem.EncodeToMemory(block)),
		strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
}

// newRSASSHKeyFixture writes an unencrypted OpenSSH RSA private key — the
// mounted material of an operator whose SSH CA is not an ed25519 key.
func newRSASSHKeyFixture(t *testing.T, dir, name string) string {
	t.Helper()
	block, err := ssh.MarshalPrivateKey(newRSAKey(t), "guided-ssh test")
	if err != nil {
		t.Fatalf("marshal openssh rsa key: %v", err)
	}
	return writeKeyFixture(t, dir, name, pem.EncodeToMemory(block))
}

// newMTLSFixture writes a valid agent mTLS CA (PKCS#8 key + X.509 certificate)
// using the same generator the gen-mtls-ca helper uses.
func newMTLSFixture(t *testing.T, dir string) (keyPath, certPath string) {
	t.Helper()
	certPEM, keyPEM, err := GenerateMTLSCA()
	if err != nil {
		t.Fatalf("GenerateMTLSCA: %v", err)
	}
	return writeKeyFixture(t, dir, "mtls-ca.key", keyPEM),
		writeKeyFixture(t, dir, "mtls-ca.crt", certPEM)
}

// newExternalKeyFixtures writes a complete, valid set of self-managed CA key
// files into dir — the starting point every failure case mutates.
func newExternalKeyFixtures(t *testing.T, dir string) ExternalKeyPaths {
	t.Helper()
	userPath, _ := newSSHKeyFixture(t, dir, "user-ca")
	hostPath, _ := newSSHKeyFixture(t, dir, "host-ca")
	mtlsKeyPath, mtlsCertPath := newMTLSFixture(t, dir)
	return ExternalKeyPaths{
		UserKeyFile:  userPath,
		HostKeyFile:  hostPath,
		MTLSKeyFile:  mtlsKeyPath,
		MTLSCertFile: mtlsCertPath,
	}
}

// writeSelfSignedCert overwrites path with a self-signed certificate for
// pub/priv — used to build mTLS CA certificates with the wrong properties.
func writeSelfSignedCert(t *testing.T, path string, pub crypto.PublicKey, priv crypto.Signer, isCA bool, usage x509.KeyUsage) {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "guided-ssh test mtls ca"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  isCA,
		KeyUsage:              usage,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write certificate: %v", err)
	}
}

// mustLoadMTLSKey reads back the key of a fixture so a replacement certificate
// can be signed with exactly that key.
func mustLoadMTLSKey(t *testing.T, path string) ed25519.PrivateKey {
	t.Helper()
	priv, err := loadMTLSPrivateKey(path)
	if err != nil {
		t.Fatalf("load fixture key %s: %v", path, err)
	}
	return priv
}

// newRSAKey generates an RSA key for the "wrong algorithm" cases.
func newRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	return key
}

// TestLoadExternalKeysValidMaterial: a complete, valid key set yields usable
// signers plus exactly the representations that are stored in
// ca_keys.public_key (authorized-keys line for SSH, certificate PEM for mTLS).
func TestLoadExternalKeysValidMaterial(t *testing.T) {
	dir := t.TempDir()
	userPath, userAuthorized := newSSHKeyFixture(t, dir, "user-ca")
	hostPath, hostAuthorized := newSSHKeyFixture(t, dir, "host-ca")
	mtlsKeyPath, mtlsCertPath := newMTLSFixture(t, dir)

	keys, err := LoadExternalKeys(ExternalKeyPaths{
		UserKeyFile:  userPath,
		HostKeyFile:  hostPath,
		MTLSKeyFile:  mtlsKeyPath,
		MTLSCertFile: mtlsCertPath,
	})
	if err != nil {
		t.Fatalf("LoadExternalKeys: %v", err)
	}

	for _, tc := range []struct {
		purpose    string
		loaded     ExternalSSHKey
		authorized string
	}{
		{"user", keys.User, userAuthorized},
		{"host", keys.Host, hostAuthorized},
	} {
		if tc.loaded.Signer == nil {
			t.Fatalf("%s ca: no signer", tc.purpose)
		}
		if tc.loaded.PublicKey != tc.authorized {
			t.Errorf("%s ca public key = %q, want %q", tc.purpose, tc.loaded.PublicKey, tc.authorized)
		}
		if !strings.HasPrefix(tc.loaded.PublicKey, "ssh-ed25519 ") || strings.Contains(tc.loaded.PublicKey, "\n") {
			t.Errorf("%s ca public key is not a single authorized-keys line: %q", tc.purpose, tc.loaded.PublicKey)
		}
		got := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(tc.loaded.Signer.PublicKey())))
		if got != tc.authorized {
			t.Errorf("%s ca: signer public key %q does not match the key file %q", tc.purpose, got, tc.authorized)
		}
	}
	if keys.User.PublicKey == keys.Host.PublicKey {
		t.Error("user and host ca must stay distinct keys")
	}

	if keys.MTLS.Certificate == nil || keys.MTLS.PrivateKey == nil {
		t.Fatalf("mtls ca incomplete: cert=%v key=%v", keys.MTLS.Certificate, keys.MTLS.PrivateKey)
	}
	if !keys.MTLS.Certificate.IsCA || keys.MTLS.Certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Errorf("mtls ca certificate is not a signing ca: isCA=%v usage=%v",
			keys.MTLS.Certificate.IsCA, keys.MTLS.Certificate.KeyUsage)
	}
	certPub, ok := keys.MTLS.Certificate.PublicKey.(ed25519.PublicKey)
	if !ok || !certPub.Equal(keys.MTLS.PrivateKey.Public()) {
		t.Error("mtls certificate does not belong to the loaded key")
	}
	// CertPEM is matched against ca_keys.public_key on adoption, so it must be
	// a canonically encoded certificate block.
	block, rest := pem.Decode([]byte(keys.MTLS.CertPEM))
	if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
		t.Fatalf("CertPEM is not exactly one certificate block: %q", keys.MTLS.CertPEM)
	}
	if string(block.Bytes) != string(keys.MTLS.Certificate.Raw) {
		t.Error("CertPEM does not carry the parsed certificate")
	}
}

// TestLoadExternalKeysAlgorithmFromMaterial: the algorithm that lands in
// ca_keys.algorithm is derived from the loaded key, so a mounted ssh-rsa CA is
// not recorded as ed25519. The "ssh-" prefix is stripped so the value matches
// what managed mode writes (NewCAKey stores the bare "ed25519").
func TestLoadExternalKeysAlgorithmFromMaterial(t *testing.T) {
	dir := t.TempDir()
	paths := newExternalKeyFixtures(t, dir)
	paths.UserKeyFile = newRSASSHKeyFixture(t, dir, "user-ca-rsa")

	keys, err := LoadExternalKeys(paths)
	if err != nil {
		t.Fatalf("LoadExternalKeys: %v", err)
	}
	if keys.User.Signer.PublicKey().Type() != ssh.KeyAlgoRSA {
		t.Fatalf("fixture is not an rsa key: %s", keys.User.Signer.PublicKey().Type())
	}
	for _, tc := range []struct {
		what string
		got  string
		want string
	}{
		{"rsa user ca", keys.User.Algorithm, "rsa"},
		{"ed25519 host ca", keys.Host.Algorithm, "ed25519"},
		{"mtls ca", keys.MTLS.Algorithm, "ed25519"},
	} {
		if tc.got != tc.want {
			t.Errorf("%s: algorithm = %q, want %q", tc.what, tc.got, tc.want)
		}
	}
}

// TestLoadExternalKeysRejectsBrokenMaterial: every way an operator can get the
// mounted secret wrong must fail at load time, naming the offending file.
func TestLoadExternalKeysRejectsBrokenMaterial(t *testing.T) {
	tests := []struct {
		name string
		// mutate turns the valid fixture set into the broken one under test.
		mutate func(t *testing.T, dir string, paths ExternalKeyPaths)
		// wantFile is the path the error must name; wantContains are further
		// substrings describing the reason (never the full prose).
		wantFile     func(paths ExternalKeyPaths) string
		wantContains []string
	}{
		{
			name: "user key file missing",
			mutate: func(t *testing.T, _ string, p ExternalKeyPaths) {
				if err := os.Remove(p.UserKeyFile); err != nil {
					t.Fatalf("remove: %v", err)
				}
			},
			wantFile:     func(p ExternalKeyPaths) string { return p.UserKeyFile },
			wantContains: []string{"user"},
		},
		{
			name: "host key file missing",
			mutate: func(t *testing.T, _ string, p ExternalKeyPaths) {
				if err := os.Remove(p.HostKeyFile); err != nil {
					t.Fatalf("remove: %v", err)
				}
			},
			wantFile:     func(p ExternalKeyPaths) string { return p.HostKeyFile },
			wantContains: []string{"host"},
		},
		{
			name: "mtls key file missing",
			mutate: func(t *testing.T, _ string, p ExternalKeyPaths) {
				if err := os.Remove(p.MTLSKeyFile); err != nil {
					t.Fatalf("remove: %v", err)
				}
			},
			wantFile:     func(p ExternalKeyPaths) string { return p.MTLSKeyFile },
			wantContains: []string{"mtls"},
		},
		{
			name: "mtls cert file missing",
			mutate: func(t *testing.T, _ string, p ExternalKeyPaths) {
				if err := os.Remove(p.MTLSCertFile); err != nil {
					t.Fatalf("remove: %v", err)
				}
			},
			wantFile:     func(p ExternalKeyPaths) string { return p.MTLSCertFile },
			wantContains: []string{"mtls"},
		},
		{
			name: "user key not a pem file",
			mutate: func(t *testing.T, dir string, _ ExternalKeyPaths) {
				writeKeyFixture(t, dir, "user-ca", []byte("this is not a pem block\n"))
			},
			wantFile:     func(p ExternalKeyPaths) string { return p.UserKeyFile },
			wantContains: []string{"parse", "user"},
		},
		{
			name: "host key not a pem file",
			mutate: func(t *testing.T, dir string, _ ExternalKeyPaths) {
				writeKeyFixture(t, dir, "host-ca", []byte("-----BEGIN OPENSSH PRIVATE KEY-----\ntruncated\n"))
			},
			wantFile:     func(p ExternalKeyPaths) string { return p.HostKeyFile },
			wantContains: []string{"parse", "host"},
		},
		{
			name: "mtls key not a pem file",
			mutate: func(t *testing.T, dir string, _ ExternalKeyPaths) {
				writeKeyFixture(t, dir, "mtls-ca.key", []byte("garbage\n"))
			},
			wantFile:     func(p ExternalKeyPaths) string { return p.MTLSKeyFile },
			wantContains: []string{"no pem block"},
		},
		{
			name: "mtls key is pkcs#1 instead of pkcs#8",
			mutate: func(t *testing.T, dir string, _ ExternalKeyPaths) {
				der := x509.MarshalPKCS1PrivateKey(newRSAKey(t))
				writeKeyFixture(t, dir, "mtls-ca.key",
					pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}))
			},
			wantFile:     func(p ExternalKeyPaths) string { return p.MTLSKeyFile },
			wantContains: []string{"pkcs#8"},
		},
		{
			name: "mtls key is rsa instead of ed25519",
			mutate: func(t *testing.T, dir string, _ ExternalKeyPaths) {
				der, err := x509.MarshalPKCS8PrivateKey(newRSAKey(t))
				if err != nil {
					t.Fatalf("marshal pkcs#8: %v", err)
				}
				writeKeyFixture(t, dir, "mtls-ca.key",
					pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
			},
			wantFile:     func(p ExternalKeyPaths) string { return p.MTLSKeyFile },
			wantContains: []string{"ed25519 required"},
		},
		{
			name: "mtls cert not a pem file",
			mutate: func(t *testing.T, dir string, _ ExternalKeyPaths) {
				writeKeyFixture(t, dir, "mtls-ca.crt", []byte("garbage\n"))
			},
			wantFile:     func(p ExternalKeyPaths) string { return p.MTLSCertFile },
			wantContains: []string{"CERTIFICATE"},
		},
		{
			name: "mtls cert pem block of the wrong type",
			mutate: func(t *testing.T, dir string, p ExternalKeyPaths) {
				raw, err := os.ReadFile(p.MTLSKeyFile)
				if err != nil {
					t.Fatalf("read key fixture: %v", err)
				}
				writeKeyFixture(t, dir, "mtls-ca.crt", raw)
			},
			wantFile:     func(p ExternalKeyPaths) string { return p.MTLSCertFile },
			wantContains: []string{"CERTIFICATE"},
		},
		{
			name: "mtls cert body is not a certificate",
			mutate: func(t *testing.T, dir string, _ ExternalKeyPaths) {
				writeKeyFixture(t, dir, "mtls-ca.crt",
					pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not der")}))
			},
			wantFile:     func(p ExternalKeyPaths) string { return p.MTLSCertFile },
			wantContains: []string{"parse"},
		},
		{
			name: "user key is passphrase-protected",
			mutate: func(t *testing.T, dir string, _ ExternalKeyPaths) {
				writeKeyFixture(t, dir, "user-ca", passphraseProtectedKey(t))
			},
			wantFile:     func(p ExternalKeyPaths) string { return p.UserKeyFile },
			wantContains: []string{"passphrase", "unencrypted"},
		},
		{
			name: "host key is passphrase-protected",
			mutate: func(t *testing.T, dir string, _ ExternalKeyPaths) {
				writeKeyFixture(t, dir, "host-ca", passphraseProtectedKey(t))
			},
			wantFile:     func(p ExternalKeyPaths) string { return p.HostKeyFile },
			wantContains: []string{"passphrase", "unencrypted"},
		},
		{
			name: "mtls cert belongs to a different key",
			mutate: func(t *testing.T, _ string, p ExternalKeyPaths) {
				_, other, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatalf("generate ed25519 key: %v", err)
				}
				writeSelfSignedCert(t, p.MTLSCertFile, other.Public(), other, true, x509.KeyUsageCertSign)
			},
			wantFile:     func(p ExternalKeyPaths) string { return p.MTLSCertFile },
			wantContains: []string{"does not belong"},
		},
		{
			name: "mtls cert without basic constraint ca",
			mutate: func(t *testing.T, _ string, p ExternalKeyPaths) {
				priv := mustLoadMTLSKey(t, p.MTLSKeyFile)
				writeSelfSignedCert(t, p.MTLSCertFile, priv.Public(), priv, false, x509.KeyUsageCertSign)
			},
			wantFile:     func(p ExternalKeyPaths) string { return p.MTLSCertFile },
			wantContains: []string{"not a ca certificate"},
		},
		{
			name: "mtls cert without keyCertSign",
			mutate: func(t *testing.T, _ string, p ExternalKeyPaths) {
				priv := mustLoadMTLSKey(t, p.MTLSKeyFile)
				writeSelfSignedCert(t, p.MTLSCertFile, priv.Public(), priv, true, x509.KeyUsageDigitalSignature)
			},
			wantFile:     func(p ExternalKeyPaths) string { return p.MTLSCertFile },
			wantContains: []string{"keyCertSign"},
		},
		{
			name: "mtls cert with a non-ed25519 public key",
			mutate: func(t *testing.T, _ string, p ExternalKeyPaths) {
				rsaKey := newRSAKey(t)
				writeSelfSignedCert(t, p.MTLSCertFile, rsaKey.Public(), rsaKey, true, x509.KeyUsageCertSign)
			},
			wantFile:     func(p ExternalKeyPaths) string { return p.MTLSCertFile },
			wantContains: []string{"ed25519 required"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			paths := newExternalKeyFixtures(t, dir)
			tc.mutate(t, dir, paths)

			keys, err := LoadExternalKeys(paths)
			if err == nil {
				t.Fatalf("expected an error, got keys %+v", keys)
			}
			if keys != nil {
				t.Errorf("keys must be nil on error, got %+v", keys)
			}
			// An operator has to fix the mounted secret, so the message must
			// point at the file and say what is wrong with it.
			if file := tc.wantFile(paths); !strings.Contains(err.Error(), file) {
				t.Errorf("error does not name %s: %v", file, err)
			}
			for _, want := range tc.wantContains {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error does not mention %q: %v", want, err)
				}
			}
		})
	}
}

// passphraseProtectedKey builds an OpenSSH key that cannot be used unattended.
func passphraseProtectedKey(t *testing.T) []byte {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "guided-ssh test", []byte("hunter2"))
	if err != nil {
		t.Fatalf("marshal encrypted openssh key: %v", err)
	}
	return pem.EncodeToMemory(block)
}
