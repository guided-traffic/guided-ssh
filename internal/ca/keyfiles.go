package ca

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/guided-traffic/guided-ssh/internal/store"
)

// ExternalKeyPaths holds the file paths of the CA material in self-managed
// mode (GSSH_CA_MODE=self-managed). All four files are mandatory; the mode
// covers all three CA purposes at once.
type ExternalKeyPaths struct {
	UserKeyFile  string // OpenSSH private key PEM of the SSH user CA
	HostKeyFile  string // OpenSSH private key PEM of the SSH host CA
	MTLSKeyFile  string // PKCS#8 PEM of the agent mTLS CA key
	MTLSCertFile string // X.509 CA certificate PEM of the agent mTLS CA
}

// ExternalSSHKey is the loaded material of one SSH CA: a ready-to-use signer
// plus its public key in authorized-keys format — exactly the representation
// stored in ca_keys.public_key.
type ExternalSSHKey struct {
	Signer    ssh.Signer
	PublicKey string
	Algorithm string // value for ca_keys.algorithm, see sshKeyAlgorithm
}

// ExternalMTLSKey is the loaded material of the agent mTLS CA: the parsed
// certificate, its Ed25519 private key and the certificate PEM that is stored
// in ca_keys.public_key (same representation as EnsureMTLSCA writes).
type ExternalMTLSKey struct {
	Certificate *x509.Certificate
	PrivateKey  ed25519.PrivateKey
	CertPEM     string
	Algorithm   string // always "ed25519": the loader accepts nothing else
}

// ExternalKeys is the CA material of all three purposes, loaded from files.
type ExternalKeys struct {
	User ExternalSSHKey
	Host ExternalSSHKey
	MTLS ExternalMTLSKey
}

// LoadExternalKeys reads and validates the CA key files of self-managed mode.
// Every error names the offending file and the concrete reason: it is a
// startup error an operator has to fix in the mounted secret.
func LoadExternalKeys(paths ExternalKeyPaths) (*ExternalKeys, error) {
	user, err := loadSSHKeyFile(paths.UserKeyFile, store.CertTypeUser)
	if err != nil {
		return nil, err
	}
	host, err := loadSSHKeyFile(paths.HostKeyFile, store.CertTypeHost)
	if err != nil {
		return nil, err
	}
	mtls, err := loadMTLSKeyFiles(paths.MTLSKeyFile, paths.MTLSCertFile)
	if err != nil {
		return nil, err
	}
	return &ExternalKeys{User: user, Host: host, MTLS: mtls}, nil
}

// loadSSHKeyFile parses an unencrypted OpenSSH private key file.
func loadSSHKeyFile(path, purpose string) (ExternalSSHKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ExternalSSHKey{}, fmt.Errorf("ca: read %s ca key file %q: %w", purpose, path, err)
	}
	signer, err := ssh.ParsePrivateKey(raw)
	if err != nil {
		var passphrase *ssh.PassphraseMissingError
		if errors.As(err, &passphrase) {
			return ExternalSSHKey{}, fmt.Errorf(
				"ca: %s ca key file %q is passphrase-protected, self-managed ca keys must be unencrypted", purpose, path)
		}
		return ExternalSSHKey{}, fmt.Errorf("ca: parse %s ca key file %q: %w", purpose, path, err)
	}
	return ExternalSSHKey{
		Signer:    signer,
		PublicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))),
		Algorithm: sshKeyAlgorithm(signer.PublicKey()),
	}, nil
}

// sshKeyAlgorithm maps an SSH public key type to the value stored in
// ca_keys.algorithm. Managed mode records the bare algorithm name "ed25519"
// (see NewCAKey), so the "ssh-" prefix of the wire format is stripped
// ("ssh-ed25519" → "ed25519", "ssh-rsa" → "rsa") and rows of both modes stay
// directly comparable. Types without that prefix (e.g. "ecdsa-sha2-nistp256")
// are stored verbatim — the loader accepts every key type ssh.ParsePrivateKey
// understands, and the row must describe the mounted material, not assume it.
func sshKeyAlgorithm(pub ssh.PublicKey) string {
	return strings.TrimPrefix(pub.Type(), "ssh-")
}

// loadMTLSKeyFiles parses the mTLS CA key (PKCS#8) and certificate (X.509) and
// checks that the certificate really is a signing CA for that key.
func loadMTLSKeyFiles(keyPath, certPath string) (ExternalMTLSKey, error) {
	priv, err := loadMTLSPrivateKey(keyPath)
	if err != nil {
		return ExternalMTLSKey{}, err
	}

	rawCert, err := os.ReadFile(certPath)
	if err != nil {
		return ExternalMTLSKey{}, fmt.Errorf("ca: read mtls ca cert file %q: %w", certPath, err)
	}
	block, _ := pem.Decode(rawCert)
	if block == nil || block.Type != "CERTIFICATE" {
		return ExternalMTLSKey{}, fmt.Errorf("ca: mtls ca cert file %q: no pem block of type CERTIFICATE", certPath)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ExternalMTLSKey{}, fmt.Errorf("ca: parse mtls ca cert file %q: %w", certPath, err)
	}
	if !cert.IsCA {
		return ExternalMTLSKey{}, fmt.Errorf("ca: mtls ca cert file %q: not a ca certificate (basic constraints ca:false)", certPath)
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return ExternalMTLSKey{}, fmt.Errorf("ca: mtls ca cert file %q: key usage does not contain keyCertSign", certPath)
	}
	certPub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return ExternalMTLSKey{}, fmt.Errorf("ca: mtls ca cert file %q: unexpected public key type %T, ed25519 required", certPath, cert.PublicKey)
	}
	if !certPub.Equal(priv.Public()) {
		return ExternalMTLSKey{}, fmt.Errorf("ca: mtls ca cert file %q does not belong to key file %q", certPath, keyPath)
	}

	// Re-encode instead of storing the raw file bytes: ca_keys.public_key is
	// matched against this string on adoption, so it must be byte-identical to
	// what EnsureMTLSCA produces regardless of comments or trailing bytes.
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes}))
	return ExternalMTLSKey{Certificate: cert, PrivateKey: priv, CertPEM: certPEM, Algorithm: "ed25519"}, nil
}

// loadMTLSPrivateKey parses the PKCS#8 PEM of the mTLS CA key.
func loadMTLSPrivateKey(keyPath string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("ca: read mtls ca key file %q: %w", keyPath, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("ca: mtls ca key file %q: no pem block", keyPath)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ca: parse mtls ca key file %q (pkcs#8 expected): %w", keyPath, err)
	}
	priv, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("ca: mtls ca key file %q: unexpected key type %T, ed25519 required", keyPath, parsed)
	}
	return priv, nil
}
