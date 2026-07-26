// Package pintls provides SPKI fingerprint pinning for TLS clients (used by
// gssh and gssh-agentd, see ADR-016): the base64-encoded SHA-256 of the
// SubjectPublicKeyInfo replaces CA/hostname verification.
package pintls

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
)

// FromCertificate returns a certificate's base64 SPKI-SHA-256 pin — exactly
// the value DecodePin expects and Verifier checks. The single source of
// this computation (server pin provider, tests, doc snippets).
func FromCertificate(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}

// DecodePin decodes and validates a base64 SPKI-SHA-256 pin.
func DecodePin(encoded string) ([]byte, error) {
	pin, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("pin is not valid base64: %w", err)
	}
	if len(pin) != sha256.Size {
		return nil, fmt.Errorf("pin must be %d bytes long (sha-256), is %d", sha256.Size, len(pin))
	}
	return pin, nil
}

// Transport returns an http.Transport that verifies the server certificate
// solely via the pinned SPKI hash; chain and hostname verification are
// deliberately skipped (the pin replaces CA trust).
func Transport(pin []byte) *http.Transport {
	return &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS12,
		// Pinning replaces CA/hostname verification; verification happens
		// via the SPKI pin in VerifyConnection.
		InsecureSkipVerify: true, //nolint:gosec // Pin verification happens in VerifyConnection (see below).
		VerifyConnection:   Verifier(pin),
	}}
}

// Verifier accepts the connection as soon as a presented certificate carries
// the pinned SPKI hash. As VerifyConnection, the check runs on both full and
// resumed handshakes (unlike VerifyPeerCertificate, which would be skipped
// on session resumption and could let the pin be bypassed).
func Verifier(pin []byte) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		for _, cert := range cs.PeerCertificates {
			sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
			if bytes.Equal(sum[:], pin) {
				return nil
			}
		}
		return errors.New("server certificate does not match the pinned fingerprint")
	}
}
