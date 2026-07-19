// Package pintls stellt SPKI-Fingerprint-Pinning für TLS-Clients bereit
// (genutzt von gssh und gssh-agentd, siehe ADR-016): der Base64-kodierte
// SHA-256 des SubjectPublicKeyInfo ersetzt die CA-/Hostname-Prüfung.
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

// DecodePin dekodiert und validiert einen Base64-SPKI-SHA-256-Pin.
func DecodePin(encoded string) ([]byte, error) {
	pin, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("pin ist kein gültiges base64: %w", err)
	}
	if len(pin) != sha256.Size {
		return nil, fmt.Errorf("pin muss %d bytes lang sein (sha-256), ist %d", sha256.Size, len(pin))
	}
	return pin, nil
}

// Transport liefert einen http.Transport, der das Serverzertifikat
// ausschließlich über den gepinnten SPKI-Hash verifiziert; Chain- und
// Hostname-Prüfung entfallen bewusst (der Pin ersetzt das CA-Vertrauen).
func Transport(pin []byte) *http.Transport {
	return &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion:            tls.VersionTLS12,
		InsecureSkipVerify:    true, //nolint:gosec // Pinning ersetzt die CA-Prüfung (VerifyPeerCertificate)
		VerifyPeerCertificate: Verifier(pin),
	}}
}

// Verifier akzeptiert die Verbindung, sobald ein präsentiertes Zertifikat
// den gepinnten SPKI-Hash trägt.
func Verifier(pin []byte) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		for _, raw := range rawCerts {
			cert, err := x509.ParseCertificate(raw)
			if err != nil {
				continue
			}
			sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
			if bytes.Equal(sum[:], pin) {
				return nil
			}
		}
		return errors.New("serverzertifikat entspricht nicht dem gepinnten fingerprint")
	}
}
