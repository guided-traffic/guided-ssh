package cli

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// agentCommentPrefix marks this CLI's entries in the ssh-agent; status
// and logout use it to recognize their own keys.
const agentCommentPrefix = "guided-ssh"

// renewMargin: certificates with less remaining validity are considered due
// for renewal during auto-login (clock skew, connection setup time).
const renewMargin = 5 * time.Minute

// connectAgent connects to the ssh-agent from SSH_AUTH_SOCK.
func connectAgent() (agent.Agent, io.Closer, error) {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return nil, nil, errors.New("SSH_AUTH_SOCK not set — is an ssh-agent running?")
	}
	// G704 false positive: local ssh-agent unix socket from SSH_AUTH_SOCK
	// (user's process environment), not a network target — not SSRF.
	conn, err := net.Dial("unix", sock) //nolint:gosec // see comment above
	if err != nil {
		return nil, nil, fmt.Errorf("connecting to ssh-agent: %w", err)
	}
	return agent.NewClient(conn), conn, nil
}

// gsshCerts returns the guided-ssh certificates in the agent.
func gsshCerts(ag agent.Agent) ([]*ssh.Certificate, error) {
	keys, err := ag.List()
	if err != nil {
		return nil, fmt.Errorf("listing agent entries: %w", err)
	}
	var certs []*ssh.Certificate
	for _, key := range keys {
		if !strings.HasPrefix(key.Comment, agentCommentPrefix) {
			continue
		}
		pub, err := ssh.ParsePublicKey(key.Blob)
		if err != nil {
			continue
		}
		if cert, ok := pub.(*ssh.Certificate); ok {
			certs = append(certs, cert)
		}
	}
	return certs, nil
}

// maxCertUnix caps certificate times from above (year ~36812) —
// ssh.CertTimeInfinity (max uint64) would overflow time.Unix.
const maxCertUnix = 1 << 40

// certTime converts SSH certificate times (Unix seconds as uint64) to time.Time.
func certTime(sec uint64) time.Time {
	if sec > maxCertUnix {
		sec = maxCertUnix
	}
	return time.Unix(int64(sec), 0) //nolint:gosec // bounded by maxCertUnix
}

// certValid reports whether the certificate is valid now and for at least
// margin longer.
func certValid(cert *ssh.Certificate, margin time.Duration) bool {
	now := time.Now()
	return !now.Before(certTime(cert.ValidAfter)) && now.Add(margin).Before(certTime(cert.ValidBefore))
}

// anyValidCert reports whether at least one certificate is still valid for
// margin longer.
func anyValidCert(certs []*ssh.Certificate, margin time.Duration) bool {
	for _, cert := range certs {
		if certValid(cert, margin) {
			return true
		}
	}
	return false
}

// loadIntoAgent replaces existing guided-ssh entries with the new key pair
// and certificate; the lifetime in the agent ends with the certificate (no
// persistence outside the agent).
func loadIntoAgent(ag agent.Agent, priv ed25519.PrivateKey, cert *ssh.Certificate) error {
	lifetime := time.Until(certTime(cert.ValidBefore))
	if lifetime <= 0 {
		return errors.New("certificate has already expired")
	}
	if _, err := removeGsshKeys(ag); err != nil {
		return err
	}
	secs := int64(lifetime/time.Second) + 1
	if secs > math.MaxUint32 {
		secs = math.MaxUint32
	}
	return ag.Add(agent.AddedKey{
		PrivateKey:   priv,
		Certificate:  cert,
		Comment:      agentCommentPrefix + " " + cert.KeyId,
		LifetimeSecs: uint32(secs), //nolint:gosec // oben auf MaxUint32 begrenzt
	})
}

// removeGsshKeys removes all guided-ssh entries from the agent.
func removeGsshKeys(ag agent.Agent) (int, error) {
	keys, err := ag.List()
	if err != nil {
		return 0, fmt.Errorf("listing agent entries: %w", err)
	}
	removed := 0
	for _, key := range keys {
		if !strings.HasPrefix(key.Comment, agentCommentPrefix) {
			continue
		}
		if err := ag.Remove(key); err != nil {
			return removed, fmt.Errorf("removing agent entry: %w", err)
		}
		removed++
	}
	return removed, nil
}
