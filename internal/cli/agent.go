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

// agentCommentPrefix kennzeichnet Einträge dieser CLI im ssh-agent; status
// und logout erkennen daran die eigenen Schlüssel.
const agentCommentPrefix = "guided-ssh"

// renewMargin: Zertifikate mit weniger Restlaufzeit gelten beim Auto-Login
// als erneuerungsbedürftig (Clock-Skew, Verbindungsaufbauzeit).
const renewMargin = 5 * time.Minute

// connectAgent verbindet sich mit dem ssh-agent aus SSH_AUTH_SOCK.
func connectAgent() (agent.Agent, io.Closer, error) {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return nil, nil, errors.New("SSH_AUTH_SOCK nicht gesetzt — läuft ein ssh-agent?")
	}
	conn, err := net.Dial("unix", sock)
	if err != nil {
		return nil, nil, fmt.Errorf("ssh-agent verbinden: %w", err)
	}
	return agent.NewClient(conn), conn, nil
}

// gsshCerts liefert die guided-ssh-Zertifikate im Agenten.
func gsshCerts(ag agent.Agent) ([]*ssh.Certificate, error) {
	keys, err := ag.List()
	if err != nil {
		return nil, fmt.Errorf("agent-einträge auflisten: %w", err)
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

// maxCertUnix begrenzt Zertifikatszeiten nach oben (Jahr ~36812) —
// ssh.CertTimeInfinity (max uint64) würde time.Unix überlaufen lassen.
const maxCertUnix = 1 << 40

// certTime wandelt SSH-Zertifikatszeiten (Unix-Sekunden als uint64) in time.Time.
func certTime(sec uint64) time.Time {
	if sec > maxCertUnix {
		sec = maxCertUnix
	}
	return time.Unix(int64(sec), 0) //nolint:gosec // durch maxCertUnix begrenzt
}

// certValid: Zertifikat ist jetzt und noch mindestens margin lang gültig.
func certValid(cert *ssh.Certificate, margin time.Duration) bool {
	now := time.Now()
	return !now.Before(certTime(cert.ValidAfter)) && now.Add(margin).Before(certTime(cert.ValidBefore))
}

// anyValidCert: mindestens ein Zertifikat ist noch margin lang gültig.
func anyValidCert(certs []*ssh.Certificate, margin time.Duration) bool {
	for _, cert := range certs {
		if certValid(cert, margin) {
			return true
		}
	}
	return false
}

// loadIntoAgent ersetzt vorhandene guided-ssh-Einträge durch das neue
// Schlüsselpaar samt Zertifikat; die Lebensdauer im Agenten endet mit dem
// Zertifikat (keine Persistenz außerhalb des Agenten).
func loadIntoAgent(ag agent.Agent, priv ed25519.PrivateKey, cert *ssh.Certificate) error {
	lifetime := time.Until(certTime(cert.ValidBefore))
	if lifetime <= 0 {
		return errors.New("zertifikat ist bereits abgelaufen")
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

// removeGsshKeys entfernt alle guided-ssh-Einträge aus dem Agenten.
func removeGsshKeys(ag agent.Agent) (int, error) {
	keys, err := ag.List()
	if err != nil {
		return 0, fmt.Errorf("agent-einträge auflisten: %w", err)
	}
	removed := 0
	for _, key := range keys {
		if !strings.HasPrefix(key.Comment, agentCommentPrefix) {
			continue
		}
		if err := ag.Remove(key); err != nil {
			return removed, fmt.Errorf("agent-eintrag entfernen: %w", err)
		}
		removed++
	}
	return removed, nil
}
