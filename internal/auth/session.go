package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

// ErrInvalidSession kapselt alle Decodier-Fehler eines Session-Cookies; die
// API behandelt sie wie eine fehlende Session (Login-Aufforderung statt 500).
var ErrInvalidSession = errors.New("auth: ungültige session")

// sessionKeyInfo ist der HKDF-Kontext der Cookie-Verschlüsselung; eine neue
// Version invalidiert alle bestehenden Sessions (erneuter Login).
const sessionKeyInfo = "guided-ssh/ui-session/v1"

// SessionCodec ver- und entschlüsselt die Web-Sessions der UI als kompakte,
// URL-sichere Cookie-Werte (AES-256-GCM). Der Schlüssel wird per HKDF aus dem
// CA-Master-Key abgeleitet: kein zusätzliches Secret im Deployment, und alle
// Replikas akzeptieren die Sessions der anderen.
type SessionCodec struct {
	aead cipher.AEAD
}

// NewSessionCodec leitet den Cookie-Schlüssel aus dem Master-Key ab.
func NewSessionCodec(masterKey []byte) (*SessionCodec, error) {
	if len(masterKey) < 32 {
		return nil, fmt.Errorf("auth: master-key zu kurz für session-schlüssel (%d bytes, 32 erwartet)", len(masterKey))
	}
	key, err := hkdf.Key(sha256.New, masterKey, nil, sessionKeyInfo, 32)
	if err != nil {
		return nil, fmt.Errorf("auth: session-schlüssel ableiten: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("auth: session-cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("auth: session-gcm: %w", err)
	}
	return &SessionCodec{aead: aead}, nil
}

// Seal verschlüsselt den Klartext zu einem Cookie-Wert (nonce‖ciphertext,
// Base64-URL ohne Padding).
func (c *SessionCodec) Seal(plaintext []byte) (string, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("auth: session-nonce: %w", err)
	}
	sealed := c.aead.Seal(nonce, nonce, plaintext, nil)
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

// Open entschlüsselt einen Cookie-Wert; manipulierte oder mit anderem
// Schlüssel erzeugte Werte kommen als ErrInvalidSession zurück.
func (c *SessionCodec) Open(value string) ([]byte, error) {
	sealed, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("%w: base64: %w", ErrInvalidSession, err)
	}
	if len(sealed) < c.aead.NonceSize() {
		return nil, fmt.Errorf("%w: wert zu kurz", ErrInvalidSession)
	}
	nonce, ciphertext := sealed[:c.aead.NonceSize()], sealed[c.aead.NonceSize():]
	plaintext, err := c.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: entschlüsseln: %w", ErrInvalidSession, err)
	}
	return plaintext, nil
}
