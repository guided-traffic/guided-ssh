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

// ErrInvalidSession wraps all decoding errors of a session cookie; the API
// treats them like a missing session (prompt for login instead of a 500).
var ErrInvalidSession = errors.New("auth: invalid session")

// sessionKeyInfo is the HKDF context of the cookie encryption; a new
// version invalidates all existing sessions (forcing re-login).
const sessionKeyInfo = "guided-ssh/ui-session/v1"

// SessionCodec encrypts and decrypts the UI's web sessions as compact,
// URL-safe cookie values (AES-256-GCM). The key is derived from the CA
// master key via HKDF: no additional secret in the deployment, and all
// replicas accept each other's sessions.
type SessionCodec struct {
	aead cipher.AEAD
}

// NewSessionCodec derives the cookie key from the master key.
func NewSessionCodec(masterKey []byte) (*SessionCodec, error) {
	if len(masterKey) < 32 {
		return nil, fmt.Errorf("auth: master key too short for session key (%d bytes, 32 expected)", len(masterKey))
	}
	key, err := hkdf.Key(sha256.New, masterKey, nil, sessionKeyInfo, 32)
	if err != nil {
		return nil, fmt.Errorf("auth: deriving session key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("auth: session cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("auth: session gcm: %w", err)
	}
	return &SessionCodec{aead: aead}, nil
}

// Seal encrypts the plaintext into a cookie value (nonce‖ciphertext,
// base64-URL without padding).
func (c *SessionCodec) Seal(plaintext []byte) (string, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("auth: session nonce: %w", err)
	}
	sealed := c.aead.Seal(nonce, nonce, plaintext, nil)
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

// Open decrypts a cookie value; tampered values or ones produced with a
// different key come back as ErrInvalidSession.
func (c *SessionCodec) Open(value string) ([]byte, error) {
	sealed, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("%w: base64: %w", ErrInvalidSession, err)
	}
	if len(sealed) < c.aead.NonceSize() {
		return nil, fmt.Errorf("%w: value too short", ErrInvalidSession)
	}
	nonce, ciphertext := sealed[:c.aead.NonceSize()], sealed[c.aead.NonceSize():]
	plaintext, err := c.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: decrypting: %w", ErrInvalidSession, err)
	}
	return plaintext, nil
}
