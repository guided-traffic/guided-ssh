package ca

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

// MasterKeySize is the required length of the master key (AES-256).
const MasterKeySize = 32

// ErrInvalidMasterKey signals a master key of the wrong length or a
// decryption failure (wrong key or tampered data).
var ErrInvalidMasterKey = errors.New("ca: invalid master key")

// ErrSelfManaged is returned by every path that would create CA key material
// while the CA runs in self-managed mode. There the key files are the source
// of truth, so bootstrapping and rotation are Git operations on the mounted
// secret, not in-app actions (see SELF_MANAGED_CA.md, D5/D6).
var ErrSelfManaged = errors.New(
	"ca: self-managed mode: ca keys are managed in git (mounted key files), the application must not create or rotate them")

// newGCM builds an AES-256-GCM AEAD from the master key.
func newGCM(masterKey []byte) (cipher.AEAD, error) {
	if len(masterKey) != MasterKeySize {
		return nil, fmt.Errorf("%w: %d bytes instead of %d", ErrInvalidMasterKey, len(masterKey), MasterKeySize)
	}
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// encryptPrivateKey encrypts a private key at rest (AES-256-GCM,
// ADR-014). Output format: nonce || ciphertext.
func encryptPrivateKey(masterKey, plaintext []byte) ([]byte, error) {
	aead, err := newGCM(masterKey)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plaintext, nil), nil
}

// decryptPrivateKey decrypts the format produced by encryptPrivateKey.
func decryptPrivateKey(masterKey, data []byte) ([]byte, error) {
	aead, err := newGCM(masterKey)
	if err != nil {
		return nil, err
	}
	if len(data) < aead.NonceSize() {
		return nil, fmt.Errorf("%w: ciphertext too short", ErrInvalidMasterKey)
	}
	nonce, ciphertext := data[:aead.NonceSize()], data[aead.NonceSize():]
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: decryption failed", ErrInvalidMasterKey)
	}
	return plaintext, nil
}
