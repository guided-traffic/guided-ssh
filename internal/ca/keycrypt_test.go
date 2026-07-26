package ca

import (
	"bytes"
	"errors"
	"testing"
)

func testMasterKey() []byte {
	key := make([]byte, MasterKeySize)
	for i := range key {
		key[i] = byte(i)
	}
	return key
}

func TestEncryptDecryptRoundtrip(t *testing.T) {
	key := testMasterKey()
	plaintext := []byte("secret private key")

	encrypted, err := encryptPrivateKey(key, plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if bytes.Contains(encrypted, plaintext) {
		t.Fatal("ciphertext contains plaintext")
	}
	decrypted, err := decryptPrivateKey(key, encrypted)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("roundtrip: %q != %q", decrypted, plaintext)
	}
}

func TestEncryptWrongKeyLength(t *testing.T) {
	if _, err := encryptPrivateKey([]byte("too short"), []byte("x")); !errors.Is(err, ErrInvalidMasterKey) {
		t.Fatalf("expected ErrInvalidMasterKey, got: %v", err)
	}
	if _, err := decryptPrivateKey([]byte("too short"), []byte("x")); !errors.Is(err, ErrInvalidMasterKey) {
		t.Fatalf("expected ErrInvalidMasterKey, got: %v", err)
	}
}

func TestDecryptWrongKey(t *testing.T) {
	encrypted, err := encryptPrivateKey(testMasterKey(), []byte("data"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	wrongKey := testMasterKey()
	wrongKey[0] ^= 0xff
	if _, err := decryptPrivateKey(wrongKey, encrypted); !errors.Is(err, ErrInvalidMasterKey) {
		t.Fatalf("expected ErrInvalidMasterKey, got: %v", err)
	}
}

func TestDecryptTooShortCiphertext(t *testing.T) {
	if _, err := decryptPrivateKey(testMasterKey(), []byte("short")); !errors.Is(err, ErrInvalidMasterKey) {
		t.Fatalf("expected ErrInvalidMasterKey, got: %v", err)
	}
}
