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
	plaintext := []byte("geheimer private key")

	encrypted, err := encryptPrivateKey(key, plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if bytes.Contains(encrypted, plaintext) {
		t.Fatal("Chiffrat enthält Klartext")
	}
	decrypted, err := decryptPrivateKey(key, encrypted)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("Roundtrip: %q != %q", decrypted, plaintext)
	}
}

func TestEncryptFalscheKeyLaenge(t *testing.T) {
	if _, err := encryptPrivateKey([]byte("zu kurz"), []byte("x")); !errors.Is(err, ErrInvalidMasterKey) {
		t.Fatalf("ErrInvalidMasterKey erwartet, bekommen: %v", err)
	}
	if _, err := decryptPrivateKey([]byte("zu kurz"), []byte("x")); !errors.Is(err, ErrInvalidMasterKey) {
		t.Fatalf("ErrInvalidMasterKey erwartet, bekommen: %v", err)
	}
}

func TestDecryptFalscherKey(t *testing.T) {
	encrypted, err := encryptPrivateKey(testMasterKey(), []byte("daten"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	wrongKey := testMasterKey()
	wrongKey[0] ^= 0xff
	if _, err := decryptPrivateKey(wrongKey, encrypted); !errors.Is(err, ErrInvalidMasterKey) {
		t.Fatalf("ErrInvalidMasterKey erwartet, bekommen: %v", err)
	}
}

func TestDecryptZuKurzesChiffrat(t *testing.T) {
	if _, err := decryptPrivateKey(testMasterKey(), []byte("kurz")); !errors.Is(err, ErrInvalidMasterKey) {
		t.Fatalf("ErrInvalidMasterKey erwartet, bekommen: %v", err)
	}
}
