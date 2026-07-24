package auth_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/guided-traffic/guided-ssh/internal/auth"
)

func testMasterKey() []byte { return bytes.Repeat([]byte{7}, 32) }

func TestSessionCodecRoundtrip(t *testing.T) {
	codec, err := auth.NewSessionCodec(testMasterKey())
	if err != nil {
		t.Fatalf("NewSessionCodec: %v", err)
	}
	sealed, err := codec.Seal([]byte(`{"user":"alice"}`))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	plaintext, err := codec.Open(sealed)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if string(plaintext) != `{"user":"alice"}` {
		t.Errorf("plaintext = %q", plaintext)
	}
}

func TestSessionCodecLehntManipulationAb(t *testing.T) {
	codec, err := auth.NewSessionCodec(testMasterKey())
	if err != nil {
		t.Fatalf("NewSessionCodec: %v", err)
	}
	sealed, err := codec.Seal([]byte("payload"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	for name, value := range map[string]string{
		"manipuliert":   sealed[:len(sealed)-2] + "xx",
		"kein base64":   "%%%",
		"zu kurz":       "AAAA",
		"leer":          "",
		"fremder codec": mustSealWithKey(t, bytes.Repeat([]byte{9}, 32), "payload"),
	} {
		if _, err := codec.Open(value); !errors.Is(err, auth.ErrInvalidSession) {
			t.Errorf("%s: Open = %v, erwartet ErrInvalidSession", name, err)
		}
	}
}

func mustSealWithKey(t *testing.T, key []byte, plaintext string) string {
	t.Helper()
	codec, err := auth.NewSessionCodec(key)
	if err != nil {
		t.Fatalf("NewSessionCodec: %v", err)
	}
	sealed, err := codec.Seal([]byte(plaintext))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	return sealed
}

func TestSessionCodecKurzerKey(t *testing.T) {
	if _, err := auth.NewSessionCodec(make([]byte, 16)); err == nil {
		t.Error("NewSessionCodec mit 16-byte-key: Fehler erwartet")
	}
}
