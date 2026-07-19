package ca

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/guided-traffic/guided-ssh/internal/store"
)

// fixedNow hält die Policy-Uhr in Tests stabil.
var fixedNow = time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)

func testEngine() *PolicyEngine {
	e := NewPolicyEngine(DefaultPolicies())
	e.now = func() time.Time { return fixedNow }
	return e
}

func testPublicKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("public key: %v", err)
	}
	return sshPub
}

func validUserRequest(t *testing.T) CertRequest {
	t.Helper()
	return CertRequest{
		CertType:    store.CertTypeUser,
		PublicKey:   testPublicKey(t),
		KeyID:       UserKeyID("sub-1", "https://idp.example"),
		Principals:  []string{"alice", "alice@example.com"},
		ValidAfter:  fixedNow,
		ValidBefore: fixedNow.Add(16 * time.Hour),
		Extensions:  map[string]string{"permit-pty": ""},
	}
}

func TestValidateOK(t *testing.T) {
	if err := testEngine().Validate(RequesterUser, validUserRequest(t)); err != nil {
		t.Fatalf("gültiger Request abgelehnt: %v", err)
	}
}

func TestValidateVerstoesse(t *testing.T) {
	cases := []struct {
		name          string
		requesterType string
		mutate        func(*CertRequest)
	}{
		{"unbekannter Requester-Typ", "roboter", func(*CertRequest) {}},
		{"falscher Zertifikatstyp", RequesterUser, func(r *CertRequest) { r.CertType = store.CertTypeHost }},
		{"KeyID fehlt", RequesterUser, func(r *CertRequest) { r.KeyID = "" }},
		{"keine Principals", RequesterUser, func(r *CertRequest) { r.Principals = nil }},
		{"verbotene Extension", RequesterUser, func(r *CertRequest) {
			r.Extensions = map[string]string{"no-touch-required": ""}
		}},
		{"verbotene Critical Option", RequesterUser, func(r *CertRequest) {
			r.CriticalOptions = map[string]string{"force-command": "/bin/true"}
		}},
		{"Laufzeit über Maximum", RequesterUser, func(r *CertRequest) {
			r.ValidBefore = r.ValidAfter.Add(17 * time.Hour)
		}},
		{"valid_before vor valid_after", RequesterUser, func(r *CertRequest) {
			r.ValidBefore = r.ValidAfter.Add(-time.Hour)
		}},
		{"zu weit rückdatiert", RequesterUser, func(r *CertRequest) {
			r.ValidAfter = fixedNow.Add(-time.Hour)
			r.ValidBefore = fixedNow.Add(time.Hour)
		}},
		{"CI über 1h", RequesterCI, func(r *CertRequest) {
			r.Extensions = map[string]string{"permit-pty": ""}
			r.ValidBefore = r.ValidAfter.Add(2 * time.Hour)
		}},
		{"CI mit Agent-Forwarding", RequesterCI, func(r *CertRequest) {
			r.ValidBefore = r.ValidAfter.Add(time.Hour)
			r.Extensions = map[string]string{"permit-agent-forwarding": ""}
		}},
	}
	engine := testEngine()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := validUserRequest(t)
			tc.mutate(&req)
			err := engine.Validate(tc.requesterType, req)
			var pv *PolicyViolationError
			if !errors.As(err, &pv) {
				t.Fatalf("PolicyViolationError erwartet, bekommen: %v", err)
			}
			if pv.Error() == "" || pv.RequesterType != tc.requesterType {
				t.Fatalf("unvollständiger Fehler: %+v", pv)
			}
		})
	}
}

func TestValidatePrincipalWhitelist(t *testing.T) {
	engine := NewPolicyEngine(map[string]Policy{
		RequesterUser: {
			CertType:          store.CertTypeUser,
			MaxValidity:       time.Hour,
			AllowedPrincipals: []string{"deploy"},
		},
	})
	engine.now = func() time.Time { return fixedNow }

	req := validUserRequest(t)
	req.Extensions = nil
	req.ValidBefore = req.ValidAfter.Add(time.Hour)
	req.Principals = []string{"deploy"}
	if err := engine.Validate(RequesterUser, req); err != nil {
		t.Fatalf("erlaubter Principal abgelehnt: %v", err)
	}
	req.Principals = []string{"root"}
	var pv *PolicyViolationError
	if err := engine.Validate(RequesterUser, req); !errors.As(err, &pv) {
		t.Fatalf("PolicyViolationError erwartet, bekommen: %v", err)
	}
}

func TestValidateHostPolicy(t *testing.T) {
	req := CertRequest{
		CertType:    store.CertTypeHost,
		PublicKey:   testPublicKey(t),
		KeyID:       HostKeyID("web-1.example"),
		Principals:  []string{"web-1.example"},
		ValidAfter:  fixedNow,
		ValidBefore: fixedNow.Add(30 * 24 * time.Hour),
	}
	if err := testEngine().Validate(RequesterHost, req); err != nil {
		t.Fatalf("gültiger Host-Request abgelehnt: %v", err)
	}
}
