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

// fixedNow keeps the policy clock stable in tests.
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
		t.Fatalf("valid request rejected: %v", err)
	}
}

func TestValidateViolations(t *testing.T) {
	cases := []struct {
		name          string
		requesterType string
		mutate        func(*CertRequest)
	}{
		{"unknown requester type", "robot", func(*CertRequest) {}},
		{"wrong certificate type", RequesterUser, func(r *CertRequest) { r.CertType = store.CertTypeHost }},
		{"KeyID missing", RequesterUser, func(r *CertRequest) { r.KeyID = "" }},
		{"no principals", RequesterUser, func(r *CertRequest) { r.Principals = nil }},
		{"forbidden extension", RequesterUser, func(r *CertRequest) {
			r.Extensions = map[string]string{"no-touch-required": ""}
		}},
		{"forbidden critical option", RequesterUser, func(r *CertRequest) {
			r.CriticalOptions = map[string]string{"force-command": "/bin/true"}
		}},
		{"lifetime over maximum", RequesterUser, func(r *CertRequest) {
			r.ValidBefore = r.ValidAfter.Add(17 * time.Hour)
		}},
		{"valid_before before valid_after", RequesterUser, func(r *CertRequest) {
			r.ValidBefore = r.ValidAfter.Add(-time.Hour)
		}},
		{"backdated too far", RequesterUser, func(r *CertRequest) {
			r.ValidAfter = fixedNow.Add(-time.Hour)
			r.ValidBefore = fixedNow.Add(time.Hour)
		}},
		{"CI over 1h", RequesterCI, func(r *CertRequest) {
			r.Extensions = map[string]string{"permit-pty": ""}
			r.ValidBefore = r.ValidAfter.Add(2 * time.Hour)
		}},
		{"CI with agent forwarding", RequesterCI, func(r *CertRequest) {
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
				t.Fatalf("expected PolicyViolationError, got: %v", err)
			}
			if pv.Error() == "" || pv.RequesterType != tc.requesterType {
				t.Fatalf("incomplete error: %+v", pv)
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
		t.Fatalf("allowed principal rejected: %v", err)
	}
	req.Principals = []string{"root"}
	var pv *PolicyViolationError
	if err := engine.Validate(RequesterUser, req); !errors.As(err, &pv) {
		t.Fatalf("expected PolicyViolationError, got: %v", err)
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
		t.Fatalf("valid host request rejected: %v", err)
	}
}
