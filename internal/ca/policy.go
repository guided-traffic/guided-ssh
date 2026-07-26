package ca

import (
	"fmt"
	"slices"
	"time"

	"github.com/guided-traffic/guided-ssh/internal/store"
)

// Requester types: who requests a certificate. They determine the policy;
// "user" and "ci" lead to user certificates, "host" to host certificates.
const (
	RequesterUser = "user"
	RequesterCI   = "ci"
	RequesterHost = "host"
)

// maxBackdate allows a small backdating of ValidAfter on issuance
// (clock skew between the CA and hosts).
const maxBackdate = 5 * time.Minute

// Policy limits what a requester type gets signed.
type Policy struct {
	// CertType is the only certificate type this requester gets.
	CertType string
	// MaxValidity is the maximum lifetime (ValidBefore − ValidAfter).
	MaxValidity time.Duration
	// AllowedPrincipals is a whitelist; empty ⇒ all principals allowed
	// (the concrete principal derivation is taken over by grants from Phase 6).
	AllowedPrincipals []string
	// AllowedExtensions is a whitelist; empty ⇒ no extensions allowed.
	AllowedExtensions []string
	// AllowedCriticalOptions is a whitelist; empty ⇒ no critical options allowed.
	AllowedCriticalOptions []string
}

// PolicyViolationError describes a rule violation; it is distinguishable
// from technical errors (the API can turn it into a 4xx instead of a 5xx).
type PolicyViolationError struct {
	RequesterType string
	Reason        string
}

func (e *PolicyViolationError) Error() string {
	return fmt.Sprintf("policy violation (%s): %s", e.RequesterType, e.Reason)
}

// PolicyEngine validates certificate requests against their requester type's policy.
type PolicyEngine struct {
	policies map[string]Policy
	now      func() time.Time
}

// NewPolicyEngine builds an engine from policies per requester type.
func NewPolicyEngine(policies map[string]Policy) *PolicyEngine {
	return &PolicyEngine{policies: policies, now: time.Now}
}

// DefaultPolicies returns the plan's default policies: user ~16 h,
// CI ≤ 1 h with minimal extensions, hosts 30 days without extensions.
func DefaultPolicies() map[string]Policy {
	userExtensions := []string{
		"permit-X11-forwarding",
		"permit-agent-forwarding",
		"permit-port-forwarding",
		"permit-pty",
		"permit-user-rc",
	}
	return map[string]Policy{
		RequesterUser: {
			CertType:               store.CertTypeUser,
			MaxValidity:            16 * time.Hour,
			AllowedExtensions:      userExtensions,
			AllowedCriticalOptions: []string{"source-address"},
		},
		RequesterCI: {
			CertType:               store.CertTypeUser,
			MaxValidity:            time.Hour,
			AllowedExtensions:      []string{"permit-pty"},
			AllowedCriticalOptions: []string{"source-address"},
		},
		RequesterHost: {
			CertType:    store.CertTypeHost,
			MaxValidity: 30 * 24 * time.Hour,
		},
	}
}

// Validate validates the request against the requester type's policy.
// Violations come back as *PolicyViolationError.
func (e *PolicyEngine) Validate(requesterType string, req CertRequest) error {
	violation := func(format string, args ...any) error {
		return &PolicyViolationError{RequesterType: requesterType, Reason: fmt.Sprintf(format, args...)}
	}

	policy, ok := e.policies[requesterType]
	if !ok {
		return violation("unknown requester type")
	}
	if req.CertType != policy.CertType {
		return violation("certificate type %q not allowed (expected %q)", req.CertType, policy.CertType)
	}
	if req.KeyID == "" {
		return violation("keyid missing")
	}
	if len(req.Principals) == 0 {
		return violation("no principals given")
	}
	if len(policy.AllowedPrincipals) > 0 {
		for _, p := range req.Principals {
			if !slices.Contains(policy.AllowedPrincipals, p) {
				return violation("principal %q not allowed", p)
			}
		}
	}
	for ext := range req.Extensions {
		if !slices.Contains(policy.AllowedExtensions, ext) {
			return violation("extension %q not allowed", ext)
		}
	}
	for opt := range req.CriticalOptions {
		if !slices.Contains(policy.AllowedCriticalOptions, opt) {
			return violation("critical option %q not allowed", opt)
		}
	}
	if !req.ValidBefore.After(req.ValidAfter) {
		return violation("valid_before is not after valid_after")
	}
	if lifetime := req.ValidBefore.Sub(req.ValidAfter); lifetime > policy.MaxValidity {
		return violation("lifetime %s exceeds maximum %s", lifetime, policy.MaxValidity)
	}
	if now := e.now(); req.ValidAfter.Before(now.Add(-maxBackdate)) {
		return violation("valid_after is more than %s in the past", maxBackdate)
	}
	return nil
}
