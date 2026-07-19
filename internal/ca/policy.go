package ca

import (
	"fmt"
	"slices"
	"time"

	"github.com/guided-traffic/guided-ssh/internal/store"
)

// Requester-Typen: wer fordert ein Zertifikat an. Sie bestimmen die Policy;
// "user" und "ci" führen zu Benutzer-, "host" zu Host-Zertifikaten.
const (
	RequesterUser = "user"
	RequesterCI   = "ci"
	RequesterHost = "host"
)

// maxBackdate erlaubt beim Ausstellen eine kleine Rückdatierung von
// ValidAfter (Clock-Skew zwischen CA und Hosts).
const maxBackdate = 5 * time.Minute

// Policy begrenzt, was ein Requester-Typ signiert bekommt.
type Policy struct {
	// CertType ist der einzige Zertifikatstyp, den dieser Requester erhält.
	CertType string
	// MaxValidity ist die maximale Laufzeit (ValidBefore − ValidAfter).
	MaxValidity time.Duration
	// AllowedPrincipals ist eine Whitelist; leer ⇒ alle Principals erlaubt
	// (die konkrete Principal-Ableitung übernehmen Grants ab Phase 6).
	AllowedPrincipals []string
	// AllowedExtensions ist eine Whitelist; leer ⇒ keine Extensions erlaubt.
	AllowedExtensions []string
	// AllowedCriticalOptions ist eine Whitelist; leer ⇒ keine Critical Options erlaubt.
	AllowedCriticalOptions []string
}

// PolicyViolationError beschreibt eine Regelverletzung; sie ist von
// technischen Fehlern unterscheidbar (API kann daraus 4xx statt 5xx machen).
type PolicyViolationError struct {
	RequesterType string
	Reason        string
}

func (e *PolicyViolationError) Error() string {
	return fmt.Sprintf("policy-verstoß (%s): %s", e.RequesterType, e.Reason)
}

// PolicyEngine prüft Zertifikats-Requests gegen die Policy ihres Requester-Typs.
type PolicyEngine struct {
	policies map[string]Policy
	now      func() time.Time
}

// NewPolicyEngine baut eine Engine aus Policies pro Requester-Typ.
func NewPolicyEngine(policies map[string]Policy) *PolicyEngine {
	return &PolicyEngine{policies: policies, now: time.Now}
}

// DefaultPolicies liefert die Standard-Policies des Plans: Benutzer ~16 h,
// CI ≤ 1 h mit minimalen Extensions, Hosts 30 Tage ohne Extensions.
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

// Validate prüft den Request gegen die Policy des Requester-Typs.
// Verstöße kommen als *PolicyViolationError zurück.
func (e *PolicyEngine) Validate(requesterType string, req CertRequest) error {
	violation := func(format string, args ...any) error {
		return &PolicyViolationError{RequesterType: requesterType, Reason: fmt.Sprintf(format, args...)}
	}

	policy, ok := e.policies[requesterType]
	if !ok {
		return violation("unbekannter requester-typ")
	}
	if req.CertType != policy.CertType {
		return violation("zertifikatstyp %q nicht erlaubt (erwartet %q)", req.CertType, policy.CertType)
	}
	if req.KeyID == "" {
		return violation("keyid fehlt")
	}
	if len(req.Principals) == 0 {
		return violation("keine principals angegeben")
	}
	if len(policy.AllowedPrincipals) > 0 {
		for _, p := range req.Principals {
			if !slices.Contains(policy.AllowedPrincipals, p) {
				return violation("principal %q nicht erlaubt", p)
			}
		}
	}
	for ext := range req.Extensions {
		if !slices.Contains(policy.AllowedExtensions, ext) {
			return violation("extension %q nicht erlaubt", ext)
		}
	}
	for opt := range req.CriticalOptions {
		if !slices.Contains(policy.AllowedCriticalOptions, opt) {
			return violation("critical option %q nicht erlaubt", opt)
		}
	}
	if !req.ValidBefore.After(req.ValidAfter) {
		return violation("valid_before liegt nicht nach valid_after")
	}
	if lifetime := req.ValidBefore.Sub(req.ValidAfter); lifetime > policy.MaxValidity {
		return violation("laufzeit %s überschreitet maximum %s", lifetime, policy.MaxValidity)
	}
	if now := e.now(); req.ValidAfter.Before(now.Add(-maxBackdate)) {
		return violation("valid_after liegt mehr als %s in der vergangenheit", maxBackdate)
	}
	return nil
}
