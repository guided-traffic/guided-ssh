package store

import (
	"errors"
	"testing"
)

func TestWildcardMatch(t *testing.T) {
	cases := []struct {
		pattern, value string
		want           bool
	}{
		{"", "", true},
		{"main", "main", true},
		{"main", "master", false},
		{"*", "beliebig/mit/slash", true},
		{"release/*", "release/1.2", true},
		{"release/*", "release/", true},
		{"release/*", "release", false},
		{"*-stable", "1.2-stable", true},
		{"*-stable", "stable-1.2", false},
		{"a*a", "a", false},
		{"a*a", "aa", true},
		{"v*.*", "v1.2", true},
		{"prod-*", "prod-eu", true},
		{"prod-*", "staging-eu", false},
	}
	for _, c := range cases {
		if got := wildcardMatch(c.pattern, c.value); got != c.want {
			t.Errorf("wildcardMatch(%q, %q) = %t, erwartet %t", c.pattern, c.value, got, c.want)
		}
	}
}

func TestCIGrantMatches(t *testing.T) {
	base := CIMatch{ProjectPath: "infra/ansible", Ref: "main", RefProtected: true}

	cases := []struct {
		name  string
		grant CIGrant
		match CIMatch
		want  bool
	}{
		{"exaktes projekt", CIGrant{ProjectPath: "infra/ansible", ProtectedOnly: true}, base, true},
		{"namespace-präfix", CIGrant{ProjectPath: "infra", ProtectedOnly: true}, base, true},
		{"kein präfix an wortgrenze", CIGrant{ProjectPath: "inf", ProtectedOnly: true}, base, false},
		{"fremdes projekt", CIGrant{ProjectPath: "andere/app", ProtectedOnly: true}, base, false},
		{
			"protected verlangt, ref unprotected",
			CIGrant{ProjectPath: "infra/ansible", ProtectedOnly: true},
			CIMatch{ProjectPath: "infra/ansible", Ref: "main", RefProtected: false},
			false,
		},
		{
			"unprotected erlaubt",
			CIGrant{ProjectPath: "infra/ansible", ProtectedOnly: false},
			CIMatch{ProjectPath: "infra/ansible", Ref: "feature/x", RefProtected: false},
			true,
		},
		{
			"ref-muster passt",
			CIGrant{ProjectPath: "infra/ansible", ProtectedOnly: true, RefPattern: "release/*"},
			CIMatch{ProjectPath: "infra/ansible", Ref: "release/1.2", RefProtected: true},
			true,
		},
		{
			"ref-muster passt nicht",
			CIGrant{ProjectPath: "infra/ansible", ProtectedOnly: true, RefPattern: "release/*"},
			base, false,
		},
		{
			"environment verlangt, job ohne environment",
			CIGrant{ProjectPath: "infra/ansible", ProtectedOnly: true, EnvironmentPattern: "prod"},
			base, false,
		},
		{
			"environment passt",
			CIGrant{ProjectPath: "infra/ansible", ProtectedOnly: true, EnvironmentPattern: "prod*"},
			CIMatch{ProjectPath: "infra/ansible", Ref: "main", RefProtected: true, Environment: "prod-eu"},
			true,
		},
	}
	for _, c := range cases {
		if got := c.grant.Matches(c.match); got != c.want {
			t.Errorf("%s: Matches = %t, erwartet %t", c.name, got, c.want)
		}
	}
}

func TestValidateCIGrantSpec(t *testing.T) {
	valid := CIGrantSpec{ProjectPath: "infra/ansible", Principals: []string{"deploy"}, MaxValiditySeconds: 3600}
	if err := validateCIGrantSpec(0, valid); err != nil {
		t.Errorf("gültige spec abgelehnt: %v", err)
	}
	cases := []struct {
		name string
		spec CIGrantSpec
	}{
		{"ohne projekt", CIGrantSpec{Principals: []string{"deploy"}, MaxValiditySeconds: 3600}},
		{"ohne principals", CIGrantSpec{ProjectPath: "x", MaxValiditySeconds: 3600}},
		{"ohne laufzeit", CIGrantSpec{ProjectPath: "x", Principals: []string{"deploy"}}},
	}
	for _, c := range cases {
		err := validateCIGrantSpec(1, c.spec)
		if !errors.Is(err, ErrInvalidGrantSpec) {
			t.Errorf("%s: err = %v, erwartet ErrInvalidGrantSpec", c.name, err)
		}
	}
}
