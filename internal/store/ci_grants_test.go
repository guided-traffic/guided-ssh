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
		{"*", "anything/with/slash", true},
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
			t.Errorf("wildcardMatch(%q, %q) = %t, want %t", c.pattern, c.value, got, c.want)
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
		{"exact project", CIGrant{ProjectPath: "infra/ansible", ProtectedOnly: true}, base, true},
		{"namespace prefix", CIGrant{ProjectPath: "infra", ProtectedOnly: true}, base, true},
		{"no prefix at word boundary", CIGrant{ProjectPath: "inf", ProtectedOnly: true}, base, false},
		{"unrelated project", CIGrant{ProjectPath: "other/app", ProtectedOnly: true}, base, false},
		{
			"protected required, ref unprotected",
			CIGrant{ProjectPath: "infra/ansible", ProtectedOnly: true},
			CIMatch{ProjectPath: "infra/ansible", Ref: "main", RefProtected: false},
			false,
		},
		{
			"unprotected allowed",
			CIGrant{ProjectPath: "infra/ansible", ProtectedOnly: false},
			CIMatch{ProjectPath: "infra/ansible", Ref: "feature/x", RefProtected: false},
			true,
		},
		{
			"ref pattern matches",
			CIGrant{ProjectPath: "infra/ansible", ProtectedOnly: true, RefPattern: "release/*"},
			CIMatch{ProjectPath: "infra/ansible", Ref: "release/1.2", RefProtected: true},
			true,
		},
		{
			"ref pattern does not match",
			CIGrant{ProjectPath: "infra/ansible", ProtectedOnly: true, RefPattern: "release/*"},
			base, false,
		},
		{
			"environment required, job without environment",
			CIGrant{ProjectPath: "infra/ansible", ProtectedOnly: true, EnvironmentPattern: "prod"},
			base, false,
		},
		{
			"environment matches",
			CIGrant{ProjectPath: "infra/ansible", ProtectedOnly: true, EnvironmentPattern: "prod*"},
			CIMatch{ProjectPath: "infra/ansible", Ref: "main", RefProtected: true, Environment: "prod-eu"},
			true,
		},
	}
	for _, c := range cases {
		if got := c.grant.Matches(c.match); got != c.want {
			t.Errorf("%s: Matches = %t, want %t", c.name, got, c.want)
		}
	}
}

func TestValidateCIGrantSpec(t *testing.T) {
	valid := CIGrantSpec{ProjectPath: "infra/ansible", Principals: []string{"deploy"}, MaxValiditySeconds: 3600}
	if err := validateCIGrantSpec(0, valid); err != nil {
		t.Errorf("valid spec rejected: %v", err)
	}
	cases := []struct {
		name string
		spec CIGrantSpec
	}{
		{"without project", CIGrantSpec{Principals: []string{"deploy"}, MaxValiditySeconds: 3600}},
		{"without principals", CIGrantSpec{ProjectPath: "x", MaxValiditySeconds: 3600}},
		{"without validity", CIGrantSpec{ProjectPath: "x", Principals: []string{"deploy"}}},
	}
	for _, c := range cases {
		err := validateCIGrantSpec(1, c.spec)
		if !errors.Is(err, ErrInvalidGrantSpec) {
			t.Errorf("%s: err = %v, want ErrInvalidGrantSpec", c.name, err)
		}
	}
}
