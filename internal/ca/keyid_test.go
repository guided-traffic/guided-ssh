package ca

import (
	"slices"
	"testing"
)

func TestKeyIDs(t *testing.T) {
	if got := UserKeyID("sub-1", "https://idp"); got != "user:sub-1@https://idp" {
		t.Errorf("UserKeyID = %q", got)
	}
	if got := CIKeyID("infra/ansible", "4711", "815"); got != "ci:infra/ansible:4711:815" {
		t.Errorf("CIKeyID = %q", got)
	}
	if got := HostKeyID("web1"); got != "host:web1" {
		t.Errorf("HostKeyID = %q", got)
	}
}

func TestCIPrincipals(t *testing.T) {
	cases := []struct {
		project string
		want    []string
	}{
		{"app", []string{"ci:app"}},
		{"infra/ansible", []string{"ci:infra/ansible", "ci:infra"}},
		{"a/b/c", []string{"ci:a/b/c", "ci:a/b", "ci:a"}},
	}
	for _, c := range cases {
		if got := CIPrincipals(c.project); !slices.Equal(got, c.want) {
			t.Errorf("CIPrincipals(%q) = %v, erwartet %v", c.project, got, c.want)
		}
	}
}
