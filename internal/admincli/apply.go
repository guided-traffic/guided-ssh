package admincli

import (
	"github.com/guided-traffic/guided-ssh/internal/rulespec"
)

// loadGrantsFile reads the declarative grants file (format: see
// internal/rulespec) and maps it onto the admin API payloads; content
// validation is handled by the server (line context comes from there as an
// index). ciGrants is nil if the ci_grants section is missing from the file.
func loadGrantsFile(path string) (grants []Grant, ciGrants []CIGrant, ciPresent bool, err error) {
	grantSpecs, ciGrantSpecs, ciPresent, err := rulespec.LoadCombined(path)
	if err != nil {
		return nil, nil, false, err
	}
	grants = make([]Grant, 0, len(grantSpecs))
	for _, spec := range grantSpecs {
		grants = append(grants, Grant{
			Group:              spec.Group,
			Issuer:             spec.Issuer,
			TagSelector:        spec.TagSelector,
			Principals:         spec.Principals,
			Sudo:               spec.Sudo,
			MaxValiditySeconds: spec.MaxValiditySeconds,
		})
	}
	if !ciPresent {
		return grants, nil, false, nil
	}
	ciGrants = make([]CIGrant, 0, len(ciGrantSpecs))
	for _, spec := range ciGrantSpecs {
		// rulespec already resolved the protected_only default, so the API
		// payload always carries it explicitly.
		protectedOnly := spec.ProtectedOnly
		ciGrants = append(ciGrants, CIGrant{
			Project:            spec.ProjectPath,
			RefPattern:         spec.RefPattern,
			ProtectedOnly:      &protectedOnly,
			EnvironmentPattern: spec.EnvironmentPattern,
			TagSelector:        spec.TagSelector,
			Principals:         spec.Principals,
			MaxValiditySeconds: spec.MaxValiditySeconds,
		})
	}
	return grants, ciGrants, true, nil
}
