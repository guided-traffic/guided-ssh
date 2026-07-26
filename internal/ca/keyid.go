package ca

import (
	"fmt"
	"strings"
)

// UserKeyID builds the KeyID of a user certificate: user:<sub>@<idp>.
func UserKeyID(subject, issuer string) string {
	return fmt.Sprintf("user:%s@%s", subject, issuer)
}

// CIKeyID builds the KeyID of a CI certificate:
// ci:<project_path>:<pipeline_id>:<job_id> — every issuance is uniquely
// attributable to a pipeline and a job in the audit trail (Phase 7).
func CIKeyID(projectPath, pipelineID, jobID string) string {
	return fmt.Sprintf("ci:%s:%s:%s", projectPath, pipelineID, jobID)
}

// CIPrincipals are the identity principals of a CI certificate (ADR-019):
// ci:<project_path> plus all namespace ancestors (ci:infra/ansible, ci:infra).
// Which local users they can reach on a host is decided by the CI grants via
// AuthorizedPrincipalsCommand — analogous to ADR-018.
func CIPrincipals(projectPath string) []string {
	principals := []string{"ci:" + projectPath}
	for {
		idx := strings.LastIndex(projectPath, "/")
		if idx <= 0 {
			return principals
		}
		projectPath = projectPath[:idx]
		principals = append(principals, "ci:"+projectPath)
	}
}

// HostKeyID builds the KeyID of a host certificate: host:<name>.
func HostKeyID(hostname string) string {
	return fmt.Sprintf("host:%s", hostname)
}
