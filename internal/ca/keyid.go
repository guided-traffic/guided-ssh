package ca

import (
	"fmt"
	"strings"
)

// UserKeyID baut die KeyID eines Benutzer-Zertifikats: user:<sub>@<idp>.
func UserKeyID(subject, issuer string) string {
	return fmt.Sprintf("user:%s@%s", subject, issuer)
}

// CIKeyID baut die KeyID eines CI-Zertifikats:
// ci:<project_path>:<pipeline_id>:<job_id> — jede Ausstellung ist im Audit
// eindeutig einer Pipeline und einem Job zuzuordnen (Phase 7).
func CIKeyID(projectPath, pipelineID, jobID string) string {
	return fmt.Sprintf("ci:%s:%s:%s", projectPath, pipelineID, jobID)
}

// CIPrincipals sind die Identitäts-Principals eines CI-Zertifikats (ADR-019):
// ci:<project_path> plus alle Namespace-Vorfahren (ci:infra/ansible, ci:infra).
// Welche lokalen Benutzer sie auf einem Host erreichen, entscheiden die
// CI-Grants über AuthorizedPrincipalsCommand — analog ADR-018.
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

// HostKeyID baut die KeyID eines Host-Zertifikats: host:<name>.
func HostKeyID(hostname string) string {
	return fmt.Sprintf("host:%s", hostname)
}
