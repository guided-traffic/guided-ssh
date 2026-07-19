package ca

import "fmt"

// UserKeyID baut die KeyID eines Benutzer-Zertifikats: user:<sub>@<idp>.
func UserKeyID(subject, issuer string) string {
	return fmt.Sprintf("user:%s@%s", subject, issuer)
}

// CIKeyID baut die KeyID eines CI-Zertifikats: ci:<project>:<pipeline>.
func CIKeyID(projectPath, pipelineID string) string {
	return fmt.Sprintf("ci:%s:%s", projectPath, pipelineID)
}

// HostKeyID baut die KeyID eines Host-Zertifikats: host:<name>.
func HostKeyID(hostname string) string {
	return fmt.Sprintf("host:%s", hostname)
}
