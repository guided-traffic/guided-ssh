//go:build e2e

package e2e

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// pullSecretName is the image pull secret the suite creates when the
// driver's Docker config holds Docker Hub credentials.
const pullSecretName = "dockerhub"

// dockerHubKeys are the keys under which a Docker config can hold Docker Hub
// credentials; `docker login` writes the first.
var dockerHubKeys = []string{"https://index.docker.io/v1/", "index.docker.io", "docker.io", "registry-1.docker.io"}

// dockerHubAuth returns a dockerconfigjson carrying only the Docker Hub entry
// of the driver's Docker config, or nil when it has no inline credentials for
// Docker Hub. The kind nodes pull the third-party images themselves and know
// nothing of the driver's `docker login`: without a pull secret every
// in-cluster pull is anonymous and shares the per-IP rate limit with
// everything else behind the same address. Credentials kept in a credential
// helper (Docker Desktop) are not inline — the suite then pulls anonymously.
func dockerHubAuth() []byte {
	dir := os.Getenv("DOCKER_CONFIG")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil
		}
		dir = filepath.Join(home, ".docker")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		return nil
	}
	var cfg struct {
		Auths map[string]struct {
			Auth string `json:"auth"`
		} `json:"auths"`
	}
	if json.Unmarshal(raw, &cfg) != nil {
		return nil
	}
	for _, key := range dockerHubKeys {
		if entry := cfg.Auths[key]; entry.Auth != "" {
			out, err := json.Marshal(map[string]any{
				"auths": map[string]any{dockerHubKeys[0]: map[string]string{"auth": entry.Auth}},
			})
			if err != nil {
				return nil
			}
			return out
		}
	}
	return nil
}

// applyPullSecret stores the Docker Hub credentials in the namespace and
// attaches them to the default service account, which the infrastructure
// pods run as. The chart's pods run as their own service account and get the
// secret through helmPullSecretArgs.
//
// The secret is created from a file and never through applyYAML: a failed
// apply prints the manifest, and with it the credentials, into the CI log.
func (e *env) applyPullSecret() {
	e.t.Helper()
	auth := dockerHubAuth()
	if auth == nil {
		e.t.Log("no inline Docker Hub credentials in the Docker config — in-cluster pulls are anonymous")
		return
	}
	path := filepath.Join(e.tmp, "dockerhub-config.json")
	if err := os.WriteFile(path, auth, 0o600); err != nil {
		e.t.Fatal(err)
	}
	// Delete first: E2E_KEEP reuses the cluster, and create does not overwrite.
	e.mustKubectl("delete", "secret", pullSecretName, "--ignore-not-found")
	e.mustKubectl("create", "secret", "docker-registry", pullSecretName, "--from-file=.dockerconfigjson="+path)
	// The service account controller creates "default" shortly after the
	// namespace; a patch before that fails with NotFound.
	e.poll(60*time.Second, "pull secret on the default service account", func() error {
		_, err := e.kubectl("patch", "serviceaccount", "default",
			"-p", `{"imagePullSecrets":[{"name":"`+pullSecretName+`"}]}`)
		return err
	})
	e.pullSecret = pullSecretName
}

// helmPullSecretArgs hands the pull secret to a chart release, if there is one.
func (e *env) helmPullSecretArgs() []string {
	if e.pullSecret == "" {
		return nil
	}
	return []string{"--set", "imagePullSecrets[0].name=" + e.pullSecret}
}
