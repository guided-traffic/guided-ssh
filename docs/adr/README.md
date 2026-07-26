# Architecture Decision Records

Every significant architecture decision is recorded as a numbered ADR
(format: [000-template.md](000-template.md)). Numbers are sequential, files are
never deleted — superseded decisions get the status "superseded by ADR-NNN".

| ADR | Title | Status |
|---|---|---|
| [001](001-backend-go.md) | Backend in Go | accepted |
| [002](002-postgresql.md) | PostgreSQL as the database | accepted |
| [003](003-frontend-angular-embedded.md) | Angular SPA, embedded in the Go binary | accepted |
| [004](004-ansible-reference-only.md) | Ansible as reference playbooks only | accepted |
| [005](005-host-integration-phases.md) | Host integration: sshd-native first, NSS/PAM later | accepted |
| [006](006-signer-interface-kms.md) | Signer interface: software key first, KMS/HSM later | accepted |
| [007](007-deployment-helm-fluxcd.md) | Deployment via Helm chart, FluxCD-compatible | accepted |
| [008](008-api-rest-mtls-oidc.md) | REST+JSON; mTLS for hosts, OIDC for humans/CI | accepted |
| [009](009-build-tooling-make-golangci.md) | Build tooling: Makefile + golangci-lint | accepted |
| [010](010-container-image-dockerfile.md) | Container image via Dockerfile (instead of ko) | accepted |
| [011](011-versioning-and-license.md) | Versioning (SemVer) and license (Apache-2.0) | accepted |
| [012](012-migrations-goose.md) | Schema migrations with goose (embedded) | accepted |
| [013](013-repository-layer-pgx.md) | Repository layer directly with pgx (no sqlc) | accepted |
| [014](014-software-signer-aes-gcm.md) | Software signer with AES-256-GCM-encrypted CA keys | accepted |
| [015](015-oidc-go-oidc-group-sync.md) | OIDC via go-oidc/x-oauth2, group sync via Keycloak Admin API | accepted |
| [016](016-cli-gssh-agent-only.md) | CLI `gssh`: agent-only keys, SPKI pinning, Match-exec integration | accepted |
| [017](017-host-enrollment-mtls.md) | Host enrollment: one-time token, mTLS mini-PKI, fail-closed principals | accepted |
| [018](018-grants-additive.md) | Grant model: additive, identity principals, declarative reconciliation | accepted |
| [019](019-gitlab-ci-grants.md) | GitLab CI: dedicated verifier, CI grants, project principals | accepted |
| [020](020-web-ui-roles-audit-export.md) | Web UI: role model, generated API client, audit export/streaming | accepted |
| [021](021-session-audit-host.md) | Session audit on the host: pam_exec, serial correlation, opt-in | accepted |
| [022](022-revocation-short-lifetimes.md) | Revocation: short lifetimes primarily, RevokedKeys as fallback | accepted |
</content>
