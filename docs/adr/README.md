# Architecture Decision Records

Jede wesentliche Architekturentscheidung wird als nummeriertes ADR festgehalten
(Format: [000-template.md](000-template.md)). Nummern fortlaufend, Dateien werden
nie gelöscht — überholte Entscheidungen bekommen Status „abgelöst durch ADR-NNN".

| ADR | Titel | Status |
|---|---|---|
| [001](001-backend-go.md) | Backend in Go | akzeptiert |
| [002](002-postgresql.md) | PostgreSQL als Datenbank | akzeptiert |
| [003](003-frontend-angular-embedded.md) | Angular-SPA, eingebettet ins Go-Binary | akzeptiert |
| [004](004-ansible-nur-referenz.md) | Ansible nur als Referenz-Playbooks | akzeptiert |
| [005](005-host-integration-phasen.md) | Host-Integration: sshd-nativ zuerst, NSS/PAM später | akzeptiert |
| [006](006-signer-interface-kms.md) | Signer-Interface: Software-Key zuerst, KMS/HSM später | akzeptiert |
| [007](007-deployment-helm-fluxcd.md) | Deployment via Helm-Chart, FluxCD-kompatibel | akzeptiert |
| [008](008-api-rest-mtls-oidc.md) | REST+JSON; mTLS für Hosts, OIDC für Menschen/CI | akzeptiert |
| [009](009-build-tooling-make-golangci.md) | Build-Tooling: Makefile + golangci-lint | akzeptiert |
| [010](010-container-image-dockerfile.md) | Container-Image via Dockerfile (statt ko) | akzeptiert |
| [011](011-versionierung-und-lizenz.md) | Versionierung (SemVer) und Lizenz (Apache-2.0) | akzeptiert |
| [012](012-migrations-goose.md) | Schema-Migrationen mit goose (embedded) | akzeptiert |
| [013](013-repository-layer-pgx.md) | Repository-Layer direkt mit pgx (kein sqlc) | akzeptiert |
| [014](014-software-signer-aes-gcm.md) | Software-Signer mit AES-256-GCM-verschlüsselten CA-Keys | akzeptiert |
| [015](015-oidc-go-oidc-gruppen-sync.md) | OIDC via go-oidc/x-oauth2, Gruppen-Sync über Keycloak-Admin-API | akzeptiert |
| [016](016-cli-gssh-agent-only.md) | CLI `gssh`: Agent-only-Schlüssel, SPKI-Pinning, Match-exec-Integration | akzeptiert |
| [017](017-host-enrollment-mtls.md) | Host-Enrollment: Einmal-Token, mTLS-Mini-PKI, Fail-closed-Principals | akzeptiert |
