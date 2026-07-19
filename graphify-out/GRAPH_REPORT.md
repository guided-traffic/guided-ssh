# Graph Report - .  (2026-07-19)

## Corpus Check
- 0 files · ~110,000 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 1171 nodes · 2906 edges · 30 communities detected
- Extraction: 61% EXTRACTED · 39% INFERRED · 0% AMBIGUOUS · INFERRED: 1140 edges (avg confidence: 0.8)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- [[_COMMUNITY_CLI gssh & Agent-Login|CLI gssh & Agent-Login]]
- [[_COMMUNITY_Keycloak-Integration|Keycloak-Integration]]
- [[_COMMUNITY_Store-Fakes (AuthCI)|Store-Fakes (Auth/CI)]]
- [[_COMMUNITY_API-Interfaces & Audit|API-Interfaces & Audit]]
- [[_COMMUNITY_CA-Fakes & CI-Verifier|CA-Fakes & CI-Verifier]]
- [[_COMMUNITY_ADRs 001-005 & Fundament|ADRs 001-005 & Fundament]]
- [[_COMMUNITY_Host-Agent Daemon|Host-Agent Daemon]]
- [[_COMMUNITY_Admin-Store-Fakes & Grants|Admin-Store-Fakes & Grants]]
- [[_COMMUNITY_Gruppen-Sync & Mapper|Gruppen-Sync & Mapper]]
- [[_COMMUNITY_Admin-CLI & YAML-Apply|Admin-CLI & YAML-Apply]]
- [[_COMMUNITY_Admin-API-Handler (GrantsCI)|Admin-API-Handler (Grants/CI)]]
- [[_COMMUNITY_Agent-API (mTLS) & ADRs|Agent-API (mTLS) & ADRs]]
- [[_COMMUNITY_Admin-CLI-Tests (CI)|Admin-CLI-Tests (CI)]]
- [[_COMMUNITY_Admin-API-Tests|Admin-API-Tests]]
- [[_COMMUNITY_ADR-018019 & CI-Rationale|ADR-018/019 & CI-Rationale]]
- [[_COMMUNITY_Software-Signer|Software-Signer]]
- [[_COMMUNITY_Sign-Endpoint-Fakes|Sign-Endpoint-Fakes]]
- [[_COMMUNITY_Enrollment & Host-ACL|Enrollment & Host-ACL]]
- [[_COMMUNITY_Admin-API-Client|Admin-API-Client]]
- [[_COMMUNITY_Domaenen-Datenmodelle|Domaenen-Datenmodelle]]
- [[_COMMUNITY_Agentd mTLS-Client|Agentd mTLS-Client]]
- [[_COMMUNITY_Signer-Interface|Signer-Interface]]
- [[_COMMUNITY_Enrollment-Datenmodell|Enrollment-Datenmodell]]
- [[_COMMUNITY_Host-Enrollment (Plan)|Host-Enrollment (Plan)]]
- [[_COMMUNITY_Store Users|Store: Users]]
- [[_COMMUNITY_Store Issuance|Store: Issuance]]
- [[_COMMUNITY_Store Groups|Store: Groups]]
- [[_COMMUNITY_Store Hosts|Store: Hosts]]
- [[_COMMUNITY_Store CA-Keys|Store: CA-Keys]]
- [[_COMMUNITY_Auth CLI-Flow|Auth: CLI-Flow]]

## God Nodes (most connected - your core abstractions)
1. `Store` - 63 edges
2. `New()` - 56 edges
3. `Run()` - 55 edges
4. `TestKeycloakIntegration()` - 38 edges
5. `run()` - 33 edges
6. `handleSignUser()` - 30 edges
7. `New()` - 29 edges
8. `newFakeAuthStore()` - 28 edges
9. `newFakeSign()` - 27 edges
10. `mustNoErr()` - 24 edges

## Surprising Connections (you probably didn't know these)
- `DefaultPolicies()` --references--> `guided-ssh Design- und Implementierungsplan`  [INFERRED]
  internal/ca/policy.go → INITIAL_PROJECT_PLAN.md
- `Store.CreateCertificateWithAudit (Transactional)` --rationale_for--> `guided-ssh Design- und Implementierungsplan`  [INFERRED]
  internal/store/issuance.go → INITIAL_PROJECT_PLAN.md
- `LoadConfig()` --implements--> `Konfigurationsdatei config.yaml (XDG, yaml.v3, GSSH_CONFIG)`  [INFERRED]
  internal/cli/config.go → docs/adr/016-cli-gssh-agent-only.md
- `Run()` --implements--> `Match-exec ssh_config-Schnipsel (gssh integrate)`  [AMBIGUOUS]
  internal/admincli/cli.go → README.md
- `Run()` --implements--> `gssh-agentd Host-Agent (Subcommands enroll/run/principals, systemd-Dienst, State unter /var/lib/guided-ssh/)`  [INFERRED]
  internal/admincli/cli.go → README.md

## Hyperedges (group relationships)
- **CI-Zertifikatsausstellung: id_tokens -> ci-login -> /v1/sign/ci -> CI-Grant-Matching -> Projekt-Principals -> Host-ACL** — gitlab_ci_id_tokens, gitlab_ci_ci_login, gitlab_ci_sign_ci_endpoint, gitlab_ci_ci_grant, gitlab_ci_project_principals, grants_authorized_principals_command [INFERRED 0.90]
- **Dreifache Laufzeit-Deckelung: CI-Grant-Maximum, CI-Policy (1 h), Token-exp (Job-Timeout)** — gitlab_ci_ci_grant, gitlab_ci_ci_policy, gitlab_ci_id_tokens [INFERRED 0.85]
- **CI-Grant-Verwaltung ueber Admin-API, gssh-admin ci-grant CLI und deklarative grants.yaml** — gitlab_ci_ci_grant, gitlab_ci_ci_grant_cli, grants_gitops_apply [INFERRED 0.80]

## Communities

### Community 0 - "CLI gssh & Agent-Login"
Cohesion: 0.04
Nodes (124): ADR-016: CLI gssh — Agent-only, stdlib-Subkommandos, SPKI-Pinning, Match-exec, Agent-only Schlüssel (ephemerales Ed25519-Paar nur im ssh-agent), Comment-Präfix guided-ssh für Agent-Einträge, Auto-Erneuerung bei Restlaufzeit unter 5 Minuten, Konfigurationsdatei config.yaml (XDG, yaml.v3, GSSH_CONFIG), Match-exec-Integration für transparentes natives ssh, Rationale: keine Platten-Persistenz, Agent räumt via LifetimeSecs selbst auf, Rationale: Puffer für Clock-Skew und Verbindungsaufbau (+116 more)

### Community 1 - "Keycloak-Integration"
Cohesion: 0.04
Nodes (70): KeycloakConfig, keycloakEnv, keycloakGroup, KeycloakSource, keycloakUser, fakeStore, New(), Policy (+62 more)

### Community 2 - "Store-Fakes (Auth/CI)"
Cohesion: 0.06
Nodes (37): agentHost(), fakeAuthStore, fakeCIStore, Store, fakeStore (In-Memory Test Store), eventsActor(), TestApplyCIGrants(), TestCIGrantsCRUD() (+29 more)

### Community 3 - "API-Interfaces & Audit"
Cohesion: 0.04
Nodes (73): CIStore, CITokenVerifier, GrantSource, signUserRequest, signUserResponse, TokenVerifier, Store.AppendAuditEvent, AuditFilter (+65 more)

### Community 4 - "CA-Fakes & CI-Verifier"
Cohesion: 0.05
Nodes (54): fakeStore, fakeVerifier, CIClaims, CIVerifier, CIVerifierConfig, Claims, fakeIDP, flexString (+46 more)

### Community 5 - "ADRs 001-005 & Fundament"
Cohesion: 0.05
Nodes (76): Trigger audit_events_append_only (lehnt UPDATE/DELETE ab), ADR-Template (Kontext/Entscheidung/Konsequenzen), ADR-001: Backend in Go, ADR-001 Begründung: x/crypto/ssh, statische Binaries, ein Sprachstack, ADR-002: PostgreSQL als Datenbank, ADR-002 Begründung: ACID, JSONB, Append-only-Grants, Partitionierung, ADR-003: Angular-SPA, eingebettet ins Go-Binary (embed.FS), ADR-003 Begründung: ein Image, kein CORS, UI-Version konsistent zur API (+68 more)

### Community 6 - "Host-Agent Daemon"
Cohesion: 0.06
Nodes (44): cacheEntry, Config, Daemon, Duration, EnrollOptions, enrollResponse, fakeAPI, Paths (+36 more)

### Community 7 - "Admin-Store-Fakes & Grants"
Cohesion: 0.06
Nodes (30): fakeGitLab, Deps, enrollRequest, enrollResponse, fakeAdminStore, HostStore, CA, newFakeGitLab() (+22 more)

### Community 8 - "Gruppen-Sync & Mapper"
Cohesion: 0.09
Nodes (38): DirectorySource, DirectoryUser, fakeDirectory, Mapper, Store, Syncer, KeycloakSource.get (Admin-API-GET), KeycloakSource (Admin-API-Directory) (+30 more)

### Community 9 - "Admin-CLI & YAML-Apply"
Cohesion: 0.09
Nodes (38): ciGrantEntry, ciGrantFlags, commonFlags, grantEntry, grantsFile, loadGrantsFile(), applyCISpecTx(), ciGrantAuditEvent() (+30 more)

### Community 10 - "Admin-API-Handler (Grants/CI)"
Cohesion: 0.08
Nodes (27): toCIGrantJSON(), validateCIGrantRequest(), grantID(), registerAdminRoutes(), toGrantJSON(), writeJSON(), adminContext, adminHandler (+19 more)

### Community 11 - "Agent-API (mTLS) & ADRs"
Cohesion: 0.07
Nodes (43): ADR-008: REST+JSON; mTLS für Hosts, OIDC für Menschen/CI, ADR-014: Software-Signer mit AES-256-GCM-verschlüsselten CA-Keys, ADR-015: OIDC via go-oidc, Gruppen-Sync über Keycloak-Admin-API, ADR-016: CLI gssh — Agent-only-Schlüssel, SPKI-Pinning, ADR-017: Host-Enrollment mit Einmal-Token, mTLS-Mini-PKI, Fail-closed-Principals, ADR-Index (docs/adr/README.md), Agent-Listener -agent-listen (TLS-Serverzertifikat aus mTLS-CA, SANs via GSSH_AGENT_TLS_NAMES, RequireAndVerifyClientCert), NewAgent() (+35 more)

### Community 12 - "Admin-CLI-Tests (CI)"
Cohesion: 0.09
Nodes (38): fakeAdminAPI, boolPtr(), TestApplyMitCIGrants(), TestApplyOhneCIAbschnittLaesstCIGrantsUnberuehrt(), TestCIGrantCreate(), TestCIGrantCreatePflichtfelder(), TestCIGrantDelete(), TestCIGrantList() (+30 more)

### Community 13 - "Admin-API-Tests"
Cohesion: 0.17
Nodes (38): TestAdminCIApply(), TestAdminCIGrantCRUD(), TestAdminCIGrantValidierung(), adminCall(), adminClaims(), newAdminServer(), newFakeAdminStore(), TestAdminApply() (+30 more)

### Community 14 - "ADR-018/019 & CI-Rationale"
Cohesion: 0.09
Nodes (40): ADR-018: Grant-Modell (additiv, Identitaets-Principals), Rationale: additiv/kein deny (keine Konflikte, Vereinigung), Rationale: Identitaets- statt Ziel-Principals (Entzugs-Timing), ADR-019: GitLab-CI — CI-Grants und Projekt-Principals, Rationale: eigenes ci_grants-Modell statt Gruppen-Grants, Rationale: Projekt-Identitaets-Principals (Host entscheidet, granulare Bindung), Rationale: eigener Verifier/Endpoint (keine Audience-/Issuer-Vermischung), Self-hosted Runner Anforderungen (GitHub Actions) (+32 more)

### Community 15 - "Software-Signer"
Cohesion: 0.12
Nodes (20): ADR-014 (Private Key Encryption at Rest), fakeConnMetadata, SoftwareSigner, decryptPrivateKey(), encryptPrivateKey(), newGCM(), TestDecryptFalscherKey(), TestDecryptZuKurzesChiffrat() (+12 more)

### Community 16 - "Sign-Endpoint-Fakes"
Cohesion: 0.11
Nodes (14): fakeAuthStore, fakeIDP (Fake-OIDC-Provider), keycloakEnv (Container-URLs), Mapper (Claims auf Benutzer), auth.Store (Persistenz-Interface), api.Deps (Handler-Abhaengigkeiten), fakeStore (In-Memory CA-Store), fakeAuthStore (api_test, In-Memory auth.Store) (+6 more)

### Community 17 - "Enrollment & Host-ACL"
Cohesion: 0.22
Nodes (18): agentRequest(), enrolledHost(), newAgentHandler(), TestAgentBundle(), TestAgentPrincipals(), TestAgentRenew(), TestAgentRenewFehlerfaelle(), fakeHostStore (+10 more)

### Community 18 - "Admin-API-Client"
Cohesion: 0.18
Nodes (5): ApplyResult, CIGrant, client, Grant, newClient()

### Community 19 - "Domaenen-Datenmodelle"
Cohesion: 0.2
Nodes (8): AccessGrant, AuditEvent, CAKey, Certificate, Group, Host, ServiceAccount, User

### Community 20 - "Agentd mTLS-Client"
Cohesion: 0.38
Nodes (2): agentAPI, apiClient

### Community 21 - "Signer-Interface"
Cohesion: 0.67
Nodes (2): CertRequest, Signer

### Community 22 - "Enrollment-Datenmodell"
Cohesion: 0.67
Nodes (2): EnrollHostParams, EnrollmentToken

### Community 23 - "Host-Enrollment (Plan)"
Cohesion: 1.0
Nodes (2): Host-Verwaltung (Enrollment, Tags, Zertifikatsrotation), Phase 5 — Host-Enrollment & Host-Agent (gssh-agentd)

### Community 24 - "Store: Users"
Cohesion: 1.0
Nodes (0): 

### Community 25 - "Store: Issuance"
Cohesion: 1.0
Nodes (0): 

### Community 26 - "Store: Groups"
Cohesion: 1.0
Nodes (0): 

### Community 27 - "Store: Hosts"
Cohesion: 1.0
Nodes (0): 

### Community 28 - "Store: CA-Keys"
Cohesion: 1.0
Nodes (0): 

### Community 29 - "Auth: CLI-Flow"
Cohesion: 1.0
Nodes (1): auth.Flow (CLI-Login-Flows)

## Ambiguous Edges - Review These
- `ADR-010: Container-Image via Multi-Stage-Dockerfile (statt ko), distroless nonroot` → `CI-Secrets (DOCKERHUB_PAT, BOT_PAT für semantic-release/Renovate)`  [AMBIGUOUS]
  docs/ci-runner.md · relation: conceptually_related_to
- `Run()` → `Match-exec ssh_config-Schnipsel (gssh integrate)`  [AMBIGUOUS]
  README.md · relation: implements

## Knowledge Gaps
- **129 isolated node(s):** `DirectoryUser`, `DirectorySource`, `FlowConfig`, `Store`, `KeycloakConfig` (+124 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **Thin community `Host-Enrollment (Plan)`** (2 nodes): `Host-Verwaltung (Enrollment, Tags, Zertifikatsrotation)`, `Phase 5 — Host-Enrollment & Host-Agent (gssh-agentd)`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Store: Users`** (1 nodes): `users.go`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Store: Issuance`** (1 nodes): `issuance.go`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Store: Groups`** (1 nodes): `groups.go`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Store: Hosts`** (1 nodes): `hosts.go`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Store: CA-Keys`** (1 nodes): `ca_keys.go`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Auth: CLI-Flow`** (1 nodes): `auth.Flow (CLI-Login-Flows)`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **What is the exact relationship between `ADR-010: Container-Image via Multi-Stage-Dockerfile (statt ko), distroless nonroot` and `CI-Secrets (DOCKERHUB_PAT, BOT_PAT für semantic-release/Renovate)`?**
  _Edge tagged AMBIGUOUS (relation: conceptually_related_to) - confidence is low._
- **What is the exact relationship between `Run()` and `Match-exec ssh_config-Schnipsel (gssh integrate)`?**
  _Edge tagged AMBIGUOUS (relation: implements) - confidence is low._
- **Why does `New()` connect `Admin-Store-Fakes & Grants` to `CLI gssh & Agent-Login`, `Keycloak-Integration`, `Store-Fakes (Auth/CI)`, `API-Interfaces & Audit`, `CA-Fakes & CI-Verifier`, `Host-Agent Daemon`, `Gruppen-Sync & Mapper`, `Admin-CLI & YAML-Apply`, `Admin-API-Handler (Grants/CI)`, `Admin-API-Tests`, `Enrollment & Host-ACL`?**
  _High betweenness centrality (0.290) - this node is a cross-community bridge._
- **Why does `Store` connect `Store-Fakes (Auth/CI)` to `CLI gssh & Agent-Login`, `Keycloak-Integration`, `API-Interfaces & Audit`, `CA-Fakes & CI-Verifier`, `Admin-Store-Fakes & Grants`, `Gruppen-Sync & Mapper`, `Admin-CLI & YAML-Apply`, `Admin-API-Handler (Grants/CI)`, `Sign-Endpoint-Fakes`?**
  _High betweenness centrality (0.140) - this node is a cross-community bridge._
- **Why does `TestKeycloakIntegration()` connect `Keycloak-Integration` to `Store-Fakes (Auth/CI)`, `API-Interfaces & Audit`, `CA-Fakes & CI-Verifier`, `Admin-Store-Fakes & Grants`, `Gruppen-Sync & Mapper`, `Admin-API-Client`?**
  _High betweenness centrality (0.134) - this node is a cross-community bridge._
- **Are the 4 inferred relationships involving `Store` (e.g. with `.handleToken()` and `TestDeviceFlow()`) actually correct?**
  _`Store` has 4 INFERRED edges - model-reasoned connections that need verification._
- **Are the 51 inferred relationships involving `New()` (e.g. with `run()` and `serve()`) actually correct?**
  _`New()` has 51 INFERRED edges - model-reasoned connections that need verification._