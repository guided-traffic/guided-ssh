# Graph Report - .  (2026-07-26)

## Corpus Check
- Large corpus: 279 files · ~277,112 words. Semantic extraction will be expensive (many Claude tokens). Consider running on a subfolder, or use --no-semantic to run AST-only.

## Summary
- 2597 nodes · 6369 edges · 251 communities detected
- Extraction: 56% EXTRACTED · 44% INFERRED · 0% AMBIGUOUS · INFERRED: 2798 edges (avg confidence: 0.79)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- [[_COMMUNITY_Audit & CI Grant Data Layer|Audit & CI Grant Data Layer]]
- [[_COMMUNITY_Admin API Grant & Enrollment Handlers|Admin API Grant & Enrollment Handlers]]
- [[_COMMUNITY_SSH Agent Certificate Management|SSH Agent Certificate Management]]
- [[_COMMUNITY_Agent Daemon Session & Auth Cache|Agent Daemon Session & Auth Cache]]
- [[_COMMUNITY_CA Signer Lifecycle|CA Signer Lifecycle]]
- [[_COMMUNITY_Admin Authentication & Grant Apply Tests|Admin Authentication & Grant Apply Tests]]
- [[_COMMUNITY_E2E Test Harness & Deployment Setup|E2E Test Harness & Deployment Setup]]
- [[_COMMUNITY_OIDC Auth & CLI Design Decisions|OIDC Auth & CLI Design Decisions]]
- [[_COMMUNITY_Angular Generated API Client|Angular Generated API Client]]
- [[_COMMUNITY_Web UI Audit & Grants Pages|Web UI Audit & Grants Pages]]
- [[_COMMUNITY_Agent Session Handler Tests|Agent Session Handler Tests]]
- [[_COMMUNITY_Directory Sync (Users & Groups)|Directory Sync (Users & Groups)]]
- [[_COMMUNITY_Rate Limiter|Rate Limiter]]
- [[_COMMUNITY_CI Grants & SPKI Pin Dialer|CI Grants & SPKI Pin Dialer]]
- [[_COMMUNITY_CI OIDC Token Verifier|CI OIDC Token Verifier]]
- [[_COMMUNITY_Go Backend & Host Integration ADRs|Go Backend & Host Integration ADRs]]
- [[_COMMUNITY_CI Grant CRUD Handlers|CI Grant CRUD Handlers]]
- [[_COMMUNITY_Agent Binary Distribution|Agent Binary Distribution]]
- [[_COMMUNITY_OIDC Login Flows (PKCEDeviceClientCreds)|OIDC Login Flows (PKCE/Device/ClientCreds)]]
- [[_COMMUNITY_One-Command Host Install Docs|One-Command Host Install Docs]]
- [[_COMMUNITY_gssh-server Bootstrap & Config|gssh-server Bootstrap & Config]]
- [[_COMMUNITY_GitLab CI E2E Test Fakes|GitLab CI E2E Test Fakes]]
- [[_COMMUNITY_Fake Admin Store (Grants)|Fake Admin Store (Grants)]]
- [[_COMMUNITY_Angular SPA Embedding & Audit Streaming|Angular SPA Embedding & Audit Streaming]]
- [[_COMMUNITY_CI Grant Request Types|CI Grant Request Types]]
- [[_COMMUNITY_Fuzz & Session Test Harness|Fuzz & Session Test Harness]]
- [[_COMMUNITY_CLI Sign & Login Tests|CLI Sign & Login Tests]]
- [[_COMMUNITY_Audit Streamer DrainEmit|Audit Streamer Drain/Emit]]
- [[_COMMUNITY_Test Config Writer Helper|Test Config Writer Helper]]
- [[_COMMUNITY_usersgo + UserDetailed|usersgo + UserDetailed]]
- [[_COMMUNITY_hostsgo + HostDetailed|hostsgo + HostDetailed]]
- [[_COMMUNITY_CIVerifierConfig + VerifierConfig|CIVerifierConfig + VerifierConfig]]
- [[_COMMUNITY_newTestSigner test CA + testSignCert|newTestSigner test CA + testSignCert]]
- [[_COMMUNITY_addForeignKey + testKeyPair|addForeignKey + testKeyPair]]
- [[_COMMUNITY_spkiPin test helper + fakeSign struct|spkiPin test helper + fakeSign struct]]
- [[_COMMUNITY_clientdo generic HTTP call + TestAPIErrorIsReported|clientdo generic HTTP call + TestAPIErrorIsReported]]
- [[_COMMUNITY_grantEntry struct + Grant struct|grantEntry struct + Grant struct]]
- [[_COMMUNITY_postEnroll + TestEnrollTokenSingleUse|postEnroll + TestEnrollTokenSingleUse]]
- [[_COMMUNITY_enrollBody + TestEnrollSuccess|enrollBody + TestEnrollSuccess]]
- [[_COMMUNITY_handleListHosts + hostJSON|handleListHosts + hostJSON]]
- [[_COMMUNITY_handleListUsers + userJSON|handleListUsers + userJSON]]
- [[_COMMUNITY_handleUpdateServiceAccount + serviceAccountJSON|handleUpdateServiceAccount + serviceAccountJSON]]
- [[_COMMUNITY_agentManifestItem struct + installScriptData struct|agentManifestItem struct + installScriptData struct]]
- [[_COMMUNITY_PinProviderStatus + rolloutGatestatus|PinProviderStatus + rolloutGatestatus]]
- [[_COMMUNITY_PinStatus struct + rolloutStatus struct|PinStatus struct + rolloutStatus struct]]
- [[_COMMUNITY_AdminStore interface + fakeAdminStore|AdminStore interface + fakeAdminStore]]
- [[_COMMUNITY_EnrollRequest interface + EnrollResponse interface|EnrollRequest interface + EnrollResponse interface]]
- [[_COMMUNITY_Generating CA Key Material + Kubernetes Secret Mounting for|Generating CA Key Material + Kubernetes Secret Mounting for ]]
- [[_COMMUNITY_Security Model Summary + README Security model host rollout|Security Model Summary + README: Security model host rollout]]
- [[_COMMUNITY_CLAUDEmd Project context + guided-ssh designimplementation|CLAUDEmd: Project context + guided-ssh design/implementation]]
- [[_COMMUNITY_Helm chart README Installation|Helm chart README: Installation]]
- [[_COMMUNITY_manifestsgo|manifestsgo]]
- [[_COMMUNITY_embedgo|embedgo]]
- [[_COMMUNITY_maints|maints]]
- [[_COMMUNITY_approutests|approutests]]
- [[_COMMUNITY_appconfigts|appconfigts]]
- [[_COMMUNITY_formatspects|formatspects]]
- [[_COMMUNITY_host-add-dialogspects|host-add-dialogspects]]
- [[_COMMUNITY_strict-http-responsets|strict-http-responsets]]
- [[_COMMUNITY_modelsts|modelsts]]
- [[_COMMUNITY_functionsts|functionsts]]
- [[_COMMUNITY_enroll-responsets|enroll-responsets]]
- [[_COMMUNITY_ui-configts|ui-configts]]
- [[_COMMUNITY_enroll-requestts|enroll-requestts]]
- [[_COMMUNITY_grant-requestts|grant-requestts]]
- [[_COMMUNITY_rollout-unavailablets|rollout-unavailablets]]
- [[_COMMUNITY_groupts|groupts]]
- [[_COMMUNITY_ci-grant-requestts|ci-grant-requestts]]
- [[_COMMUNITY_grantts|grantts]]
- [[_COMMUNITY_agent-manifestts|agent-manifestts]]
- [[_COMMUNITY_audit-eventts|audit-eventts]]
- [[_COMMUNITY_agent-binaryts|agent-binaryts]]
- [[_COMMUNITY_auth-sessionts|auth-sessionts]]
- [[_COMMUNITY_sign-requestts|sign-requestts]]
- [[_COMMUNITY_apply-resultts|apply-resultts]]
- [[_COMMUNITY_hostts|hostts]]
- [[_COMMUNITY_certificatets|certificatets]]
- [[_COMMUNITY_audit-listts|audit-listts]]
- [[_COMMUNITY_ci-grantts|ci-grantts]]
- [[_COMMUNITY_userts|userts]]
- [[_COMMUNITY_sign-responsets|sign-responsets]]
- [[_COMMUNITY_issuancego|issuancego]]
- [[_COMMUNITY_groupsgo|groupsgo]]
- [[_COMMUNITY_ca_keysgo|ca_keysgo]]
- [[_COMMUNITY_AgentHeartbeats counter|AgentHeartbeats counter]]
- [[_COMMUNITY_FlowConfig|FlowConfig]]
- [[_COMMUNITY_errFakeStore|errFakeStore]]
- [[_COMMUNITY_fakeAuthStorefail|fakeAuthStorefail]]
- [[_COMMUNITY_fakeAuthStoreGetUserBySubject|fakeAuthStoreGetUserBySubject]]
- [[_COMMUNITY_fakeAuthStoreCreateUser|fakeAuthStoreCreateUser]]
- [[_COMMUNITY_fakeAuthStoreUpdateUser|fakeAuthStoreUpdateUser]]
- [[_COMMUNITY_fakeAuthStoreListUsers|fakeAuthStoreListUsers]]
- [[_COMMUNITY_fakeAuthStoreSetUserGroups|fakeAuthStoreSetUserGroups]]
- [[_COMMUNITY_fakeAuthStoreGetGroupByName|fakeAuthStoreGetGroupByName]]
- [[_COMMUNITY_fakeAuthStoreCreateGroup|fakeAuthStoreCreateGroup]]
- [[_COMMUNITY_fakeAuthStoreAppendAuditEvent|fakeAuthStoreAppendAuditEvent]]
- [[_COMMUNITY_fakeAuthStoreauditCount|fakeAuthStoreauditCount]]
- [[_COMMUNITY_fakeAuthStoregroupNames|fakeAuthStoregroupNames]]
- [[_COMMUNITY_flexString|flexString]]
- [[_COMMUNITY_CIVerifierIssuer|CIVerifierIssuer]]
- [[_COMMUNITY_keycloakPageSize const|keycloakPageSize const]]
- [[_COMMUNITY_KeycloakConfig|KeycloakConfig]]
- [[_COMMUNITY_KeycloakSourceIssuer|KeycloakSourceIssuer]]
- [[_COMMUNITY_Verifier|Verifier]]
- [[_COMMUNITY_VerifierIssuer|VerifierIssuer]]
- [[_COMMUNITY_RequesterUser constant|RequesterUser constant]]
- [[_COMMUNITY_RequesterCI constant|RequesterCI constant]]
- [[_COMMUNITY_RequesterHost constant|RequesterHost constant]]
- [[_COMMUNITY_maxBackdate constant|maxBackdate constant]]
- [[_COMMUNITY_SoftwareSignerCAKeyID method|SoftwareSignerCAKeyID method]]
- [[_COMMUNITY_SoftwareSignerPublicKey method|SoftwareSignerPublicKey method]]
- [[_COMMUNITY_FileSignerCAKeyID method|FileSignerCAKeyID method]]
- [[_COMMUNITY_FileSignerPublicKey method|FileSignerPublicKey method]]
- [[_COMMUNITY_ExternalKeyPaths struct|ExternalKeyPaths struct]]
- [[_COMMUNITY_EventKeyRotated audit event constant|EventKeyRotated audit event constant]]
- [[_COMMUNITY_renewMargin constant|renewMargin constant]]
- [[_COMMUNITY_TestLoadIntoAgentAndGsshCerts|TestLoadIntoAgentAndGsshCerts]]
- [[_COMMUNITY_TestCertValid|TestCertValid]]
- [[_COMMUNITY_TestRemoveGsshKeysKeepsForeignKey|TestRemoveGsshKeysKeepsForeignKey]]
- [[_COMMUNITY_fakeIDP struct|fakeIDP struct]]
- [[_COMMUNITY_minimalConfig|minimalConfig]]
- [[_COMMUNITY_stubBrowser|stubBrowser]]
- [[_COMMUNITY_stubExecSSH|stubExecSSH]]
- [[_COMMUNITY_writeJSON test helper|writeJSON test helper]]
- [[_COMMUNITY_TestResolveConfigPath|TestResolveConfigPath]]
- [[_COMMUNITY_TestSignUserWithoutPinSelfSigned|TestSignUserWithoutPinSelfSigned]]
- [[_COMMUNITY_TestRunIntegrate|TestRunIntegrate]]
- [[_COMMUNITY_ApplyResult struct|ApplyResult struct]]
- [[_COMMUNITY_clientgetGrant|clientgetGrant]]
- [[_COMMUNITY_commonFlags struct|commonFlags struct]]
- [[_COMMUNITY_TestString|TestString]]
- [[_COMMUNITY_fakeSessionStore|fakeSessionStore]]
- [[_COMMUNITY_TestRateLimitMapStaysBounded|TestRateLimitMapStaysBounded]]
- [[_COMMUNITY_SessionStore interface|SessionStore interface]]
- [[_COMMUNITY_sessionEvent struct|sessionEvent struct]]
- [[_COMMUNITY_renewRequest struct|renewRequest struct]]
- [[_COMMUNITY_renewResponse struct|renewResponse struct]]
- [[_COMMUNITY_principalsResponse struct|principalsResponse struct]]
- [[_COMMUNITY_renewMTLSRequest struct|renewMTLSRequest struct]]
- [[_COMMUNITY_renewMTLSResponse struct|renewMTLSResponse struct]]
- [[_COMMUNITY_RateLimiterConfig struct|RateLimiterConfig struct]]
- [[_COMMUNITY_RateLimiterallow|RateLimiterallow]]
- [[_COMMUNITY_bucket struct token bucket|bucket struct token bucket]]
- [[_COMMUNITY_PinProviderConfig struct|PinProviderConfig struct]]
- [[_COMMUNITY_PinProviderRun|PinProviderRun]]
- [[_COMMUNITY_rolloutGateallow|rolloutGateallow]]
- [[_COMMUNITY_rolloutUnavailable struct|rolloutUnavailable struct]]
- [[_COMMUNITY_enrollRequest struct|enrollRequest struct]]
- [[_COMMUNITY_grantJSON struct|grantJSON struct]]
- [[_COMMUNITY_grantRequest struct|grantRequest struct]]
- [[_COMMUNITY_adminContextensureGroup|adminContextensureGroup]]
- [[_COMMUNITY_uiSession struct|uiSession struct]]
- [[_COMMUNITY_uiAuthState struct|uiAuthState struct]]
- [[_COMMUNITY_uiAuthContext struct|uiAuthContext struct]]
- [[_COMMUNITY_uiAuthContexthandleLogout|uiAuthContexthandleLogout]]
- [[_COMMUNITY_uiAuthContexthandleMe|uiAuthContexthandleMe]]
- [[_COMMUNITY_Config auditstream|Config auditstream]]
- [[_COMMUNITY_syncBuffer|syncBuffer]]
- [[_COMMUNITY_Paths|Paths]]
- [[_COMMUNITY_apiClientBundle|apiClientBundle]]
- [[_COMMUNITY_Daemon|Daemon]]
- [[_COMMUNITY_socketTokenHeader|socketTokenHeader]]
- [[_COMMUNITY_GetUserBySubject|GetUserBySubject]]
- [[_COMMUNITY_UserDetailed|UserDetailed]]
- [[_COMMUNITY_querier|querier]]
- [[_COMMUNITY_AuditFilter|AuditFilter]]
- [[_COMMUNITY_auditFilterWhere|auditFilterWhere]]
- [[_COMMUNITY_ListActiveSessions|ListActiveSessions]]
- [[_COMMUNITY_Close|Close]]
- [[_COMMUNITY_ErrNotFound|ErrNotFound]]
- [[_COMMUNITY_GetGrant|GetGrant]]
- [[_COMMUNITY_GrantWithGroup|GrantWithGroup]]
- [[_COMMUNITY_GetGrantDetailed|GetGrantDetailed]]
- [[_COMMUNITY_ListGrantsDetailed|ListGrantsDetailed]]
- [[_COMMUNITY_ListGrants|ListGrants]]
- [[_COMMUNITY_ListGrantsForGroups|ListGrantsForGroups]]
- [[_COMMUNITY_ApplyResult|ApplyResult]]
- [[_COMMUNITY_ServiceAccount|ServiceAccount]]
- [[_COMMUNITY_GetGroup|GetGroup]]
- [[_COMMUNITY_GetGroupByName|GetGroupByName]]
- [[_COMMUNITY_ListGroups|ListGroups]]
- [[_COMMUNITY_GetHost|GetHost]]
- [[_COMMUNITY_GetHostByName|GetHostByName]]
- [[_COMMUNITY_ListHosts|ListHosts]]
- [[_COMMUNITY_UpdateHost|UpdateHost]]
- [[_COMMUNITY_HostDetailed|HostDetailed]]
- [[_COMMUNITY_GetHostTags|GetHostTags]]
- [[_COMMUNITY_NextCertificateSerial|NextCertificateSerial]]
- [[_COMMUNITY_GetCertificateBySerial|GetCertificateBySerial]]
- [[_COMMUNITY_ListCertificates|ListCertificates]]
- [[_COMMUNITY_ListCAKeys|ListCAKeys]]
- [[_COMMUNITY_EventHostEnrolled|EventHostEnrolled]]
- [[_COMMUNITY_EventEnrollTokenCreated|EventEnrollTokenCreated]]
- [[_COMMUNITY_CIGrant|CIGrant]]
- [[_COMMUNITY_CIMatch|CIMatch]]
- [[_COMMUNITY_StoreGetCIGrant|StoreGetCIGrant]]
- [[_COMMUNITY_StoreListCIGrants|StoreListCIGrants]]
- [[_COMMUNITY_CIGrantSpec|CIGrantSpec]]
- [[_COMMUNITY_Role type|Role type]]
- [[_COMMUNITY_Parameter abstract class|Parameter abstract class]]
- [[_COMMUNITY_ApplyResult|ApplyResult]]
- [[_COMMUNITY_AuditList|AuditList]]
- [[_COMMUNITY_User|User]]
- [[_COMMUNITY_ListGroups$Params|ListGroups$Params]]
- [[_COMMUNITY_ListUsers$Params|ListUsers$Params]]
- [[_COMMUNITY_ListHosts$Params|ListHosts$Params]]
- [[_COMMUNITY_ListCertificates$Params|ListCertificates$Params]]
- [[_COMMUNITY_GetInstallScript$Params|GetInstallScript$Params]]
- [[_COMMUNITY_DownloadAgent$Params|DownloadAgent$Params]]
- [[_COMMUNITY_GetAgentManifest$Params|GetAgentManifest$Params]]
- [[_COMMUNITY_PostAuthLogout$Params|PostAuthLogout$Params]]
- [[_COMMUNITY_GetUiConfig$Params|GetUiConfig$Params]]
- [[_COMMUNITY_GetAuthMe$Params|GetAuthMe$Params]]
- [[_COMMUNITY_GetHealth$Params|GetHealth$Params]]
- [[_COMMUNITY_ExportAudit$Json$Params|ExportAudit$Json$Params]]
- [[_COMMUNITY_ListAudit$Params|ListAudit$Params]]
- [[_COMMUNITY_ExportAudit$Csv$Params|ExportAudit$Csv$Params]]
- [[_COMMUNITY_SignUser$Params|SignUser$Params]]
- [[_COMMUNITY_SignCi$Params|SignCi$Params]]
- [[_COMMUNITY_gssh-admin CLI Component|gssh-admin CLI Component]]
- [[_COMMUNITY_SIEM Consumer Component|SIEM Consumer Component]]
- [[_COMMUNITY_cmdgssh maingo user CLI entrypoint|cmd/gssh maingo user CLI entrypoint]]
- [[_COMMUNITY_cmdgssh-admin maingo admin CLI entrypoint|cmd/gssh-admin maingo admin CLI entrypoint]]
- [[_COMMUNITY_gssh-admin main|gssh-admin main]]
- [[_COMMUNITY_gssh-agentd main|gssh-agentd main]]
- [[_COMMUNITY_envwaitError|envwaitError]]
- [[_COMMUNITY_gitlabFakediscoveryJSON|gitlabFakediscoveryJSON]]
- [[_COMMUNITY_gitlabFakejwksJSON|gitlabFakejwksJSON]]
- [[_COMMUNITY_DEVELOPERmd gssh-server|DEVELOPERmd: gssh-server]]
- [[_COMMUNITY_DEVELOPERmd gssh user CLI|DEVELOPERmd: gssh user CLI]]
- [[_COMMUNITY_DEVELOPERmd gssh-admin admin CLI|DEVELOPERmd: gssh-admin admin CLI]]
- [[_COMMUNITY_DEVELOPERmd gssh-agentd host agent|DEVELOPERmd: gssh-agentd host agent]]
- [[_COMMUNITY_DEVELOPERmd License and versioning|DEVELOPERmd: License and versioning]]
- [[_COMMUNITY_README Key features|README: Key features]]
- [[_COMMUNITY_README How it works|README: How it works]]
- [[_COMMUNITY_README Quick start|README: Quick start]]
- [[_COMMUNITY_README GitLab CI|README: GitLab CI]]
- [[_COMMUNITY_Terminology publicagent listener, pin, fail-closed, hairpin|Terminology public/agent listener, pin, fail-closed, hairpin]]
- [[_COMMUNITY_Feasibility assessment|Feasibility assessment]]
- [[_COMMUNITY_Target Flow UX|Target Flow UX]]
- [[_COMMUNITY_CLAUDEmd Project orientation graphify usage|CLAUDEmd: Project orientation graphify usage]]
- [[_COMMUNITY_CLAUDEmd Language policy English only|CLAUDEmd: Language policy English only]]
- [[_COMMUNITY_Flux example repo structure|Flux example: repo structure]]
- [[_COMMUNITY_Flux example bootstrap|Flux example: bootstrap]]
- [[_COMMUNITY_Flux example IdP service account for sync|Flux example: IdP service account for sync]]
- [[_COMMUNITY_Flux example upgrade path|Flux example: upgrade path]]
- [[_COMMUNITY_Helm chart README PostgreSQL|Helm chart README: PostgreSQL]]
- [[_COMMUNITY_Helm chart README Database migrations|Helm chart README: Database migrations]]
- [[_COMMUNITY_Helm chart README Agent API mTLS|Helm chart README: Agent API mTLS]]
- [[_COMMUNITY_Helm chart README Metrics|Helm chart README: Metrics]]
- [[_COMMUNITY_Helm chart README Chart release GitHub Pages|Helm chart README: Chart release GitHub Pages]]

## God Nodes (most connected - your core abstractions)
1. `run()` - 96 edges
2. `New()` - 95 edges
3. `Store` - 73 edges
4. `get()` - 46 edges
5. `newFakeAuthStore()` - 45 edges
6. `Run()` - 41 edges
7. `cleanDB()` - 41 edges
8. `mustNoErr()` - 41 edges
9. `env` - 40 edges
10. `newFakeIDP()` - 33 edges

## Surprising Connections (you probably didn't know these)
- `Phase E — Docs, Helm, E2E` --cites--> `TestE2E()`  [INFERRED]
  ONE_CMD_INSTALL.md → test/e2e/e2e_test.go
- `staticTokenVerifier` --semantically_similar_to--> `FakeSession`  [INFERRED] [semantically similar]
  internal/store/selfmanaged_ca_integration_test.go → web/src/app/core/role.guard.spec.ts
- `testInternalDatabase` --references--> `Helm chart README: Internal database (test only)`  [INFERRED]
  test/e2e/e2e_test.go → deploy/helm/guided-ssh/README.md
- `env.buildArtifacts` --conceptually_related_to--> `DEVELOPER.md: Development workflow (make targets)`  [INFERRED]
  test/e2e/setup.go → DEVELOPER.md
- `Phase 13 — Quality Assurance & Release` --cites--> `TestSignEndpointLast()`  [EXTRACTED]
  INITIAL_PROJECT_PLAN.md → test/load/sign_load_test.go

## Hyperedges (group relationships)
- **Parallel OIDC token verification for users vs CI jobs** — verifier_verifier_verify, verifier_claims, gitlab_civerifier_verify, gitlab_ciclaims, verifier_errinvalidtoken [INFERRED 0.75]
- **Directory sync reconciles IdP group state into local DB** — sync_syncer_synconce, sync_syncer_reconcile, mapper_mapper_ensuregroups, keycloak_keycloaksource_users, sync_directorysource [INFERRED 0.80]
- **Flow's three OIDC grant flows sharing id_token extraction** — flow_flow_authcodepkce, flow_flow_deviceflow, flow_flow_clientcredentials, flow_idtokenfrom [INFERRED 0.80]
- **Self-managed CA key adoption and rotation lifecycle (mounted files -> ca_keys rows -> signer -> retirement)** — keyfiles_externalkeys, ca_adoptexternalkeys, filesigner_filesigner, ca_retirekey [INFERRED 0.80]
- **Validate-sign-persist certificate issuance pipeline** — ca_issue, policy_validate, signer_signer, ca_store [EXTRACTED 0.90]
- **CLI/CI credential exchange and ssh-agent loading flow** — cilogin_cilogin, client_signci, agent_loadintoagent, agent_connectagent [EXTRACTED 0.85]
- **CI Grant CRUD Flow (CLI to API)** — cigrant_runcigrantcmd, client_listcigrants, client_createcigrant, admin_ci_handlelistcigrants, admin_ci_cigrantjson [INFERRED 0.85]
- **Declarative GitOps Grants Sync (apply -f)** — apply_loadgrantsfile, cli_runapplycmd, client_applygrants, client_applycigrants, admin_ci_handleapplycigrants [INFERRED 0.85]
- **OIDC/Service-Account Authentication for Admin CLI** — cli_connect, login_fetchidtoken, login_fetchservicetoken, cli_commonflags [INFERRED 0.80]
- **Host rollout gate: manifest, download, install.sh gated by pin+binaries+URLs** — rollout_rolloutgate, agents_handleagentmanifest, agents_handleagentdownload, install_script_handleinstallscript, pinprovider_pinprovider [EXTRACTED 0.90]
- **Admin API dual authentication: bearer token or BFF UI session cookie** — admin_admincontext, admin_authenticate, ui_auth_uiauthcontext, ui_auth_sessionfromrequest [EXTRACTED 0.85]
- **Host certificate lifecycle: enrollment issuance and mTLS-authenticated renewal share issueHostCert** — enroll_issuehostcert, enroll_handleenroll, agent_agentrenew, agent_agenthost [EXTRACTED 0.85]
- **Fail-closed security pattern across pinning, principals, and grant issuance** — pintls_verifier, principals_printprincipals, sign_handlesignuser [INFERRED 0.75]
- **Fail-open pam_exec session/sudo audit hook** — pam_runpamsession, cli_runpamsessioncmd, enroll_writepamfiles [INFERRED 0.85]
- **mTLS client certificate issuance and rotation lifecycle** — enroll_writestate, client_newapiclient, client_setclientcert [INFERRED 0.70]
- **Generic query helpers backing repository CRUD** — query_queryone, query_queryall, query_execaffectingone, users_createuser, hosts_createhost, ca_keys_createcakey, grants_creategranttx, audit_insertauditevent [INFERRED 0.80]
- **Mutation + audit event written atomically in one transaction** — grants_creategranttx, sessions_openhostsession, enrollment_enrollhost, issuance_createcertificatewithaudit, audit_insertauditevent [INFERRED 0.85]
- **Two-thirds-of-validity rotation/lifecycle logic for certs and CA keys** — daemon_needsrenewal, daemon_mtlsneedsrotation, ca_keys_adoptcakey, ca_keys_updatecakeystate [INFERRED 0.70]
- **SELF_MANAGED_CA.md Phase 3 integration test suite** — selfmanaged_ca_integration_test_testselfmanagedcafullissuepath, selfmanaged_ca_integration_test_testmanagedtoselfmanagedswitchover, selfmanaged_ca_integration_test_testselfmanagedcadatabaseisderivedstate [EXTRACTED 0.90]
- **CI grant declarative GitOps reconciliation** — ci_grants_applycigrants, ci_grants_applycispectx, ci_grants_createcigranttx, ci_grants_updatecigranttx, ci_grants_deletecigranttx [EXTRACTED 0.85]
- **Guard against the infinite roleGuard redirect-loop regression** — smoke_servedist, role_guard_roleguard, role_guard_spec_roleguard, app_routes_routes [INFERRED 0.85]
- **Generated Angular API Client Infrastructure** — api_configuration_apiconfiguration, request_builder_requestbuilder, strict_http_response_stricthttpresponse, api_api [INFERRED 0.85]
- **CI Access Rule CRUD Flow** — ci_cipage, ci_cigrantdialog, ci_grant_request_cigrantrequest, create_ci_grant_createcigrant, update_ci_grant_updatecigrant [INFERRED 0.80]
- **Host Enrollment Token Generation Flow** — host_add_dialog_hostadddialog, create_enroll_token_createenrolltoken, agent_manifest_agentmanifest, host_add_dialog_witharch, host_add_dialog_twostepcommands [INFERRED 0.80]
- **Grants CRUD + Bulk Apply API** — list_grants_listgrants, create_grant_creategrant, get_grant_getgrant, update_grant_updategrant, delete_grant_deletegrant, apply_grants_applygrants [INFERRED 0.85]
- **CI-Grants CRUD + Bulk Apply API** — list_ci_grants_listcigrants, create_ci_grant_createcigrant, get_ci_grant_getcigrant, update_ci_grant_updatecigrant, delete_ci_grant_deletecigrant, apply_ci_grants_applycigrants [INFERRED 0.85]
- **Host Enrollment and Trust Bootstrap Flow** — enroll_host_enrollhost, get_ca_bundle_getcabundle, host_host, certificate_certificate [INFERRED 0.70]
- **App sidenav sections map to admin directory/audit/sign API domains** — app_template, list_hosts_listhosts, list_users_listusers, list_groups_listgroups, list_audit_listaudit, sign_ci_signci [INFERRED 0.60]
- **Audit list and export endpoints share identical filter parameter shape (event_type, actor, q, since, until)** — list_audit_listaudit, export_audit_json_exportaudit_json, export_audit_csv_exportaudit_csv [INFERRED 0.85]
- **App shell drives session bootstrap/login/logout using system auth and config endpoints** — app_template, get_auth_me_getauthme, get_ui_config_getuiconfig, post_auth_logout_postauthlogout, get_health_gethealth [INFERRED 0.55]
- **Fail-closed Principals Lookup as the Revocation Mechanism** — architecture_principals_lookup, grants_evaluation_points, operations_manual_revocation, 022_revocation_short_lifetimes_principals_lookup, troubleshooting_host_login_fails [INFERRED 0.75]
- **CA Key Rotation and Lifecycle Across Managed/Self-managed Modes** — self_managed_ca_rotation, operations_manual_ca_key_rotation, 022_revocation_short_lifetimes_ca_rotation, threat_model_ca_private_keys [INFERRED 0.70]
- **Append-only Audit Integrity Guarantee Across DB, Threat Model, and SIEM Export** — audit_retention_append_only_guarantee, threat_model_audit_log_integrity, 002_postgresql_decision, web_ui_audit_streaming [INFERRED 0.70]
- **GitLab CI Certificate Issuance Flow** — 019_ci_grants_model, 019_project_principals, 019_keyid, 019_ci_login [EXTRACTED 0.90]
- **CA Key Material Protection Strategy (Interface + Encryption + mTLS PKI)** — 006_signer_interface_kms, 014_software_signer_aes_gcm, 017_mtls_minipki [INFERRED 0.75]
- **Thin CLI Entry-Point Pattern (main delegates to internal Run)** — cmd_gssh_main_main, cmd_gssh_admin_main_main, cmd_gssh_agentd_main_main, cmd_gssh_server_main_main [INFERRED 0.80]
- **Fixed-order E2E scenario suite (SSO, grants, CI, rotation, chaos, offboarding, audit, internal DB)** — e2e_test_teste2e, e2e_test_testssologin, e2e_test_testgrantchange, e2e_test_testciprovisioning, e2e_test_testhostrotation, e2e_test_testchaos, e2e_test_testoffboarding, e2e_test_testaudit, e2e_test_testinternaldatabase [EXTRACTED 0.95]
- **Self-managed CA adopt-on-start and rotation design** — self_managed_ca_d4_adopt_on_start, self_managed_ca_d6_rotation_flow, self_managed_ca_implementation_decisions, self_managed_ca_open_points [INFERRED 0.75]
- **Mandatory fail-closed SPKI pinning across the host rollout feature** — one_cmd_install_iron_rules, one_cmd_install_phase_p_pinning, one_cmd_install_security_model, readme_security_model, helm_readme_pin_source [INFERRED 0.80]

## Communities

### Community 0 - "Audit & CI Grant Data Layer"
Cohesion: 0.02
Nodes (165): ingestSessionEvent(), fakeCIStore, AppendAuditEvent, auditFilterArgs(), CountAuditEvents, insertAuditEvent(), ListAuditEvents, ListAuditEventsAfter (+157 more)

### Community 1 - "Admin API Grant & Enrollment Handlers"
Cohesion: 0.02
Nodes (131): adminContext struct, handleCreateCIGrant, toCIGrantJSON(), validateCIGrantRequest(), grantID(), adminContext.hasRole, registerAdminRoutes(), toGrantJSON() (+123 more)

### Community 2 - "SSH Agent Certificate Management"
Cohesion: 0.03
Nodes (158): fakeAdminAPI, agentCommentPrefix constant, anyValidCert(), certTime(), certValid(), connectAgent(), gsshCerts(), loadIntoAgent() (+150 more)

### Community 3 - "Agent Daemon Session & Auth Cache"
Cohesion: 0.02
Nodes (131): authRec, authRecord, cacheEntry, Config, Daemon, Duration, EnrollOptions, enrollResponse (+123 more)

### Community 4 - "CA Signer Lifecycle"
Cohesion: 0.03
Nodes (129): CA.activeSigner method, CA.AdoptExternalKeys method, CA.Bundle method, CA, CertRequest, CA.createKey method, CA.EnsureCAKeys method, EventCertIssued audit event constant (+121 more)

### Community 5 - "Admin Authentication & Grant Apply Tests"
Cohesion: 0.04
Nodes (115): adminContext.authenticate, adminContext.authorized, TestAdminCIApply(), TestAdminCIGrantCRUD(), TestAdminCIGrantValidation(), adminContext.handleApplyGrants, adminContext.handleCreateGrant, adminCall() (+107 more)

### Community 6 - "E2E Test Harness & Deployment Setup"
Cohesion: 0.03
Nodes (91): DEVELOPER.md: Development workflow (make targets), env, gitlabFake, portForward, goSSH(), hostKeyCallback, signCIStatus, signUserStatus (+83 more)

### Community 7 - "OIDC Auth & CLI Design Decisions"
Cohesion: 0.02
Nodes (114): ADR Template, ADR-002: PostgreSQL as the Database, ADR-004: Ansible Only as Reference Playbooks, ADR-007: Deployment via Helm chart, FluxCD-compatible, ADR-009: Build Tooling — Makefile + golangci-lint, Claim Mapping, CLI OIDC Flows (x/oauth2), ADR-015: OIDC/Group Sync Decision (+106 more)

### Community 8 - "Angular Generated API Client"
Cohesion: 0.03
Nodes (55): AgentBinary (interface), AgentManifest (interface), Api, ApiFnOptional (type), ApiFnRequired (type), ApiConfiguration, provideApiConfiguration(), App (+47 more)

### Community 9 - "Web UI Audit & Grants Pages"
Cohesion: 0.03
Nodes (50): app.html (Angular App Shell Template), applyCiGrants(), applyGrants(), AuditPage, endOfDay(), AuditEvent (interface), EVENT_TYPES (constant), startOfDay() (+42 more)

### Community 10 - "Agent Session Handler Tests"
Cohesion: 0.05
Nodes (75): AgentDeps struct, newSessionsHandler(), TestAgentSessionsDispatch(), TestAgentSessionsWithoutClientCert(), agentRequest(), enrolledHost(), newAgentHandler(), TestAgentBundle() (+67 more)

### Community 11 - "Directory Sync (Users & Groups)"
Cohesion: 0.04
Nodes (59): DirectorySource, DirectoryUser, fakeAuthStore, fakeDirectory, KeycloakConfig, keycloakEnv, keycloakGroup, KeycloakSource (+51 more)

### Community 12 - "Rate Limiter"
Cohesion: 0.05
Nodes (57): Info, bucket, clientBuckets, RateLimiter, RateLimiterConfig, statusRecorder, CreateEnrollmentToken, EnrollmentToken (+49 more)

### Community 13 - "CI Grants & SPKI Pin Dialer"
Cohesion: 0.06
Nodes (52): ApplyResult, CIGrant, Grant, staticVerifier, agentManifest struct, PinProvider, PinProviderConfig, PinStatus (+44 more)

### Community 14 - "CI OIDC Token Verifier"
Cohesion: 0.07
Nodes (40): CIClaims, CIVerifier, CIVerifierConfig, Claims, fakeIDP, flexString, Verifier, VerifierConfig (+32 more)

### Community 15 - "Go Backend & Host Integration ADRs"
Cohesion: 0.05
Nodes (52): ADR-001: Backend in Go, Rationale: Single Go Stack — x/crypto/ssh, Shared Code, Static Binaries (CGO_ENABLED=0), ADR-005: Host Integration — sshd-native First, NSS/PAM Later, Rationale: Avoid C Interop / Delicate Login-Path Risk, Stage 1 (MVP): Pure sshd Mechanics, Stage 2 (Phase 9): PAM Session/Sudo Audit, Optional NSS, Rationale: Swappable Signing Backend, Uniform Audit (+44 more)

### Community 16 - "CI Grant CRUD Handlers"
Cohesion: 0.08
Nodes (45): handleApplyCIGrants, handleDeleteCIGrant, handleGetCIGrant, handleListCIGrants, handleUpdateCIGrant, ciGrantEntry, ciGrantFlags, commonFlags (+37 more)

### Community 17 - "Agent Binary Distribution"
Cohesion: 0.1
Nodes (31): binFS embed.FS, binPrefix const, ErrNotFound, hashFile(), New(), NewFromFS(), parseName(), Source (+23 more)

### Community 18 - "OIDC Login Flows (PKCE/Device/ClientCreds)"
Cohesion: 0.1
Nodes (30): Flow, FlowConfig, commonFlags.connect (auth resolution), loginOptions, TestClientCredentialsFromEnvironment, TestTokenFromEnvironment, ErrNoIDToken, Flow (+22 more)

### Community 19 - "One-Command Host Install Docs"
Cohesion: 0.07
Nodes (34): DEVELOPER.md: Host rollout (internal/agentdist), Flux example: secrets with SOPS (age), Flux example: self-managed CA keys walkthrough, Helm chart README: CA mode (managed vs self-managed), Helm chart README: Host rollout (one-command install), Helm chart README: Important values table, Helm chart README: Which pin source, Helm chart README: Secrets (+26 more)

### Community 20 - "gssh-server Bootstrap & Config"
Cohesion: 0.11
Nodes (25): cmd/gssh-server genmtlsca_test.go, caModeFromEnv(), checkAudienceSeparation(), dbConnString(), hostCertValidityFromEnv(), newAgentServer() — mTLS agent API server, parseTags(), pinConfigFromEnv() (+17 more)

### Community 21 - "GitLab CI E2E Test Fakes"
Cohesion: 0.11
Nodes (20): fakeGitLab, fakeGitLab test double, newFakeGitLab(), postSignCIRaw(), postSignCIStatus(), runAnsiblePing(), signCICert(), TestGitLabCIEndToEnd() (+12 more)

### Community 22 - "Fake Admin Store (Grants)"
Cohesion: 0.16
Nodes (1): fakeAdminStore

### Community 23 - "Angular SPA Embedding & Audit Streaming"
Cohesion: 0.18
Nodes (11): ADR-003: Angular SPA, Embedded into Go Binary, Monitoring (Prometheus Metrics), Clock Skew Issues, Diagnostic Tools, Angular SPA Embedded via go:embed, Generated API Client (ng-openapi-gen), Web UI Audit Streaming (SIEM), Web UI Build Process (+3 more)

### Community 24 - "CI Grant Request Types"
Cohesion: 0.29
Nodes (7): applyCIRequest, ciGrantJSON (API representation), ciGrantRequest (POST/PUT body), ciGrantEntry struct, ciGrantFlags struct, boolPtr helper, CIGrant struct

### Community 25 - "Fuzz & Session Test Harness"
Cohesion: 0.29
Nodes (7): TestAgentSessionsDispatch, client struct (admin API HTTP client), fakeAdminAPI struct, fakeHostStore, fuzzHandler (test harness), FuzzSignCI, FuzzSignUser

### Community 26 - "CLI Sign & Login Tests"
Cohesion: 0.33
Nodes (6): TestSignUserWithPin, TestRunLogout, TestRunStatusWithCertificate, newFakeIDP, newFakeSign, startAgent (in-memory ssh-agent)

### Community 27 - "Audit Streamer Drain/Emit"
Cohesion: 0.4
Nodes (5): Streamer.drain, Streamer.emit, eventJSON, Streamer.postWebhook, Streamer.Run

### Community 28 - "Test Config Writer Helper"
Cohesion: 0.67
Nodes (3): writeConfig (admincli test helper), TestLoadConfig, writeConfig (cli test helper)

### Community 29 - "usersgo + UserDetailed"
Cohesion: 1.0
Nodes (1): UserDetailed

### Community 30 - "hostsgo + HostDetailed"
Cohesion: 1.0
Nodes (1): HostDetailed

### Community 31 - "CIVerifierConfig + VerifierConfig"
Cohesion: 1.0
Nodes (2): CIVerifierConfig, VerifierConfig

### Community 32 - "newTestSigner test CA + testSignCert"
Cohesion: 1.0
Nodes (2): newTestSigner (test CA), testSignCert

### Community 33 - "addForeignKey + testKeyPair"
Cohesion: 1.0
Nodes (2): addForeignKey, testKeyPair

### Community 34 - "spkiPin test helper + fakeSign struct"
Cohesion: 1.0
Nodes (2): spkiPin (test helper), fakeSign struct

### Community 35 - "clientdo generic HTTP call + TestAPIErrorIsReported"
Cohesion: 1.0
Nodes (2): client.do (generic HTTP call), TestAPIErrorIsReported

### Community 36 - "grantEntry struct + Grant struct"
Cohesion: 1.0
Nodes (2): grantEntry struct, Grant struct

### Community 37 - "postEnroll + TestEnrollTokenSingleUse"
Cohesion: 1.0
Nodes (2): postEnroll, TestEnrollTokenSingleUse

### Community 38 - "enrollBody + TestEnrollSuccess"
Cohesion: 1.0
Nodes (2): enrollBody, TestEnrollSuccess

### Community 39 - "handleListHosts + hostJSON"
Cohesion: 1.0
Nodes (2): handleListHosts, hostJSON

### Community 40 - "handleListUsers + userJSON"
Cohesion: 1.0
Nodes (2): handleListUsers, userJSON

### Community 41 - "handleUpdateServiceAccount + serviceAccountJSON"
Cohesion: 1.0
Nodes (2): handleUpdateServiceAccount, serviceAccountJSON

### Community 42 - "agentManifestItem struct + installScriptData struct"
Cohesion: 1.0
Nodes (2): agentManifestItem struct, installScriptData struct

### Community 43 - "PinProviderStatus + rolloutGatestatus"
Cohesion: 1.0
Nodes (2): PinProvider.Status, rolloutGate.status

### Community 44 - "PinStatus struct + rolloutStatus struct"
Cohesion: 1.0
Nodes (2): PinStatus struct, rolloutStatus struct

### Community 45 - "AdminStore interface + fakeAdminStore"
Cohesion: 1.0
Nodes (2): AdminStore interface, fakeAdminStore

### Community 46 - "EnrollRequest interface + EnrollResponse interface"
Cohesion: 1.0
Nodes (2): EnrollRequest (interface), EnrollResponse (interface)

### Community 47 - "Generating CA Key Material + Kubernetes Secret Mounting for "
Cohesion: 1.0
Nodes (2): Generating CA Key Material, Kubernetes Secret Mounting for CA Keys

### Community 48 - "Security Model Summary + README: Security model host rollout"
Cohesion: 1.0
Nodes (2): Security Model (Summary), README: Security model (host rollout)

### Community 49 - "CLAUDEmd: Project context + guided-ssh design/implementation"
Cohesion: 1.0
Nodes (2): CLAUDE.md: Project context, guided-ssh design/implementation plan overview

### Community 50 - "Helm chart README: Installation"
Cohesion: 1.0
Nodes (2): Helm chart README: Installation, Helm post-install NOTES.txt

### Community 51 - "manifestsgo"
Cohesion: 1.0
Nodes (0): 

### Community 52 - "embedgo"
Cohesion: 1.0
Nodes (0): 

### Community 53 - "maints"
Cohesion: 1.0
Nodes (0): 

### Community 54 - "approutests"
Cohesion: 1.0
Nodes (0): 

### Community 55 - "appconfigts"
Cohesion: 1.0
Nodes (0): 

### Community 56 - "formatspects"
Cohesion: 1.0
Nodes (0): 

### Community 57 - "host-add-dialogspects"
Cohesion: 1.0
Nodes (0): 

### Community 58 - "strict-http-responsets"
Cohesion: 1.0
Nodes (0): 

### Community 59 - "modelsts"
Cohesion: 1.0
Nodes (0): 

### Community 60 - "functionsts"
Cohesion: 1.0
Nodes (0): 

### Community 61 - "enroll-responsets"
Cohesion: 1.0
Nodes (0): 

### Community 62 - "ui-configts"
Cohesion: 1.0
Nodes (0): 

### Community 63 - "enroll-requestts"
Cohesion: 1.0
Nodes (0): 

### Community 64 - "grant-requestts"
Cohesion: 1.0
Nodes (0): 

### Community 65 - "rollout-unavailablets"
Cohesion: 1.0
Nodes (0): 

### Community 66 - "groupts"
Cohesion: 1.0
Nodes (0): 

### Community 67 - "ci-grant-requestts"
Cohesion: 1.0
Nodes (0): 

### Community 68 - "grantts"
Cohesion: 1.0
Nodes (0): 

### Community 69 - "agent-manifestts"
Cohesion: 1.0
Nodes (0): 

### Community 70 - "audit-eventts"
Cohesion: 1.0
Nodes (0): 

### Community 71 - "agent-binaryts"
Cohesion: 1.0
Nodes (0): 

### Community 72 - "auth-sessionts"
Cohesion: 1.0
Nodes (0): 

### Community 73 - "sign-requestts"
Cohesion: 1.0
Nodes (0): 

### Community 74 - "apply-resultts"
Cohesion: 1.0
Nodes (0): 

### Community 75 - "hostts"
Cohesion: 1.0
Nodes (0): 

### Community 76 - "certificatets"
Cohesion: 1.0
Nodes (0): 

### Community 77 - "audit-listts"
Cohesion: 1.0
Nodes (0): 

### Community 78 - "ci-grantts"
Cohesion: 1.0
Nodes (0): 

### Community 79 - "userts"
Cohesion: 1.0
Nodes (0): 

### Community 80 - "sign-responsets"
Cohesion: 1.0
Nodes (0): 

### Community 81 - "issuancego"
Cohesion: 1.0
Nodes (0): 

### Community 82 - "groupsgo"
Cohesion: 1.0
Nodes (0): 

### Community 83 - "ca_keysgo"
Cohesion: 1.0
Nodes (0): 

### Community 84 - "AgentHeartbeats counter"
Cohesion: 1.0
Nodes (1): AgentHeartbeats counter

### Community 85 - "FlowConfig"
Cohesion: 1.0
Nodes (1): FlowConfig

### Community 86 - "errFakeStore"
Cohesion: 1.0
Nodes (1): errFakeStore

### Community 87 - "fakeAuthStorefail"
Cohesion: 1.0
Nodes (1): fakeAuthStore.fail

### Community 88 - "fakeAuthStoreGetUserBySubject"
Cohesion: 1.0
Nodes (1): fakeAuthStore.GetUserBySubject

### Community 89 - "fakeAuthStoreCreateUser"
Cohesion: 1.0
Nodes (1): fakeAuthStore.CreateUser

### Community 90 - "fakeAuthStoreUpdateUser"
Cohesion: 1.0
Nodes (1): fakeAuthStore.UpdateUser

### Community 91 - "fakeAuthStoreListUsers"
Cohesion: 1.0
Nodes (1): fakeAuthStore.ListUsers

### Community 92 - "fakeAuthStoreSetUserGroups"
Cohesion: 1.0
Nodes (1): fakeAuthStore.SetUserGroups

### Community 93 - "fakeAuthStoreGetGroupByName"
Cohesion: 1.0
Nodes (1): fakeAuthStore.GetGroupByName

### Community 94 - "fakeAuthStoreCreateGroup"
Cohesion: 1.0
Nodes (1): fakeAuthStore.CreateGroup

### Community 95 - "fakeAuthStoreAppendAuditEvent"
Cohesion: 1.0
Nodes (1): fakeAuthStore.AppendAuditEvent

### Community 96 - "fakeAuthStoreauditCount"
Cohesion: 1.0
Nodes (1): fakeAuthStore.auditCount

### Community 97 - "fakeAuthStoregroupNames"
Cohesion: 1.0
Nodes (1): fakeAuthStore.groupNames

### Community 98 - "flexString"
Cohesion: 1.0
Nodes (1): flexString

### Community 99 - "CIVerifierIssuer"
Cohesion: 1.0
Nodes (1): CIVerifier.Issuer

### Community 100 - "keycloakPageSize const"
Cohesion: 1.0
Nodes (1): keycloakPageSize const

### Community 101 - "KeycloakConfig"
Cohesion: 1.0
Nodes (1): KeycloakConfig

### Community 102 - "KeycloakSourceIssuer"
Cohesion: 1.0
Nodes (1): KeycloakSource.Issuer

### Community 103 - "Verifier"
Cohesion: 1.0
Nodes (1): Verifier

### Community 104 - "VerifierIssuer"
Cohesion: 1.0
Nodes (1): Verifier.Issuer

### Community 105 - "RequesterUser constant"
Cohesion: 1.0
Nodes (1): RequesterUser constant

### Community 106 - "RequesterCI constant"
Cohesion: 1.0
Nodes (1): RequesterCI constant

### Community 107 - "RequesterHost constant"
Cohesion: 1.0
Nodes (1): RequesterHost constant

### Community 108 - "maxBackdate constant"
Cohesion: 1.0
Nodes (1): maxBackdate constant

### Community 109 - "SoftwareSignerCAKeyID method"
Cohesion: 1.0
Nodes (1): SoftwareSigner.CAKeyID method

### Community 110 - "SoftwareSignerPublicKey method"
Cohesion: 1.0
Nodes (1): SoftwareSigner.PublicKey method

### Community 111 - "FileSignerCAKeyID method"
Cohesion: 1.0
Nodes (1): FileSigner.CAKeyID method

### Community 112 - "FileSignerPublicKey method"
Cohesion: 1.0
Nodes (1): FileSigner.PublicKey method

### Community 113 - "ExternalKeyPaths struct"
Cohesion: 1.0
Nodes (1): ExternalKeyPaths struct

### Community 114 - "EventKeyRotated audit event constant"
Cohesion: 1.0
Nodes (1): EventKeyRotated audit event constant

### Community 115 - "renewMargin constant"
Cohesion: 1.0
Nodes (1): renewMargin constant

### Community 116 - "TestLoadIntoAgentAndGsshCerts"
Cohesion: 1.0
Nodes (1): TestLoadIntoAgentAndGsshCerts

### Community 117 - "TestCertValid"
Cohesion: 1.0
Nodes (1): TestCertValid

### Community 118 - "TestRemoveGsshKeysKeepsForeignKey"
Cohesion: 1.0
Nodes (1): TestRemoveGsshKeysKeepsForeignKey

### Community 119 - "fakeIDP struct"
Cohesion: 1.0
Nodes (1): fakeIDP struct

### Community 120 - "minimalConfig"
Cohesion: 1.0
Nodes (1): minimalConfig

### Community 121 - "stubBrowser"
Cohesion: 1.0
Nodes (1): stubBrowser

### Community 122 - "stubExecSSH"
Cohesion: 1.0
Nodes (1): stubExecSSH

### Community 123 - "writeJSON test helper"
Cohesion: 1.0
Nodes (1): writeJSON (test helper)

### Community 124 - "TestResolveConfigPath"
Cohesion: 1.0
Nodes (1): TestResolveConfigPath

### Community 125 - "TestSignUserWithoutPinSelfSigned"
Cohesion: 1.0
Nodes (1): TestSignUserWithoutPinSelfSigned

### Community 126 - "TestRunIntegrate"
Cohesion: 1.0
Nodes (1): TestRunIntegrate

### Community 127 - "ApplyResult struct"
Cohesion: 1.0
Nodes (1): ApplyResult struct

### Community 128 - "clientgetGrant"
Cohesion: 1.0
Nodes (1): client.getGrant

### Community 129 - "commonFlags struct"
Cohesion: 1.0
Nodes (1): commonFlags struct

### Community 130 - "TestString"
Cohesion: 1.0
Nodes (1): TestString

### Community 131 - "fakeSessionStore"
Cohesion: 1.0
Nodes (1): fakeSessionStore

### Community 132 - "TestRateLimitMapStaysBounded"
Cohesion: 1.0
Nodes (1): TestRateLimitMapStaysBounded

### Community 133 - "SessionStore interface"
Cohesion: 1.0
Nodes (1): SessionStore interface

### Community 134 - "sessionEvent struct"
Cohesion: 1.0
Nodes (1): sessionEvent struct

### Community 135 - "renewRequest struct"
Cohesion: 1.0
Nodes (1): renewRequest struct

### Community 136 - "renewResponse struct"
Cohesion: 1.0
Nodes (1): renewResponse struct

### Community 137 - "principalsResponse struct"
Cohesion: 1.0
Nodes (1): principalsResponse struct

### Community 138 - "renewMTLSRequest struct"
Cohesion: 1.0
Nodes (1): renewMTLSRequest struct

### Community 139 - "renewMTLSResponse struct"
Cohesion: 1.0
Nodes (1): renewMTLSResponse struct

### Community 140 - "RateLimiterConfig struct"
Cohesion: 1.0
Nodes (1): RateLimiterConfig struct

### Community 141 - "RateLimiterallow"
Cohesion: 1.0
Nodes (1): RateLimiter.allow

### Community 142 - "bucket struct token bucket"
Cohesion: 1.0
Nodes (1): bucket struct (token bucket)

### Community 143 - "PinProviderConfig struct"
Cohesion: 1.0
Nodes (1): PinProviderConfig struct

### Community 144 - "PinProviderRun"
Cohesion: 1.0
Nodes (1): PinProvider.Run

### Community 145 - "rolloutGateallow"
Cohesion: 1.0
Nodes (1): rolloutGate.allow

### Community 146 - "rolloutUnavailable struct"
Cohesion: 1.0
Nodes (1): rolloutUnavailable struct

### Community 147 - "enrollRequest struct"
Cohesion: 1.0
Nodes (1): enrollRequest struct

### Community 148 - "grantJSON struct"
Cohesion: 1.0
Nodes (1): grantJSON struct

### Community 149 - "grantRequest struct"
Cohesion: 1.0
Nodes (1): grantRequest struct

### Community 150 - "adminContextensureGroup"
Cohesion: 1.0
Nodes (1): adminContext.ensureGroup

### Community 151 - "uiSession struct"
Cohesion: 1.0
Nodes (1): uiSession struct

### Community 152 - "uiAuthState struct"
Cohesion: 1.0
Nodes (1): uiAuthState struct

### Community 153 - "uiAuthContext struct"
Cohesion: 1.0
Nodes (1): uiAuthContext struct

### Community 154 - "uiAuthContexthandleLogout"
Cohesion: 1.0
Nodes (1): uiAuthContext.handleLogout

### Community 155 - "uiAuthContexthandleMe"
Cohesion: 1.0
Nodes (1): uiAuthContext.handleMe

### Community 156 - "Config auditstream"
Cohesion: 1.0
Nodes (1): Config (auditstream)

### Community 157 - "syncBuffer"
Cohesion: 1.0
Nodes (1): syncBuffer

### Community 158 - "Paths"
Cohesion: 1.0
Nodes (1): Paths

### Community 159 - "apiClientBundle"
Cohesion: 1.0
Nodes (1): apiClient.Bundle

### Community 160 - "Daemon"
Cohesion: 1.0
Nodes (1): Daemon

### Community 161 - "socketTokenHeader"
Cohesion: 1.0
Nodes (1): socketTokenHeader

### Community 162 - "GetUserBySubject"
Cohesion: 1.0
Nodes (1): GetUserBySubject

### Community 163 - "UserDetailed"
Cohesion: 1.0
Nodes (1): UserDetailed

### Community 164 - "querier"
Cohesion: 1.0
Nodes (1): querier

### Community 165 - "AuditFilter"
Cohesion: 1.0
Nodes (1): AuditFilter

### Community 166 - "auditFilterWhere"
Cohesion: 1.0
Nodes (1): auditFilterWhere

### Community 167 - "ListActiveSessions"
Cohesion: 1.0
Nodes (1): ListActiveSessions

### Community 168 - "Close"
Cohesion: 1.0
Nodes (1): Close

### Community 169 - "ErrNotFound"
Cohesion: 1.0
Nodes (1): ErrNotFound

### Community 170 - "GetGrant"
Cohesion: 1.0
Nodes (1): GetGrant

### Community 171 - "GrantWithGroup"
Cohesion: 1.0
Nodes (1): GrantWithGroup

### Community 172 - "GetGrantDetailed"
Cohesion: 1.0
Nodes (1): GetGrantDetailed

### Community 173 - "ListGrantsDetailed"
Cohesion: 1.0
Nodes (1): ListGrantsDetailed

### Community 174 - "ListGrants"
Cohesion: 1.0
Nodes (1): ListGrants

### Community 175 - "ListGrantsForGroups"
Cohesion: 1.0
Nodes (1): ListGrantsForGroups

### Community 176 - "ApplyResult"
Cohesion: 1.0
Nodes (1): ApplyResult

### Community 177 - "ServiceAccount"
Cohesion: 1.0
Nodes (1): ServiceAccount

### Community 178 - "GetGroup"
Cohesion: 1.0
Nodes (1): GetGroup

### Community 179 - "GetGroupByName"
Cohesion: 1.0
Nodes (1): GetGroupByName

### Community 180 - "ListGroups"
Cohesion: 1.0
Nodes (1): ListGroups

### Community 181 - "GetHost"
Cohesion: 1.0
Nodes (1): GetHost

### Community 182 - "GetHostByName"
Cohesion: 1.0
Nodes (1): GetHostByName

### Community 183 - "ListHosts"
Cohesion: 1.0
Nodes (1): ListHosts

### Community 184 - "UpdateHost"
Cohesion: 1.0
Nodes (1): UpdateHost

### Community 185 - "HostDetailed"
Cohesion: 1.0
Nodes (1): HostDetailed

### Community 186 - "GetHostTags"
Cohesion: 1.0
Nodes (1): GetHostTags

### Community 187 - "NextCertificateSerial"
Cohesion: 1.0
Nodes (1): NextCertificateSerial

### Community 188 - "GetCertificateBySerial"
Cohesion: 1.0
Nodes (1): GetCertificateBySerial

### Community 189 - "ListCertificates"
Cohesion: 1.0
Nodes (1): ListCertificates

### Community 190 - "ListCAKeys"
Cohesion: 1.0
Nodes (1): ListCAKeys

### Community 191 - "EventHostEnrolled"
Cohesion: 1.0
Nodes (1): EventHostEnrolled

### Community 192 - "EventEnrollTokenCreated"
Cohesion: 1.0
Nodes (1): EventEnrollTokenCreated

### Community 193 - "CIGrant"
Cohesion: 1.0
Nodes (1): CIGrant

### Community 194 - "CIMatch"
Cohesion: 1.0
Nodes (1): CIMatch

### Community 195 - "StoreGetCIGrant"
Cohesion: 1.0
Nodes (1): Store.GetCIGrant

### Community 196 - "StoreListCIGrants"
Cohesion: 1.0
Nodes (1): Store.ListCIGrants

### Community 197 - "CIGrantSpec"
Cohesion: 1.0
Nodes (1): CIGrantSpec

### Community 198 - "Role type"
Cohesion: 1.0
Nodes (1): Role (type)

### Community 199 - "Parameter abstract class"
Cohesion: 1.0
Nodes (1): Parameter (abstract class)

### Community 200 - "ApplyResult"
Cohesion: 1.0
Nodes (1): ApplyResult

### Community 201 - "AuditList"
Cohesion: 1.0
Nodes (1): AuditList

### Community 202 - "User"
Cohesion: 1.0
Nodes (1): User

### Community 203 - "ListGroups$Params"
Cohesion: 1.0
Nodes (1): ListGroups$Params

### Community 204 - "ListUsers$Params"
Cohesion: 1.0
Nodes (1): ListUsers$Params

### Community 205 - "ListHosts$Params"
Cohesion: 1.0
Nodes (1): ListHosts$Params

### Community 206 - "ListCertificates$Params"
Cohesion: 1.0
Nodes (1): ListCertificates$Params

### Community 207 - "GetInstallScript$Params"
Cohesion: 1.0
Nodes (1): GetInstallScript$Params

### Community 208 - "DownloadAgent$Params"
Cohesion: 1.0
Nodes (1): DownloadAgent$Params

### Community 209 - "GetAgentManifest$Params"
Cohesion: 1.0
Nodes (1): GetAgentManifest$Params

### Community 210 - "PostAuthLogout$Params"
Cohesion: 1.0
Nodes (1): PostAuthLogout$Params

### Community 211 - "GetUiConfig$Params"
Cohesion: 1.0
Nodes (1): GetUiConfig$Params

### Community 212 - "GetAuthMe$Params"
Cohesion: 1.0
Nodes (1): GetAuthMe$Params

### Community 213 - "GetHealth$Params"
Cohesion: 1.0
Nodes (1): GetHealth$Params

### Community 214 - "ExportAudit$Json$Params"
Cohesion: 1.0
Nodes (1): ExportAudit$Json$Params

### Community 215 - "ListAudit$Params"
Cohesion: 1.0
Nodes (1): ListAudit$Params

### Community 216 - "ExportAudit$Csv$Params"
Cohesion: 1.0
Nodes (1): ExportAudit$Csv$Params

### Community 217 - "SignUser$Params"
Cohesion: 1.0
Nodes (1): SignUser$Params

### Community 218 - "SignCi$Params"
Cohesion: 1.0
Nodes (1): SignCi$Params

### Community 219 - "gssh-admin CLI Component"
Cohesion: 1.0
Nodes (1): gssh-admin CLI Component

### Community 220 - "SIEM Consumer Component"
Cohesion: 1.0
Nodes (1): SIEM Consumer Component

### Community 221 - "cmd/gssh maingo user CLI entrypoint"
Cohesion: 1.0
Nodes (1): cmd/gssh main.go (user CLI entrypoint)

### Community 222 - "cmd/gssh-admin maingo admin CLI entrypoint"
Cohesion: 1.0
Nodes (1): cmd/gssh-admin main.go (admin CLI entrypoint)

### Community 223 - "gssh-admin main"
Cohesion: 1.0
Nodes (0): 

### Community 224 - "gssh-agentd main"
Cohesion: 1.0
Nodes (0): 

### Community 225 - "envwaitError"
Cohesion: 1.0
Nodes (1): env.waitError

### Community 226 - "gitlabFakediscoveryJSON"
Cohesion: 1.0
Nodes (1): gitlabFake.discoveryJSON

### Community 227 - "gitlabFakejwksJSON"
Cohesion: 1.0
Nodes (1): gitlabFake.jwksJSON

### Community 228 - "DEVELOPERmd: gssh-server"
Cohesion: 1.0
Nodes (1): DEVELOPER.md: gssh-server

### Community 229 - "DEVELOPERmd: gssh user CLI"
Cohesion: 1.0
Nodes (1): DEVELOPER.md: gssh (user CLI)

### Community 230 - "DEVELOPERmd: gssh-admin admin CLI"
Cohesion: 1.0
Nodes (1): DEVELOPER.md: gssh-admin (admin CLI)

### Community 231 - "DEVELOPERmd: gssh-agentd host agent"
Cohesion: 1.0
Nodes (1): DEVELOPER.md: gssh-agentd (host agent)

### Community 232 - "DEVELOPERmd: License and versioning"
Cohesion: 1.0
Nodes (1): DEVELOPER.md: License and versioning

### Community 233 - "README: Key features"
Cohesion: 1.0
Nodes (1): README: Key features

### Community 234 - "README: How it works"
Cohesion: 1.0
Nodes (1): README: How it works

### Community 235 - "README: Quick start"
Cohesion: 1.0
Nodes (1): README: Quick start

### Community 236 - "README: GitLab CI"
Cohesion: 1.0
Nodes (1): README: GitLab CI

### Community 237 - "Terminology public/agent listener, pin, fail-closed, hairpin"
Cohesion: 1.0
Nodes (1): Terminology (public/agent listener, pin, fail-closed, hairpin)

### Community 238 - "Feasibility assessment"
Cohesion: 1.0
Nodes (1): Feasibility assessment

### Community 239 - "Target Flow UX"
Cohesion: 1.0
Nodes (1): Target Flow (UX)

### Community 240 - "CLAUDEmd: Project orientation graphify usage"
Cohesion: 1.0
Nodes (1): CLAUDE.md: Project orientation (graphify usage)

### Community 241 - "CLAUDEmd: Language policy English only"
Cohesion: 1.0
Nodes (1): CLAUDE.md: Language policy (English only)

### Community 242 - "Flux example: repo structure"
Cohesion: 1.0
Nodes (1): Flux example: repo structure

### Community 243 - "Flux example: bootstrap"
Cohesion: 1.0
Nodes (1): Flux example: bootstrap

### Community 244 - "Flux example: IdP service account for sync"
Cohesion: 1.0
Nodes (1): Flux example: IdP service account for sync

### Community 245 - "Flux example: upgrade path"
Cohesion: 1.0
Nodes (1): Flux example: upgrade path

### Community 246 - "Helm chart README: PostgreSQL"
Cohesion: 1.0
Nodes (1): Helm chart README: PostgreSQL

### Community 247 - "Helm chart README: Database migrations"
Cohesion: 1.0
Nodes (1): Helm chart README: Database migrations

### Community 248 - "Helm chart README: Agent API mTLS"
Cohesion: 1.0
Nodes (1): Helm chart README: Agent API (mTLS)

### Community 249 - "Helm chart README: Metrics"
Cohesion: 1.0
Nodes (1): Helm chart README: Metrics

### Community 250 - "Helm chart README: Chart release GitHub Pages"
Cohesion: 1.0
Nodes (1): Helm chart README: Chart release (GitHub Pages)

## Ambiguous Edges - Review These
- `AuditPage` → `exportAudit$Json()`  [AMBIGUOUS]
  web/src/app/features/audit.ts · relation: conceptually_related_to
- `AuditPage` → `exportAudit$Csv()`  [AMBIGUOUS]
  web/src/app/features/audit.ts · relation: conceptually_related_to
- `getHealth()` → `app.html (Angular App Shell Template)`  [AMBIGUOUS]
  web/src/app/app.html · relation: conceptually_related_to
- `validateCIGrantRequest()` → `TestRateLimitFailureBudgetBlocks`  [AMBIGUOUS]
  internal/api/ratelimit_test.go · relation: semantically_similar_to
- `HostStore interface` → `fakeAuthStore`  [AMBIGUOUS]
  internal/api/sign_test.go · relation: semantically_similar_to

## Knowledge Gaps
- **619 isolated node(s):** `DirectoryUser`, `DirectorySource`, `FlowConfig`, `Store`, `CIClaims` (+614 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **Thin community `usersgo + UserDetailed`** (2 nodes): `users.go`, `UserDetailed`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `hostsgo + HostDetailed`** (2 nodes): `hosts.go`, `HostDetailed`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `CIVerifierConfig + VerifierConfig`** (2 nodes): `CIVerifierConfig`, `VerifierConfig`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `newTestSigner test CA + testSignCert`** (2 nodes): `newTestSigner (test CA)`, `testSignCert`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `addForeignKey + testKeyPair`** (2 nodes): `addForeignKey`, `testKeyPair`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `spkiPin test helper + fakeSign struct`** (2 nodes): `spkiPin (test helper)`, `fakeSign struct`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `clientdo generic HTTP call + TestAPIErrorIsReported`** (2 nodes): `client.do (generic HTTP call)`, `TestAPIErrorIsReported`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `grantEntry struct + Grant struct`** (2 nodes): `grantEntry struct`, `Grant struct`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `postEnroll + TestEnrollTokenSingleUse`** (2 nodes): `postEnroll`, `TestEnrollTokenSingleUse`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `enrollBody + TestEnrollSuccess`** (2 nodes): `enrollBody`, `TestEnrollSuccess`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `handleListHosts + hostJSON`** (2 nodes): `handleListHosts`, `hostJSON`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `handleListUsers + userJSON`** (2 nodes): `handleListUsers`, `userJSON`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `handleUpdateServiceAccount + serviceAccountJSON`** (2 nodes): `handleUpdateServiceAccount`, `serviceAccountJSON`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `agentManifestItem struct + installScriptData struct`** (2 nodes): `agentManifestItem struct`, `installScriptData struct`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `PinProviderStatus + rolloutGatestatus`** (2 nodes): `PinProvider.Status`, `rolloutGate.status`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `PinStatus struct + rolloutStatus struct`** (2 nodes): `PinStatus struct`, `rolloutStatus struct`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `AdminStore interface + fakeAdminStore`** (2 nodes): `AdminStore interface`, `fakeAdminStore`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `EnrollRequest interface + EnrollResponse interface`** (2 nodes): `EnrollRequest (interface)`, `EnrollResponse (interface)`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Generating CA Key Material + Kubernetes Secret Mounting for `** (2 nodes): `Generating CA Key Material`, `Kubernetes Secret Mounting for CA Keys`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Security Model Summary + README: Security model host rollout`** (2 nodes): `Security Model (Summary)`, `README: Security model (host rollout)`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `CLAUDEmd: Project context + guided-ssh design/implementation`** (2 nodes): `CLAUDE.md: Project context`, `guided-ssh design/implementation plan overview`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Helm chart README: Installation`** (2 nodes): `Helm chart README: Installation`, `Helm post-install NOTES.txt`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `manifestsgo`** (1 nodes): `manifests.go`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `embedgo`** (1 nodes): `embed.go`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `maints`** (1 nodes): `main.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `approutests`** (1 nodes): `app.routes.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `appconfigts`** (1 nodes): `app.config.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `formatspects`** (1 nodes): `format.spec.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `host-add-dialogspects`** (1 nodes): `host-add-dialog.spec.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `strict-http-responsets`** (1 nodes): `strict-http-response.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `modelsts`** (1 nodes): `models.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `functionsts`** (1 nodes): `functions.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `enroll-responsets`** (1 nodes): `enroll-response.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `ui-configts`** (1 nodes): `ui-config.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `enroll-requestts`** (1 nodes): `enroll-request.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `grant-requestts`** (1 nodes): `grant-request.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `rollout-unavailablets`** (1 nodes): `rollout-unavailable.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `groupts`** (1 nodes): `group.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `ci-grant-requestts`** (1 nodes): `ci-grant-request.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `grantts`** (1 nodes): `grant.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `agent-manifestts`** (1 nodes): `agent-manifest.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `audit-eventts`** (1 nodes): `audit-event.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `agent-binaryts`** (1 nodes): `agent-binary.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `auth-sessionts`** (1 nodes): `auth-session.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `sign-requestts`** (1 nodes): `sign-request.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `apply-resultts`** (1 nodes): `apply-result.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `hostts`** (1 nodes): `host.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `certificatets`** (1 nodes): `certificate.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `audit-listts`** (1 nodes): `audit-list.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `ci-grantts`** (1 nodes): `ci-grant.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `userts`** (1 nodes): `user.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `sign-responsets`** (1 nodes): `sign-response.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `issuancego`** (1 nodes): `issuance.go`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `groupsgo`** (1 nodes): `groups.go`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `ca_keysgo`** (1 nodes): `ca_keys.go`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `AgentHeartbeats counter`** (1 nodes): `AgentHeartbeats counter`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `FlowConfig`** (1 nodes): `FlowConfig`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `errFakeStore`** (1 nodes): `errFakeStore`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `fakeAuthStorefail`** (1 nodes): `fakeAuthStore.fail`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `fakeAuthStoreGetUserBySubject`** (1 nodes): `fakeAuthStore.GetUserBySubject`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `fakeAuthStoreCreateUser`** (1 nodes): `fakeAuthStore.CreateUser`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `fakeAuthStoreUpdateUser`** (1 nodes): `fakeAuthStore.UpdateUser`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `fakeAuthStoreListUsers`** (1 nodes): `fakeAuthStore.ListUsers`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `fakeAuthStoreSetUserGroups`** (1 nodes): `fakeAuthStore.SetUserGroups`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `fakeAuthStoreGetGroupByName`** (1 nodes): `fakeAuthStore.GetGroupByName`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `fakeAuthStoreCreateGroup`** (1 nodes): `fakeAuthStore.CreateGroup`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `fakeAuthStoreAppendAuditEvent`** (1 nodes): `fakeAuthStore.AppendAuditEvent`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `fakeAuthStoreauditCount`** (1 nodes): `fakeAuthStore.auditCount`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `fakeAuthStoregroupNames`** (1 nodes): `fakeAuthStore.groupNames`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `flexString`** (1 nodes): `flexString`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `CIVerifierIssuer`** (1 nodes): `CIVerifier.Issuer`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `keycloakPageSize const`** (1 nodes): `keycloakPageSize const`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `KeycloakConfig`** (1 nodes): `KeycloakConfig`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `KeycloakSourceIssuer`** (1 nodes): `KeycloakSource.Issuer`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Verifier`** (1 nodes): `Verifier`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `VerifierIssuer`** (1 nodes): `Verifier.Issuer`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `RequesterUser constant`** (1 nodes): `RequesterUser constant`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `RequesterCI constant`** (1 nodes): `RequesterCI constant`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `RequesterHost constant`** (1 nodes): `RequesterHost constant`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `maxBackdate constant`** (1 nodes): `maxBackdate constant`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `SoftwareSignerCAKeyID method`** (1 nodes): `SoftwareSigner.CAKeyID method`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `SoftwareSignerPublicKey method`** (1 nodes): `SoftwareSigner.PublicKey method`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `FileSignerCAKeyID method`** (1 nodes): `FileSigner.CAKeyID method`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `FileSignerPublicKey method`** (1 nodes): `FileSigner.PublicKey method`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `ExternalKeyPaths struct`** (1 nodes): `ExternalKeyPaths struct`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `EventKeyRotated audit event constant`** (1 nodes): `EventKeyRotated audit event constant`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `renewMargin constant`** (1 nodes): `renewMargin constant`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `TestLoadIntoAgentAndGsshCerts`** (1 nodes): `TestLoadIntoAgentAndGsshCerts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `TestCertValid`** (1 nodes): `TestCertValid`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `TestRemoveGsshKeysKeepsForeignKey`** (1 nodes): `TestRemoveGsshKeysKeepsForeignKey`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `fakeIDP struct`** (1 nodes): `fakeIDP struct`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `minimalConfig`** (1 nodes): `minimalConfig`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `stubBrowser`** (1 nodes): `stubBrowser`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `stubExecSSH`** (1 nodes): `stubExecSSH`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `writeJSON test helper`** (1 nodes): `writeJSON (test helper)`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `TestResolveConfigPath`** (1 nodes): `TestResolveConfigPath`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `TestSignUserWithoutPinSelfSigned`** (1 nodes): `TestSignUserWithoutPinSelfSigned`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `TestRunIntegrate`** (1 nodes): `TestRunIntegrate`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `ApplyResult struct`** (1 nodes): `ApplyResult struct`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `clientgetGrant`** (1 nodes): `client.getGrant`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `commonFlags struct`** (1 nodes): `commonFlags struct`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `TestString`** (1 nodes): `TestString`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `fakeSessionStore`** (1 nodes): `fakeSessionStore`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `TestRateLimitMapStaysBounded`** (1 nodes): `TestRateLimitMapStaysBounded`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `SessionStore interface`** (1 nodes): `SessionStore interface`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `sessionEvent struct`** (1 nodes): `sessionEvent struct`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `renewRequest struct`** (1 nodes): `renewRequest struct`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `renewResponse struct`** (1 nodes): `renewResponse struct`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `principalsResponse struct`** (1 nodes): `principalsResponse struct`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `renewMTLSRequest struct`** (1 nodes): `renewMTLSRequest struct`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `renewMTLSResponse struct`** (1 nodes): `renewMTLSResponse struct`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `RateLimiterConfig struct`** (1 nodes): `RateLimiterConfig struct`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `RateLimiterallow`** (1 nodes): `RateLimiter.allow`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `bucket struct token bucket`** (1 nodes): `bucket struct (token bucket)`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `PinProviderConfig struct`** (1 nodes): `PinProviderConfig struct`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `PinProviderRun`** (1 nodes): `PinProvider.Run`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `rolloutGateallow`** (1 nodes): `rolloutGate.allow`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `rolloutUnavailable struct`** (1 nodes): `rolloutUnavailable struct`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `enrollRequest struct`** (1 nodes): `enrollRequest struct`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `grantJSON struct`** (1 nodes): `grantJSON struct`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `grantRequest struct`** (1 nodes): `grantRequest struct`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `adminContextensureGroup`** (1 nodes): `adminContext.ensureGroup`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `uiSession struct`** (1 nodes): `uiSession struct`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `uiAuthState struct`** (1 nodes): `uiAuthState struct`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `uiAuthContext struct`** (1 nodes): `uiAuthContext struct`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `uiAuthContexthandleLogout`** (1 nodes): `uiAuthContext.handleLogout`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `uiAuthContexthandleMe`** (1 nodes): `uiAuthContext.handleMe`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Config auditstream`** (1 nodes): `Config (auditstream)`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `syncBuffer`** (1 nodes): `syncBuffer`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Paths`** (1 nodes): `Paths`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `apiClientBundle`** (1 nodes): `apiClient.Bundle`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Daemon`** (1 nodes): `Daemon`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `socketTokenHeader`** (1 nodes): `socketTokenHeader`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `GetUserBySubject`** (1 nodes): `GetUserBySubject`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `UserDetailed`** (1 nodes): `UserDetailed`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `querier`** (1 nodes): `querier`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `AuditFilter`** (1 nodes): `AuditFilter`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `auditFilterWhere`** (1 nodes): `auditFilterWhere`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `ListActiveSessions`** (1 nodes): `ListActiveSessions`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Close`** (1 nodes): `Close`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `ErrNotFound`** (1 nodes): `ErrNotFound`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `GetGrant`** (1 nodes): `GetGrant`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `GrantWithGroup`** (1 nodes): `GrantWithGroup`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `GetGrantDetailed`** (1 nodes): `GetGrantDetailed`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `ListGrantsDetailed`** (1 nodes): `ListGrantsDetailed`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `ListGrants`** (1 nodes): `ListGrants`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `ListGrantsForGroups`** (1 nodes): `ListGrantsForGroups`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `ApplyResult`** (1 nodes): `ApplyResult`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `ServiceAccount`** (1 nodes): `ServiceAccount`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `GetGroup`** (1 nodes): `GetGroup`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `GetGroupByName`** (1 nodes): `GetGroupByName`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `ListGroups`** (1 nodes): `ListGroups`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `GetHost`** (1 nodes): `GetHost`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `GetHostByName`** (1 nodes): `GetHostByName`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `ListHosts`** (1 nodes): `ListHosts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `UpdateHost`** (1 nodes): `UpdateHost`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `HostDetailed`** (1 nodes): `HostDetailed`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `GetHostTags`** (1 nodes): `GetHostTags`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `NextCertificateSerial`** (1 nodes): `NextCertificateSerial`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `GetCertificateBySerial`** (1 nodes): `GetCertificateBySerial`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `ListCertificates`** (1 nodes): `ListCertificates`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `ListCAKeys`** (1 nodes): `ListCAKeys`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `EventHostEnrolled`** (1 nodes): `EventHostEnrolled`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `EventEnrollTokenCreated`** (1 nodes): `EventEnrollTokenCreated`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `CIGrant`** (1 nodes): `CIGrant`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `CIMatch`** (1 nodes): `CIMatch`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `StoreGetCIGrant`** (1 nodes): `Store.GetCIGrant`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `StoreListCIGrants`** (1 nodes): `Store.ListCIGrants`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `CIGrantSpec`** (1 nodes): `CIGrantSpec`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Role type`** (1 nodes): `Role (type)`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Parameter abstract class`** (1 nodes): `Parameter (abstract class)`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `ApplyResult`** (1 nodes): `ApplyResult`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `AuditList`** (1 nodes): `AuditList`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `User`** (1 nodes): `User`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `ListGroups$Params`** (1 nodes): `ListGroups$Params`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `ListUsers$Params`** (1 nodes): `ListUsers$Params`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `ListHosts$Params`** (1 nodes): `ListHosts$Params`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `ListCertificates$Params`** (1 nodes): `ListCertificates$Params`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `GetInstallScript$Params`** (1 nodes): `GetInstallScript$Params`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `DownloadAgent$Params`** (1 nodes): `DownloadAgent$Params`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `GetAgentManifest$Params`** (1 nodes): `GetAgentManifest$Params`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `PostAuthLogout$Params`** (1 nodes): `PostAuthLogout$Params`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `GetUiConfig$Params`** (1 nodes): `GetUiConfig$Params`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `GetAuthMe$Params`** (1 nodes): `GetAuthMe$Params`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `GetHealth$Params`** (1 nodes): `GetHealth$Params`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `ExportAudit$Json$Params`** (1 nodes): `ExportAudit$Json$Params`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `ListAudit$Params`** (1 nodes): `ListAudit$Params`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `ExportAudit$Csv$Params`** (1 nodes): `ExportAudit$Csv$Params`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `SignUser$Params`** (1 nodes): `SignUser$Params`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `SignCi$Params`** (1 nodes): `SignCi$Params`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `gssh-admin CLI Component`** (1 nodes): `gssh-admin CLI Component`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `SIEM Consumer Component`** (1 nodes): `SIEM Consumer Component`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `cmd/gssh maingo user CLI entrypoint`** (1 nodes): `cmd/gssh main.go (user CLI entrypoint)`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `cmd/gssh-admin maingo admin CLI entrypoint`** (1 nodes): `cmd/gssh-admin main.go (admin CLI entrypoint)`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `gssh-admin main`** (1 nodes): `gssh-admin main()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `gssh-agentd main`** (1 nodes): `gssh-agentd main()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `envwaitError`** (1 nodes): `env.waitError`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `gitlabFakediscoveryJSON`** (1 nodes): `gitlabFake.discoveryJSON`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `gitlabFakejwksJSON`** (1 nodes): `gitlabFake.jwksJSON`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `DEVELOPERmd: gssh-server`** (1 nodes): `DEVELOPER.md: gssh-server`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `DEVELOPERmd: gssh user CLI`** (1 nodes): `DEVELOPER.md: gssh (user CLI)`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `DEVELOPERmd: gssh-admin admin CLI`** (1 nodes): `DEVELOPER.md: gssh-admin (admin CLI)`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `DEVELOPERmd: gssh-agentd host agent`** (1 nodes): `DEVELOPER.md: gssh-agentd (host agent)`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `DEVELOPERmd: License and versioning`** (1 nodes): `DEVELOPER.md: License and versioning`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `README: Key features`** (1 nodes): `README: Key features`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `README: How it works`** (1 nodes): `README: How it works`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `README: Quick start`** (1 nodes): `README: Quick start`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `README: GitLab CI`** (1 nodes): `README: GitLab CI`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Terminology public/agent listener, pin, fail-closed, hairpin`** (1 nodes): `Terminology (public/agent listener, pin, fail-closed, hairpin)`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Feasibility assessment`** (1 nodes): `Feasibility assessment`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Target Flow UX`** (1 nodes): `Target Flow (UX)`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `CLAUDEmd: Project orientation graphify usage`** (1 nodes): `CLAUDE.md: Project orientation (graphify usage)`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `CLAUDEmd: Language policy English only`** (1 nodes): `CLAUDE.md: Language policy (English only)`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Flux example: repo structure`** (1 nodes): `Flux example: repo structure`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Flux example: bootstrap`** (1 nodes): `Flux example: bootstrap`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Flux example: IdP service account for sync`** (1 nodes): `Flux example: IdP service account for sync`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Flux example: upgrade path`** (1 nodes): `Flux example: upgrade path`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Helm chart README: PostgreSQL`** (1 nodes): `Helm chart README: PostgreSQL`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Helm chart README: Database migrations`** (1 nodes): `Helm chart README: Database migrations`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Helm chart README: Agent API mTLS`** (1 nodes): `Helm chart README: Agent API (mTLS)`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Helm chart README: Metrics`** (1 nodes): `Helm chart README: Metrics`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Helm chart README: Chart release GitHub Pages`** (1 nodes): `Helm chart README: Chart release (GitHub Pages)`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **What is the exact relationship between `AuditPage` and `exportAudit$Json()`?**
  _Edge tagged AMBIGUOUS (relation: conceptually_related_to) - confidence is low._
- **What is the exact relationship between `AuditPage` and `exportAudit$Csv()`?**
  _Edge tagged AMBIGUOUS (relation: conceptually_related_to) - confidence is low._
- **What is the exact relationship between `getHealth()` and `app.html (Angular App Shell Template)`?**
  _Edge tagged AMBIGUOUS (relation: conceptually_related_to) - confidence is low._
- **What is the exact relationship between `validateCIGrantRequest()` and `TestRateLimitFailureBudgetBlocks`?**
  _Edge tagged AMBIGUOUS (relation: semantically_similar_to) - confidence is low._
- **What is the exact relationship between `HostStore interface` and `fakeAuthStore`?**
  _Edge tagged AMBIGUOUS (relation: semantically_similar_to) - confidence is low._
- **Why does `New()` connect `Admin Authentication & Grant Apply Tests` to `Audit & CI Grant Data Layer`, `Admin API Grant & Enrollment Handlers`, `SSH Agent Certificate Management`, `Agent Daemon Session & Auth Cache`, `CA Signer Lifecycle`, `Agent Session Handler Tests`, `Directory Sync (Users & Groups)`, `Rate Limiter`, `CI Grants & SPKI Pin Dialer`, `CI Grant CRUD Handlers`, `Agent Binary Distribution`, `OIDC Login Flows (PKCE/Device/ClientCreds)`, `GitLab CI E2E Test Fakes`, `Fake Admin Store (Grants)`?**
  _High betweenness centrality (0.078) - this node is a cross-community bridge._
- **Why does `run()` connect `SSH Agent Certificate Management` to `Audit & CI Grant Data Layer`, `Admin API Grant & Enrollment Handlers`, `CA Signer Lifecycle`, `Admin Authentication & Grant Apply Tests`, `E2E Test Harness & Deployment Setup`, `Agent Session Handler Tests`, `Directory Sync (Users & Groups)`, `Rate Limiter`, `CI Grants & SPKI Pin Dialer`, `GitLab CI E2E Test Fakes`?**
  _High betweenness centrality (0.057) - this node is a cross-community bridge._