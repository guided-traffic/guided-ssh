# ADR-019: GitLab CI integration — CI grants and project principals

## Status

Accepted (Phase 7)

## Context

GitLab runners are meant to receive short-lived SSH certificates without
static secrets (core requirement). GitLab issues an OIDC `id_token` per job;
the CA must validate it and map it to access rules. Open questions: how are
CI rules modeled, which principals does a CI certificate carry, and how does
a host authorize a pipeline that has no user identity?

## Decision

1. **Dedicated verifier, dedicated endpoint.** GitLab is a second,
   independent OIDC issuer (`GSSH_CI_ISSUER`, JWKS via discovery). The
   expected audience is configurable (`GSSH_CI_AUDIENCE`, default
   `guided-ssh`). CI tokens are accepted only at `POST /v1/sign/ci` — never
   at the user endpoint (no mixing of audiences/issuers).

2. **Dedicated grant model `ci_grants`** (instead of reusing group grants):
   project or group path × ref condition (`protected_only`, `ref_pattern`
   glob) × optional environment condition × tag selector → target
   principals, validity maximum. `project_path` matches exactly or as a
   namespace prefix (`infra` covers `infra/ansible`). Same semantics as
   ADR-018: additive only, no deny; validity = maximum across matching
   grants, additionally hard-capped by the CI policy (1 h) and by token
   expiry (= GitLab job timeout).

3. **Project identity principals.** Analogous to user certificates
   (ADR-018), CI certificates carry identity rather than target principals:
   `ci:<project_path>` plus all namespace ancestors (`ci:infra/ansible`,
   `ci:infra`). The host decides: `ListAuthorizedPrincipals` additionally
   returns `ci:<project_path>` for a local user for each CI grant whose tag
   selector matches the host and whose principals include the local user.
   This keeps the pipeline↔host binding as granular as the grant (project
   or group) — a CI certificate from project A does not work on hosts that
   are only enabled for project B. The host agent and sshd configuration
   remain unchanged.

4. **KeyID `ci:<project_path>:<pipeline_id>:<job_id>`** — every issuance can
   be unambiguously attributed to a pipeline and job in the audit trail. A
   `service_accounts` entry (kind `gitlab-ci`) is ensured per project and
   linked to the certificate; `active = false` acts as a kill switch per
   project.

5. **`gssh ci-login`** reads the job token from an environment variable
   (`id_tokens` feature, default `GSSH_CI_TOKEN`; the removed `CI_JOB_JWT`
   is not supported) and loads the key + certificate exclusively into the
   job's ssh-agent — identical to the user CLI, but without a browser flow
   and without a configuration file (`--api-url`/`GSSH_API_URL`).

## Consequences

- Two verifiers (IdP, GitLab) with separate audiences; requester type `ci`
  uses the existing policy (max 1 h, `permit-pty` only).
- CI grants are managed like group grants: admin API
  (`/v1/admin/ci-grants…`), CLI (`gssh-admin ci-grant …`), and declaratively
  in the same `grants.yaml` (`ci_grants:` section, GitOps).
- Group grants (broad) are possible via namespace prefixes, but remain
  granular in the certificate (ancestor principals only take effect up to
  the grant level).
- No wildcard matching needed on the host path; sshd compares exact strings.
