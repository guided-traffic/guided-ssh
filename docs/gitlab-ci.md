# GitLab CI Integration (Phase 7)

GitLab runners receive a short-lived SSH certificate for the duration of a job —
without static keys in CI variables. GitLab issues an OIDC `id_token` per job;
guided-ssh validates it against the GitLab JWKS endpoint and issues a
certificate with a pipeline-bound key ID and project-bound principals
(ADR-019).

## Flow

```
GitLab job (id_tokens) ──► gssh ci-login ──► POST /v1/sign/ci ──► CA
      │                          │                  │
      │  GSSH_CI_TOKEN (JWT)     │  token + pubkey  │  validates issuer/JWKS/
      │                          │                  │  audience, matches CI grants
      └── ssh-agent ◄── certificate (≤ 1 h, ci:<project>:<pipeline>:<job>) ──┘
```

- **Key ID** `ci:<project_path>:<pipeline_id>:<job_id>` — every issuance is
  uniquely attributable to a pipeline and job in the audit trail.
- **Principals** `ci:<project_path>` plus namespace ancestors (`ci:infra`) —
  which local users they can reach is decided by the host via the
  CI grants (AuthorizedPrincipalsCommand), analogous to ADR-018.
- **Validity** capped threefold: the CI grant maximum, policy (1 h hard cap),
  and token expiry (GitLab sets `exp` to the job timeout).
- A service account (kind `gitlab-ci`) is maintained per project;
  `active = false` disables issuance for the project (kill switch).

## Server configuration

```sh
GSSH_CI_ISSUER=https://gitlab.example.com   # GitLab base URL (OIDC issuer)
GSSH_CI_AUDIENCE=guided-ssh                 # optional, default guided-ssh
```

Without `GSSH_CI_ISSUER`, `POST /v1/sign/ci` stays disabled (503). GitLab and
the user IdP are strictly separate issuers with separate audiences —
CI tokens are never accepted at the user endpoint.

## CI grants

A CI grant binds project/group × ref condition × host tags to local
target users:

| Field | Meaning |
|---|---|
| `project` | project path (`infra/ansible`) or namespace (`infra` covers all projects beneath it) |
| `ref` | glob over the ref name (`main`, `release/*`); empty = all refs |
| `protected_only` | protected refs only (`ref_protected`), default `true` |
| `environment` | glob over the `environment` claim; empty = no condition |
| `tags` | tag selector over host tags (⊆ semantics, empty = all hosts) |
| `principals` | local target users on the hosts (e.g. `deploy`) |
| `max_validity` | maximum validity (additionally hard-capped by the 1 h policy) |

Managed like group grants — CLI:

```sh
gssh-admin ci-grant create --project infra/ansible --ref main \
  --tags env=prod --principals deploy --max-validity 1h
gssh-admin ci-grant list
```

or declaratively in the same `grants.yaml` (GitOps, `gssh-admin apply -f`):

```yaml
ci_grants:
  - project: infra/ansible
    ref: main
    protected_only: true
    tags:
      env: prod
    principals: [deploy]
    max_validity: 1h
```

If the `ci_grants:` section is missing, CI grants are left untouched on
apply; an empty section deletes all of them. Semantics as in ADR-018: purely
additive, no deny; revocation via grant removal.

## Reference pipeline

Full example: [`deploy/examples/gitlab-ci/.gitlab-ci.yml`](../deploy/examples/gitlab-ci/.gitlab-ci.yml)

```yaml
provision:
  image: alpine:3.22
  id_tokens:
    GSSH_CI_TOKEN:
      aud: guided-ssh
  variables:
    GSSH_API_URL: https://gssh.example.com
  before_script:
    - apk add --no-cache openssh-client ansible
    - eval $(ssh-agent -s)
    - gssh ci-login
  script:
    - ansible-playbook -i inventory.yml site.yml
```

Key points:

- `id_tokens` with `aud: guided-ssh` produces the job token in `GSSH_CI_TOKEN`
  (the deprecated `CI_JOB_JWT` is not supported).
- `gssh ci-login` loads the key + certificate exclusively into the job's
  ssh-agent — Ansible uses the agent automatically, no key files.
- The job needs a running ssh-agent (`eval $(ssh-agent -s)`).
- Self-signed servers: `--pin-sha256`/`GSSH_PIN_SHA256` (SPKI pinning as
  in the user CLI).

## Ansible

Example playbook and inventory pattern:
[`deploy/examples/ansible/`](../deploy/examples/ansible/) — certificate-based,
the target user (`ansible_user`) must be a principal of a matching CI grant.
Clients must trust the host CA (`@cert-authority` line from
`GET /v1/ca/bundle/host`), otherwise a host-key prompt/`known_hosts`
maintenance is required.

## Security notes

- The audience requirement `aud: guided-ssh` prevents GitLab tokens issued
  for other services from being accepted.
- `protected_only: true` (default) prevents arbitrary feature branches
  (anyone with push rights) from gaining production access.
- The pipeline↔host binding is as granular as the grant: a certificate from
  project A does not work on hosts that are only authorized for project B
  (project principals, ADR-019).
