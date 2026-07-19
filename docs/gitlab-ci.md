# GitLab-CI-Integration (Phase 7)

GitLab-Runner erhalten für die Dauer eines Jobs ein kurzlebiges SSH-Zertifikat —
ohne statische Keys in CI-Variablen. GitLab stellt pro Job ein OIDC `id_token`
aus; guided-ssh validiert es gegen den GitLab-JWKS-Endpoint und stellt ein
Zertifikat mit pipeline-gebundener KeyID und projektgebundenen Principals aus
(ADR-019).

## Ablauf

```
GitLab-Job (id_tokens) ──► gssh ci-login ──► POST /v1/sign/ci ──► CA
      │                          │                  │
      │  GSSH_CI_TOKEN (JWT)     │  Token + PubKey  │  validiert Issuer/JWKS/
      │                          │                  │  Audience, matcht CI-Grants
      └── ssh-agent ◄── Zertifikat (≤ 1 h, ci:<project>:<pipeline>:<job>) ──┘
```

- **KeyID** `ci:<project_path>:<pipeline_id>:<job_id>` — jede Ausstellung ist
  im Audit eindeutig einer Pipeline und einem Job zuzuordnen.
- **Principals** `ci:<project_path>` plus Namespace-Vorfahren (`ci:infra`) —
  welche lokalen Benutzer sie erreichen, entscheidet der Host über die
  CI-Grants (AuthorizedPrincipalsCommand), analog ADR-018.
- **Laufzeit** dreifach gedeckelt: CI-Grant-Maximum, Policy (1 h hart) und
  Token-Ablauf (GitLab setzt `exp` auf das Job-Timeout).
- Pro Projekt wird ein Service-Account (kind `gitlab-ci`) geführt;
  `active = false` deaktiviert die Ausstellung für das Projekt (Not-Aus).

## Server-Konfiguration

```sh
GSSH_CI_ISSUER=https://gitlab.example.com   # GitLab-Basis-URL (OIDC-Issuer)
GSSH_CI_AUDIENCE=guided-ssh                 # optional, Default guided-ssh
```

Ohne `GSSH_CI_ISSUER` bleibt `POST /v1/sign/ci` deaktiviert (503). GitLab und
der Benutzer-IdP sind strikt getrennte Issuer mit getrennten Audiences —
CI-Tokens werden nie am Benutzer-Endpoint akzeptiert.

## CI-Grants

Ein CI-Grant bindet Projekt/Gruppe × Ref-Bedingung × Host-Tags an lokale
Ziel-Benutzer:

| Feld | Bedeutung |
|---|---|
| `project` | Projekt-Pfad (`infra/ansible`) oder Namespace (`infra` deckt alle Projekte darunter ab) |
| `ref` | Glob über den Ref-Namen (`main`, `release/*`); leer = alle Refs |
| `protected_only` | nur geschützte Refs (`ref_protected`), Default `true` |
| `environment` | Glob über den `environment`-Claim; leer = keine Bedingung |
| `tags` | Tag-Selektor über Host-Tags (⊆-Semantik, leer = alle Hosts) |
| `principals` | lokale Ziel-Benutzer auf den Hosts (z. B. `deploy`) |
| `max_validity` | Laufzeit-Maximum (zusätzlich hart durch Policy 1 h gedeckelt) |

Verwaltung wie Gruppen-Grants — CLI:

```sh
gssh-admin ci-grant create --project infra/ansible --ref main \
  --tags env=prod --principals deploy --max-validity 1h
gssh-admin ci-grant list
```

oder deklarativ in derselben `grants.yaml` (GitOps, `gssh-admin apply -f`):

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

Fehlt der `ci_grants:`-Abschnitt, bleiben CI-Grants beim Apply unangetastet;
ein leerer Abschnitt löscht alle. Semantik wie ADR-018: nur additiv, kein
deny; Entzug über Grant-Entfernung.

## Referenz-Pipeline

Vollständiges Beispiel: [`deploy/examples/gitlab-ci/.gitlab-ci.yml`](../deploy/examples/gitlab-ci/.gitlab-ci.yml)

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

Kernpunkte:

- `id_tokens` mit `aud: guided-ssh` erzeugt das Job-Token in `GSSH_CI_TOKEN`
  (das entfernte `CI_JOB_JWT` wird nicht unterstützt).
- `gssh ci-login` lädt Schlüssel + Zertifikat ausschließlich in den ssh-agent
  des Jobs — Ansible nutzt den Agenten automatisch, keine Key-Dateien.
- Der Job braucht einen laufenden ssh-agent (`eval $(ssh-agent -s)`).
- Selbstsignierte Server: `--pin-sha256`/`GSSH_PIN_SHA256` (SPKI-Pinning wie
  in der Benutzer-CLI).

## Ansible

Beispiel-Playbook und Inventory-Muster:
[`deploy/examples/ansible/`](../deploy/examples/ansible/) — zertifikatsbasiert,
der Zielbenutzer (`ansible_user`) muss Principal eines passenden CI-Grants
sein. Die Clients müssen der Host-CA vertrauen (`@cert-authority`-Zeile aus
`GET /v1/ca/bundle/host`), sonst Host-Key-Prompt/`known_hosts`-Pflege.

## Sicherheitsnotizen

- Audience-Vorgabe `aud: guided-ssh` verhindert, dass fremde für andere
  Dienste ausgestellte GitLab-Tokens akzeptiert werden.
- `protected_only: true` (Default) verhindert, dass beliebige Feature-Branches
  (jeder mit Push-Rechten) Produktionszugriff erhalten.
- Bindung Pipeline↔Host ist so granular wie der Grant: ein Zertifikat von
  Projekt A funktioniert nicht auf Hosts, die nur für Projekt B freigegeben
  sind (Projekt-Principals, ADR-019).
