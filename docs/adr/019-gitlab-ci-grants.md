# ADR-019: GitLab-CI-Integration — CI-Grants und Projekt-Principals

## Status

Akzeptiert (Phase 7)

## Kontext

GitLab-Runner sollen ohne statische Secrets kurzlebige SSH-Zertifikate erhalten
(Kernanforderung). GitLab stellt pro Job ein OIDC `id_token` aus; die CA muss es
validieren und auf Zugriffsregeln abbilden. Offene Fragen: Wie werden CI-Regeln
modelliert, welche Principals trägt ein CI-Zertifikat, und wie autorisiert der
Host eine Pipeline, die keine Benutzeridentität hat?

## Entscheidung

1. **Eigener Verifier, eigener Endpoint.** GitLab ist ein zweiter, unabhängiger
   OIDC-Issuer (`GSSH_CI_ISSUER`, JWKS via Discovery). Die erwartete Audience
   ist konfigurierbar (`GSSH_CI_AUDIENCE`, Default `guided-ssh`). CI-Tokens
   werden ausschließlich an `POST /v1/sign/ci` akzeptiert — nie am
   Benutzer-Endpoint (keine Audience-/Issuer-Vermischung).

2. **Eigenes Grant-Modell `ci_grants`** (statt Wiederverwendung der
   Gruppen-Grants): Projekt- oder Gruppen-Pfad × Ref-Bedingung
   (`protected_only`, `ref_pattern`-Glob) × optionale Environment-Bedingung ×
   Tag-Selektor → Ziel-Principals, Laufzeit-Maximum. `project_path` matcht
   exakt oder als Namespace-Präfix (`infra` deckt `infra/ansible` ab).
   Semantik wie ADR-018: nur additiv, kein deny; Laufzeit = Maximum über
   passende Grants, zusätzlich hart durch die CI-Policy (1 h) und den
   Token-Ablauf (= GitLab-Job-Timeout) gedeckelt.

3. **Projekt-Identitäts-Principals.** CI-Zertifikate tragen — analog zu
   Benutzerzertifikaten (ADR-018) — Identitäts- statt Ziel-Principals:
   `ci:<project_path>` plus alle Namespace-Vorfahren (`ci:infra/ansible`,
   `ci:infra`). Der Host entscheidet: `ListAuthorizedPrincipals` liefert für
   einen lokalen Benutzer zusätzlich `ci:<project_path>` jedes CI-Grants,
   dessen Tag-Selektor auf den Host passt und dessen Principals den lokalen
   Benutzer enthalten. Damit bleibt die Bindung Pipeline↔Host so granular wie
   der Grant (Projekt oder Gruppe) — ein CI-Zertifikat von Projekt A
   funktioniert nicht auf Hosts, die nur für Projekt B freigegeben sind.
   Host-Agent und sshd-Konfiguration bleiben unverändert.

4. **KeyID `ci:<project_path>:<pipeline_id>:<job_id>`** — jede Ausstellung ist
   im Audit eindeutig einer Pipeline und einem Job zuzuordnen. Pro Projekt wird
   ein `service_accounts`-Eintrag (kind `gitlab-ci`) sichergestellt und mit dem
   Zertifikat verknüpft; `active = false` wirkt als Not-Aus pro Projekt.

5. **`gssh ci-login`** liest das Job-Token aus einer Env-Variable
   (`id_tokens`-Feature, Default `GSSH_CI_TOKEN`; das entfernte `CI_JOB_JWT`
   wird nicht unterstützt) und lädt Schlüssel + Zertifikat ausschließlich in
   den ssh-agent des Jobs — identisch zur Benutzer-CLI, aber ohne Browser-Flow
   und ohne Konfigurationsdatei (`--api-url`/`GSSH_API_URL`).

## Konsequenzen

- Zwei Verifier (IdP, GitLab) mit getrennten Audiences; Requester-Typ `ci`
  nutzt die bestehende Policy (max. 1 h, nur `permit-pty`).
- CI-Grants werden wie Gruppen-Grants verwaltet: Admin-API
  (`/v1/admin/ci-grants…`), CLI (`gssh-admin ci-grant …`) und deklarativ in
  derselben `grants.yaml` (`ci_grants:`-Abschnitt, GitOps).
- Gruppen-Grants (breit) sind über Namespace-Präfixe möglich, bleiben aber im
  Zertifikat sichtbar granular (Vorfahren-Principals nur bis zur Grant-Ebene
  wirksam).
- Kein Wildcard-Matching im Host-Pfad nötig; sshd vergleicht exakte Strings.
