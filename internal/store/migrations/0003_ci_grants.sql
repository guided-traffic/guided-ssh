-- +goose Up

-- CI-Grants (Phase 7, ADR-019): GitLab-Projekt/Gruppe × Ref-Bedingung ×
-- Tag-Selektor → Ziel-Principals. project_path matcht exakt oder als
-- Namespace-Präfix (Zeile "infra" deckt "infra/ansible" ab).
CREATE TABLE ci_grants (
    id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_path         text        NOT NULL,
    -- Glob über den Ref-Namen ('*' matcht beliebig, auch '/'); '' = alle Refs
    ref_pattern          text        NOT NULL DEFAULT '',
    -- nur Jobs auf geschützten Refs (ref_protected)
    protected_only       boolean     NOT NULL DEFAULT true,
    -- Glob über den environment-Claim; '' = keine Bedingung
    environment_pattern  text        NOT NULL DEFAULT '',
    tag_selector         jsonb       NOT NULL DEFAULT '{}',
    principals           text[]      NOT NULL,
    max_validity_seconds bigint      NOT NULL CHECK (max_validity_seconds > 0),
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX ci_grants_project_path_idx ON ci_grants (project_path);

-- +goose Down
DROP TABLE ci_grants;
