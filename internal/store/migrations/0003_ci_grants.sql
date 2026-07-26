-- +goose Up

-- CI grants (phase 7, ADR-019): GitLab project/group × ref condition ×
-- tag selector → target principals. project_path matches exactly or as a
-- namespace prefix (the row "infra" covers "infra/ansible").
CREATE TABLE ci_grants (
    id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_path         text        NOT NULL,
    -- glob over the ref name ('*' matches anything, including '/'); '' = all refs
    ref_pattern          text        NOT NULL DEFAULT '',
    -- only jobs on protected refs (ref_protected)
    protected_only       boolean     NOT NULL DEFAULT true,
    -- glob over the environment claim; '' = no condition
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
