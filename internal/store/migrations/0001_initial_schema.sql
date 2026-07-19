-- +goose Up

-- Benutzer aus dem IdP (Source of Truth bleibt der IdP, siehe Plan: kein SCIM im MVP).
CREATE TABLE users (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    issuer     text        NOT NULL,
    subject    text        NOT NULL,
    username   text        NOT NULL,
    email      text        NOT NULL,
    uid        integer,
    gid        integer,
    active     boolean     NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (issuer, subject)
);

CREATE TABLE groups (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    issuer      text        NOT NULL,
    name        text        NOT NULL,
    external_id text,
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (issuer, name)
);

CREATE TABLE user_groups (
    user_id  uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    group_id uuid NOT NULL REFERENCES groups (id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, group_id)
);

CREATE TABLE hosts (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name         text        NOT NULL UNIQUE,
    public_key   text,
    enrolled_at  timestamptz,
    last_seen_at timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE host_tags (
    host_id uuid NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
    key     text NOT NULL,
    value   text NOT NULL,
    PRIMARY KEY (host_id, key)
);

-- Zugriffsregel: IdP-Gruppe × Tag-Selektor → Principals, sudo, max. Zertifikatslaufzeit.
CREATE TABLE access_grants (
    id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id             uuid        NOT NULL REFERENCES groups (id) ON DELETE CASCADE,
    tag_selector         jsonb       NOT NULL DEFAULT '{}',
    principals           text[]      NOT NULL,
    sudo                 boolean     NOT NULL DEFAULT false,
    max_validity_seconds bigint      NOT NULL CHECK (max_validity_seconds > 0),
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE ca_keys (
    id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    purpose               text        NOT NULL CHECK (purpose IN ('user', 'host')),
    algorithm             text        NOT NULL DEFAULT 'ed25519',
    public_key            text        NOT NULL,
    -- verschlüsselt at rest (Phase 2); NULL, wenn der Key in einem KMS/HSM liegt (Phase 10)
    encrypted_private_key bytea,
    state                 text        NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'retiring', 'retired')),
    created_at            timestamptz NOT NULL DEFAULT now(),
    retired_at            timestamptz
);

-- CI-Identitäten (z. B. GitLab-Projekte); claim_matcher bestimmt, welche OIDC-Claims passen müssen.
CREATE TABLE service_accounts (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name          text        NOT NULL UNIQUE,
    kind          text        NOT NULL,
    issuer        text        NOT NULL,
    claim_matcher jsonb       NOT NULL DEFAULT '{}',
    active        boolean     NOT NULL DEFAULT true,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
);

-- Jedes ausgestellte Zertifikat (Benutzer und Host).
CREATE TABLE certificates (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    serial             bigint      NOT NULL UNIQUE,
    key_id             text        NOT NULL,
    cert_type          text        NOT NULL CHECK (cert_type IN ('user', 'host')),
    public_key         text        NOT NULL,
    principals         text[]      NOT NULL,
    valid_after        timestamptz NOT NULL,
    valid_before       timestamptz NOT NULL,
    ca_key_id          uuid        NOT NULL REFERENCES ca_keys (id),
    user_id            uuid REFERENCES users (id),
    service_account_id uuid REFERENCES service_accounts (id),
    host_id            uuid REFERENCES hosts (id),
    issuer_context     jsonb       NOT NULL DEFAULT '{}',
    created_at         timestamptz NOT NULL DEFAULT now(),
    CHECK (valid_before > valid_after)
);

CREATE INDEX certificates_key_id_idx ON certificates (key_id);
CREATE INDEX certificates_valid_before_idx ON certificates (valid_before);

-- Serial-Vergabe für Zertifikate (Phase 2 nutzt sie beim Signieren).
CREATE SEQUENCE certificate_serial_seq;

-- Append-only-Audit-Log; nach Monat partitionierbar (Retention-Konzept: docs/audit-retention.md).
-- Partitionsschlüssel occurred_at muss Teil des Primary Key sein.
CREATE TABLE audit_events (
    id          bigint GENERATED ALWAYS AS IDENTITY,
    occurred_at timestamptz NOT NULL DEFAULT now(),
    event_type  text        NOT NULL,
    actor       text        NOT NULL DEFAULT '',
    payload     jsonb       NOT NULL DEFAULT '{}',
    PRIMARY KEY (id, occurred_at)
)
PARTITION BY RANGE (occurred_at);

-- Default-Partition fängt alles, solange keine Monatspartitionen angelegt sind.
CREATE TABLE audit_events_default PARTITION OF audit_events DEFAULT;

CREATE INDEX audit_events_occurred_at_idx ON audit_events (occurred_at);
CREATE INDEX audit_events_event_type_idx ON audit_events (event_type, occurred_at);

-- Append-only-Schutz: UPDATE/DELETE schlagen unabhängig von DB-Grants fehl.
-- Zweite Schutzschicht (kein UPDATE/DELETE-Grant für die App-Rolle): docs/audit-retention.md.
-- +goose StatementBegin
CREATE FUNCTION audit_events_block_mutation() RETURNS trigger
    LANGUAGE plpgsql
AS
$$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only (% not allowed)', TG_OP;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER audit_events_append_only
    BEFORE UPDATE OR DELETE
    ON audit_events
    FOR EACH ROW
EXECUTE FUNCTION audit_events_block_mutation();

-- +goose Down
DROP TABLE audit_events;
DROP FUNCTION audit_events_block_mutation();
DROP SEQUENCE certificate_serial_seq;
DROP TABLE certificates;
DROP TABLE service_accounts;
DROP TABLE ca_keys;
DROP TABLE access_grants;
DROP TABLE host_tags;
DROP TABLE hosts;
DROP TABLE user_groups;
DROP TABLE groups;
DROP TABLE users;
