-- +goose Up

-- Einmalige Enrollment-Tokens (Phase 5): in der DB liegt nur der SHA-256-Hash,
-- das Klartext-Token sieht ausschließlich der Ersteller und der Host.
CREATE TABLE enrollment_tokens (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash bytea       NOT NULL UNIQUE,
    -- optional an einen Hostnamen gebunden; NULL = beliebiger Hostname
    host_name  text,
    tags       jsonb       NOT NULL DEFAULT '{}',
    expires_at timestamptz NOT NULL,
    used_at    timestamptz,
    used_by    uuid REFERENCES hosts (id),
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Die mTLS-CA der Host-Agenten (X.509) nutzt dieselbe Key-Tabelle wie die
-- SSH-CAs; public_key enthält dann das CA-Zertifikat als PEM.
ALTER TABLE ca_keys DROP CONSTRAINT ca_keys_purpose_check;
ALTER TABLE ca_keys ADD CONSTRAINT ca_keys_purpose_check CHECK (purpose IN ('user', 'host', 'mtls'));

-- +goose Down
ALTER TABLE ca_keys DROP CONSTRAINT ca_keys_purpose_check;
ALTER TABLE ca_keys ADD CONSTRAINT ca_keys_purpose_check CHECK (purpose IN ('user', 'host'));
DROP TABLE enrollment_tokens;
