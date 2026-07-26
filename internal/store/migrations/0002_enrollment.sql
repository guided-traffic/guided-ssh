-- +goose Up

-- Single-use enrollment tokens (phase 5): the DB only holds the SHA-256 hash,
-- the plaintext token is seen only by its creator and the host.
CREATE TABLE enrollment_tokens (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash bytea       NOT NULL UNIQUE,
    -- optionally bound to a hostname; NULL = any hostname
    host_name  text,
    tags       jsonb       NOT NULL DEFAULT '{}',
    expires_at timestamptz NOT NULL,
    used_at    timestamptz,
    used_by    uuid REFERENCES hosts (id),
    created_at timestamptz NOT NULL DEFAULT now()
);

-- The mTLS CA of the host agents (X.509) uses the same key table as the
-- SSH CAs; public_key then holds the CA certificate as PEM.
ALTER TABLE ca_keys DROP CONSTRAINT ca_keys_purpose_check;
ALTER TABLE ca_keys ADD CONSTRAINT ca_keys_purpose_check CHECK (purpose IN ('user', 'host', 'mtls'));

-- +goose Down
ALTER TABLE ca_keys DROP CONSTRAINT ca_keys_purpose_check;
ALTER TABLE ca_keys ADD CONSTRAINT ca_keys_purpose_check CHECK (purpose IN ('user', 'host'));
DROP TABLE enrollment_tokens;
