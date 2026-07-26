-- +goose Up

-- Host sessions (phase 9): the host agent reports session start/end via the
-- mTLS agent API. cert_serial correlates the session with the issued
-- certificate (certificates.serial) and thereby with the user; user_id is
-- resolved during correlation (NULL if the serial is unknown/unresolvable,
-- e.g. local accounts without a guided-ssh certificate). ended_at NULL = active session.
CREATE TABLE host_sessions (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id     uuid        NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
    local_user  text        NOT NULL,
    remote_user text        NOT NULL DEFAULT '',
    remote_addr text        NOT NULL DEFAULT '',
    tty         text        NOT NULL DEFAULT '',
    cert_serial bigint,
    key_id      text        NOT NULL DEFAULT '',
    user_id     uuid REFERENCES users (id),
    started_at  timestamptz NOT NULL DEFAULT now(),
    ended_at    timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now()
);

-- Active sessions per host (dashboards, correlating session end with start).
CREATE INDEX host_sessions_active_idx ON host_sessions (host_id, local_user, tty)
    WHERE ended_at IS NULL;
CREATE INDEX host_sessions_cert_serial_idx ON host_sessions (cert_serial);

-- +goose Down
DROP TABLE host_sessions;
