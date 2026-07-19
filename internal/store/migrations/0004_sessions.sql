-- +goose Up

-- Host-Sessions (Phase 9): der Host-Agent meldet Session-Start/-Ende über die
-- mTLS-Agent-API. cert_serial korreliert die Session mit dem ausgestellten
-- Zertifikat (certificates.serial) und damit mit dem Nutzer; user_id wird bei
-- der Korrelation aufgelöst (NULL, wenn der Serial unbekannt/nicht auflösbar ist,
-- z. B. lokale Konten ohne guided-ssh-Zertifikat). ended_at NULL = aktive Session.
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

-- Aktive Sessions je Host (Dashboards, Korrelation von Session-Ende auf -Start).
CREATE INDEX host_sessions_active_idx ON host_sessions (host_id, local_user, tty)
    WHERE ended_at IS NULL;
CREATE INDEX host_sessions_cert_serial_idx ON host_sessions (cert_serial);

-- +goose Down
DROP TABLE host_sessions;
