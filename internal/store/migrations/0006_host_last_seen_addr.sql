-- +goose Up

-- The agent's observed source address at the last mTLS contact (heartbeat/
-- enroll-adjacent agent calls). Diagnostic value for the UI's connect-via-IP
-- fallback: hosts without a DNS entry can be reached by this address when
-- agent egress and sshd share it (flat LAN) — behind NAT they differ, which
-- the UI states. Text instead of inet: stored verbatim from net.SplitHostPort,
-- no address arithmetic needed.
ALTER TABLE hosts ADD COLUMN last_seen_addr text;

-- +goose Down
ALTER TABLE hosts DROP COLUMN last_seen_addr;
