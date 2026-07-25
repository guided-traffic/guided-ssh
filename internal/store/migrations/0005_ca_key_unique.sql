-- +goose Up

-- Self-managed CA mode (SELF_MANAGED_CA.md, D4) adopts a mounted key by looking
-- up its (purpose, public_key) and inserting the row only if it is absent. The
-- unique index turns that into an atomic "INSERT ... ON CONFLICT DO NOTHING +
-- re-select", so replicas starting concurrently adopt the same row instead of
-- creating duplicates. It also closes the existing bootstrap race in
-- EnsureCAKeys, where two replicas could each create an active key.
--
-- public_key holds an SSH public key for purpose 'user'/'host' and the whole
-- X.509 CA certificate PEM for 'mtls'. Even the PEM stays far below the btree
-- index row limit (~2704 bytes; an ed25519 CA cert PEM is a few hundred bytes),
-- so a plain unique index over the text column is sufficient — no expression
-- index over a digest needed.
CREATE UNIQUE INDEX ca_keys_purpose_public_key_idx ON ca_keys (purpose, public_key);

-- +goose Down
DROP INDEX ca_keys_purpose_public_key_idx;
