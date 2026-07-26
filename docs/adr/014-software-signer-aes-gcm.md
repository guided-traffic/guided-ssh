# ADR-014: Software signer with AES-256-GCM-encrypted CA keys

- Status: accepted
- Date: 2026-07-19

## Context

Phase 2 needs a way to store the Ed25519 CA private keys without relying on a
KMS/HSM (that follows in Phase 10 via the same `Signer` interface), but
without leaving the keys in plaintext in the database. The plan names age or
AES-GCM with a master key from a Kubernetes secret as candidates.

## Decision

AES-256-GCM from the Go standard library (`crypto/aes` + `crypto/cipher`), not
age. The private key is serialized in OpenSSH PEM format and stored as
`nonce || ciphertext` in `ca_keys.encrypted_private_key`. The 32-byte master
key comes base64-encoded from the environment variable
`GSSH_CA_MASTER_KEY` (sourced from a secret in the Kubernetes deployment).

## Consequences

- No additional dependency; GCM provides confidentiality and integrity
  (tampered data, or data decrypted with the wrong key, fails to decrypt).
- age would add no value over direct AES-GCM here: it ultimately wraps the
  same primitive, but is designed for file/recipient scenarios.
- Master key rotation requires re-encrypting the `ca_keys` entries; with the
  small number of rows involved, this is a simple admin command that can be
  added later.
- Compromise of the master key together with database access exposes the CA
  keys — accepted for the MVP, with hardening via PKCS#11/KMS in Phase 10
  (threat model: `docs/threat-model.md`).
