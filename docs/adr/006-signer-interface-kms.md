# ADR-006: Signer interface — software key first, KMS/HSM later

- Status: accepted
- Date: 2026-07-19

## Context

The CA key is the most valuable asset (see the threat model). Production
readiness calls for KMS/HSM; for development and early phases, that would be
disproportionately heavyweight.

## Decision

Signing goes exclusively through an interface
(`Sign(ctx, CertRequest) (*ssh.Certificate, error)`). First implementation:
software signer with an Ed25519 key, encrypted at rest (key from a K8s
secret). Later (Phase 10): PKCS#11 signer (covers HSM and SoftHSM tests),
cloud KMS as needed. User and host CAs use separate keys.

## Consequences

- Backend can be swapped without reworking the CA logic; the policy and audit
  path is identical for all signers.
- Every signing operation is audited independently of the backend.
- The software signer remains available permanently for development/tests;
  production deployments configure the backend via Helm values.
