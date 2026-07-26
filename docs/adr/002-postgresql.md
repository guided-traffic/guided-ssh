# ADR-002: PostgreSQL as the database

- Status: accepted
- Date: 2026-07-19

## Context

Requirements: a transaction-safe audit log (issuance + audit event atomically),
flexible certificate metadata, grants/ACLs, operation in Kubernetes.

## Decision

PostgreSQL as the sole database.

## Consequences

- ACID: certificate issuance and the `audit_events` entry in a single transaction.
- JSONB for certificate metadata and variable claim contexts.
- Append-only protection via DB grants (no UPDATE/DELETE), plus optional triggers.
- Partitioning by month for audit retention.
- Operations: external or CloudNativePG; tests via Testcontainers.
