# ADR-007: Deployment via Helm chart, FluxCD-compatible

- Status: accepted
- Date: 2026-07-19

## Context

The target environment is Kubernetes, managed via GitOps with FluxCD (a requirement).

## Decision

Delivery as a Helm chart (`deploy/helm/guided-ssh`), published to an OCI
registry. A reference setup for FluxCD (`HelmRelease`, Kustomize overlays,
SOPS examples) is maintained in `deploy/flux-example/`.

## Consequences

- Configuration entirely via `values.yaml`; secrets only as
  `existingSecret` references (compatible with external-secrets and SOPS).
- DB migrations as a Job/init container with a lock — upgrades via Flux
  without manual steps.
- The chart is tested like code (chart-testing, `helm test`) and released with versioning.
