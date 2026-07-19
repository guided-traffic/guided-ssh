# ADR-007: Deployment via Helm-Chart, FluxCD-kompatibel

- Status: akzeptiert
- Datum: 2026-07-19

## Kontext

Zielumgebung ist Kubernetes, verwaltet über GitOps mit FluxCD (Anforderung).

## Entscheidung

Auslieferung als Helm-Chart (`deploy/helm/guided-ssh`), publiziert in eine
OCI-Registry. Referenz-Setup für FluxCD (`HelmRelease`, Kustomize-Overlays,
SOPS-Beispiele) wird in `deploy/flux-example/` gepflegt.

## Konsequenzen

- Konfiguration vollständig über `values.yaml`; Secrets nur als
  `existingSecret`-Referenzen (kompatibel mit external-secrets und SOPS).
- DB-Migrationen als Job/Init-Container mit Lock — Upgrade via Flux ohne Handarbeit.
- Chart wird wie Code getestet (chart-testing, `helm test`) und versioniert released.
