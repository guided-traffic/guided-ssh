# ADR-011: Versionierung (SemVer) und Lizenz (Apache-2.0)

- Status: akzeptiert
- Datum: 2026-07-19

## Kontext

Phase 0 verlangt ein festgelegtes Versionierungsschema und eine Lizenz. Releases
umfassen mehrere Artefakte (Binaries, Container-Image, Helm-Chart), die zusammen
funktionieren müssen.

## Entscheidung

- **Lizenz: Apache-2.0** (LICENSE liegt im Repo) — Patentklausel, unternehmensfreundlich,
  üblich im Cloud-Native-Umfeld.
- **Versionierung: Semantic Versioning 2.0.0** über Git-Tags `vX.Y.Z`.
  `0.x` bis zum MVP (Breaking Changes erlaubt); ab `1.0.0` gilt SemVer strikt für
  API, CLI-Flags, Helm-Values und DB-Migrationen (nur vorwärts).
- Binaries, Container-Image und Helm-Chart(-`appVersion`) werden pro Release
  **gemeinsam** mit derselben Version getaggt; die Chart-`version` darf für
  Chart-only-Fixes unabhängig patchen.
- Build-Metadaten (`version`, `commit`, `date`) werden via `-ldflags` in
  `internal/version` eingebrannt (`git describe --tags`).

## Konsequenzen

- Eindeutige Zuordnung Support-Anfrage ⇔ Codestand (`gssh-server -version`).
- Release = Tag pushen; Pipeline baut und published alle Artefakte konsistent.
- SemVer-Disziplin ab 1.0.0 erzwingt bewusste API-Evolution (OpenAPI-Diff im Review).
