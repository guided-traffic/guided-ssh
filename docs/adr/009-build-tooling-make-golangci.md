# ADR-009: Build-Tooling — Makefile + golangci-lint

- Status: akzeptiert
- Datum: 2026-07-19

## Kontext

Der Plan ließ Makefile oder Taskfile offen; Linting war mit `golangci-lint` gesetzt.
Build-Targets sind zugleich die Schnittstelle der CI-Pipeline.

## Entscheidung

Makefile (statt Taskfile): `build`, `test`, `cover` (inkl. Coverage-Gate ≥ 80 %,
Schwelle `COVERAGE_MIN`), `lint`, `fmt`, `image`, `clean`.
golangci-lint v2 mit Standard-Linter-Set plus `gosec`, `revive`, `misspell`,
`unconvert`, `unparam`, `copyloopvar`; Formatierung via `gofumpt` + `goimports`.

## Konsequenzen

- `make` ist auf jedem Runner/Entwicklerrechner vorhanden — kein zusätzliches
  Tool zu installieren (Taskfile bräuchte das `task`-Binary).
- CI ruft dieselben Targets wie Entwickler lokal ⇒ „works on my machine"-Lücken klein.
- `gosec` von Anfang an aktiv — passend zum Sicherheitsfokus des Projekts.
- Makefile-Syntax ist spröde; bei wachsender Komplexität wandern Schritte in
  Skripte unter `hack/` (Beispiel: `hack/coverage.sh`).
