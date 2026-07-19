# ADR-013: Repository-Layer direkt mit pgx (kein sqlc)

- Status: akzeptiert
- Datum: 2026-07-19

## Kontext

Der Persistenz-Layer (Phase 1) braucht typsicheren Zugriff auf ~9 Tabellen mit
PostgreSQL-Spezifika (JSONB, `text[]`, Partitionierung, Trigger). Kandidaten
laut Plan: sqlc (Codegen aus SQL) oder pgx direkt.

## Entscheidung

`jackc/pgx` v5 direkt, handgeschriebene Repository-Funktionen in
`internal/store`. Boilerplate wird über `pgx.RowToStructByName` plus generische
Helper (`queryOne`/`queryAll`) klein gehalten; Structs tragen `db`-Tags.

## Konsequenzen

- Kein Codegen-Schritt in Build/CI, keine Toolversion zu pinnen.
- Volle Kontrolle über SQL (JSONB-Ausdrücke wie `jsonb_each_text`, `unnest`,
  Partitions-Queries) ohne Generator-Grenzen.
- Kein Compile-Time-Check der SQL-Strings — Absicherung stattdessen über
  Integrationstests gegen Testcontainer-Postgres (Coverage-Gate erzwingt sie).
- Rückbaupfad: Bei stark wachsender Query-Zahl kann sqlc je Paket eingeführt
  werden; das Schema bleibt unverändert.
