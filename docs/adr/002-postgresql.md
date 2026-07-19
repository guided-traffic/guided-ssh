# ADR-002: PostgreSQL als Datenbank

- Status: akzeptiert
- Datum: 2026-07-19

## Kontext

Benötigt werden: transaktionssicheres Audit-Log (Ausstellung + Audit-Event atomar),
flexible Zertifikats-Metadaten, Grants/ACLs, Betrieb in Kubernetes.

## Entscheidung

PostgreSQL als einzige Datenbank.

## Konsequenzen

- ACID: Zertifikatsausstellung und `audit_events`-Eintrag in einer Transaktion.
- JSONB für Zertifikats-Metadaten und variable Claim-Kontexte.
- Append-only-Schutz über DB-Grants (kein UPDATE/DELETE) plus Trigger möglich.
- Partitionierung nach Monat für Audit-Retention.
- Betrieb: extern oder CloudNativePG; Tests via Testcontainer.
