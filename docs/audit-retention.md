# Audit-Retention und Append-only-Garantie

Gilt für die Tabelle `audit_events` (Phase 1). Ziel: Audit-Daten sind
unveränderlich, ihr Wachstum ist beherrschbar, Löschung geschieht ausschließlich
kontrolliert über Partitionen — nie zeilenweise.

## Append-only-Garantie (zwei Schichten)

1. **Trigger (im Schema, Migration 0001):** `audit_events_append_only` lehnt
   UPDATE und DELETE auf `audit_events` (inkl. aller Partitionen) mit einer
   Exception ab — unabhängig davon, mit welcher Rolle zugegriffen wird.
2. **DB-Grants (Betrieb):** Die Anwendungsrolle erhält auf `audit_events` nur
   `INSERT` und `SELECT` — kein `UPDATE`, `DELETE` oder `TRUNCATE`. Migrationen
   laufen als Schema-Owner (separate Rolle). Beispiel:

   ```sql
   CREATE ROLE guidedssh_app LOGIN;
   GRANT USAGE ON SCHEMA public TO guidedssh_app;
   GRANT SELECT, INSERT ON audit_events TO guidedssh_app;
   -- übrige Tabellen: SELECT, INSERT, UPDATE, DELETE nach Bedarf
   ```

   Hinweis: `TRUNCATE` feuert keine Row-Trigger — der fehlende
   `TRUNCATE`-Grant ist daher zwingender Teil der Garantie, nicht Kür.

Retention-Löschungen umgehen beide Schichten bewusst per `DETACH`/`DROP`
ganzer Partitionen durch eine privilegierte Wartungsrolle (siehe unten) —
zeilenweises Löschen bleibt damit auch für Admins ungewöhnlich und auffällig.

## Partitionierung nach Monat

`audit_events` ist `PARTITION BY RANGE (occurred_at)`; der Primärschlüssel ist
`(id, occurred_at)`, weil der Partitionsschlüssel Teil des PK sein muss.

- **Stand Phase 1:** Es existiert nur `audit_events_default`. Sie fängt alle
  Zeilen, solange keine Monatspartitionen angelegt sind — funktional korrekt,
  aber ohne Retention-Vorteil.
- **Zielbild (ab Inbetriebnahme):** Pro Monat eine Partition, angelegt vor
  Monatsbeginn (z. B. durch einen CronJob, Phase 11):

  ```sql
  CREATE TABLE audit_events_2026_08 PARTITION OF audit_events
      FOR VALUES FROM ('2026-08-01T00:00:00Z') TO ('2026-09-01T00:00:00Z');
  ```

- **Ablauf der Retention** (Aufbewahrungsfrist konfigurierbar, Default-Empfehlung
  18 Monate; regulatorische Vorgaben des Betreibers gehen vor):

  1. `ALTER TABLE audit_events DETACH PARTITION audit_events_2025_01;`
  2. Optional archivieren (`COPY ... TO` / `pg_dump` der abgehängten Tabelle
     nach Objektspeicher, komprimiert).
  3. `DROP TABLE audit_events_2025_01;`

  Detach + Drop sind metadaten-schnell und erzeugen kein zeilenweises
  DELETE-Volumen (kein Bloat, kein Vacuum-Druck).

## Betriebshinweise

- Partitions-Pflege (Anlegen künftiger Monate, Detach/Drop abgelaufener) wird in
  Phase 11 als Kubernetes-CronJob mit eigener DB-Rolle umgesetzt; bis dahin
  manuell nach obigem Muster.
- Läuft eine Zeile in die Default-Partition (Partition fehlte), später per
  `DETACH`/Re-Attach-Fenster korrigieren — Inhalte bleiben unverändert.
- SIEM-Streaming (Phase 8) reduziert die Abhängigkeit von langer DB-Retention:
  Export ist der Langzeitspeicher, die DB hält das Abfragefenster.
