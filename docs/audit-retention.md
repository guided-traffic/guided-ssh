# Audit Retention and Append-only Guarantee

Applies to the `audit_events` table (Phase 1). Goal: audit data is
immutable, its growth is manageable, and deletion happens exclusively in a
controlled way via partitions — never row by row.

## Append-only guarantee (two layers)

1. **Trigger (in the schema, migration 0001):** `audit_events_append_only`
   rejects UPDATE and DELETE on `audit_events` (including all partitions)
   with an exception — regardless of which role performs the access.
2. **DB grants (operations):** The application role is granted only
   `INSERT` and `SELECT` on `audit_events` — no `UPDATE`, `DELETE`, or
   `TRUNCATE`. Migrations run as the schema owner (a separate role).
   Example:

   ```sql
   CREATE ROLE guidedssh_app LOGIN;
   GRANT USAGE ON SCHEMA public TO guidedssh_app;
   GRANT SELECT, INSERT ON audit_events TO guidedssh_app;
   -- other tables: SELECT, INSERT, UPDATE, DELETE as needed
   ```

   Note: `TRUNCATE` does not fire row triggers — the missing
   `TRUNCATE` grant is therefore a mandatory part of the guarantee, not optional.

Retention deletions deliberately bypass both layers via `DETACH`/`DROP` of
entire partitions, performed by a privileged maintenance role (see below) —
row-by-row deletion therefore remains unusual and conspicuous even for admins.

## Partitioning by month

`audit_events` is `PARTITION BY RANGE (occurred_at)`; the primary key is
`(id, occurred_at)`, because the partition key must be part of the PK.

- **As of Phase 1:** Only `audit_events_default` exists. It catches all
  rows as long as no monthly partitions have been created — functionally
  correct, but without any retention benefit.
- **Target state (from go-live onward):** One partition per month, created
  before the start of the month (e.g. by a CronJob, Phase 11):

  ```sql
  CREATE TABLE audit_events_2026_08 PARTITION OF audit_events
      FOR VALUES FROM ('2026-08-01T00:00:00Z') TO ('2026-09-01T00:00:00Z');
  ```

- **Retention expiry** (retention period configurable, default recommendation
  18 months; the operator's regulatory requirements take precedence):

  1. `ALTER TABLE audit_events DETACH PARTITION audit_events_2025_01;`
  2. Optionally archive (`COPY ... TO` / `pg_dump` of the detached table
     to object storage, compressed).
  3. `DROP TABLE audit_events_2025_01;`

  Detach + drop are metadata-fast and produce no row-by-row DELETE volume
  (no bloat, no vacuum pressure).

## Operational notes

- Partition maintenance (creating upcoming months, detaching/dropping expired
  ones) will be implemented in Phase 11 as a Kubernetes CronJob with its own
  DB role; until then it is done manually following the pattern above.
- If a row ends up in the default partition (because a partition was
  missing), correct it later via a `DETACH`/re-attach window — the content
  stays unchanged.
- SIEM streaming (Phase 8) reduces the dependency on long DB retention:
  the export is the long-term store, the DB holds the query window.
