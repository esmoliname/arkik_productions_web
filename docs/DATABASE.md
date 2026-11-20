# Arkik Productions — Database

## Engine

Neon PostgreSQL via `@neondatabase/serverless`. Runtime Vercel uses `DATABASE_URL` (`-pooler`, least-privilege role `arkik_app`). Direct CLI connections are strictly separated with zero fallback: `db/migrate.js` (`arkik_migrator`) and `db/seed-dev.js` (strict loopback + `APP_ENV=development` only) use `DIRECT_DATABASE_URL`, whereas `db/manage-admin-pins.js` (`arkik_admin`) uses `DIRECT_ADMIN_DATABASE_URL` (neither Direct variable is ever configured in Vercel runtime).

## Migrations

`db/migrations/*.sql` applied by `node db/migrate.js` (`npm run db:migrate`) over `DIRECT_DATABASE_URL`, protected by session `pg_advisory_lock` on a single Direct client and SHA-256 `checksum` verification in `schema_migrations`, with bounded `SET LOCAL lock_timeout` and `statement_timeout`. Never DROP/TRUNCATE. Multi-statement `;` splitting for `-- arkik:no-tx` migrations is intentionally deferred until a full SQL lexer/parser is ever required (never naive `;` splitting).

### Pre-cutover Role Timeouts (`P0.4.5-C`) & Runtime Coherency (`AUD-04`)

- Runtime transactions (`api/_lib/db.js`) and `arkik_app` role defaults align on:
  - `lock_timeout = 3000` ms (`3s`)
  - `statement_timeout = 8000` ms (`8s`)
  - `idle_in_transaction_session_timeout = 10000` ms (`10s`) — strictly the **inactivity timeout inside an open transaction** (preventing abandoned idle transactions on locks/connections), **not** total operation duration (bounded by client `query_timeout = 11000` ms and `DEFAULT_OPERATION_TIMEOUT_MS = 12000` ms).
- Administrative Direct roles maintain their own independent budgets matching their CLI workloads (`arkik_admin`: `statement_timeout = 10000`, `lock_timeout = 3000`, `idle_in_transaction_session_timeout = 15000`; `arkik_migrator`: `statement_timeout = 60000`, `lock_timeout = 5000`, `idle_in_transaction_session_timeout = 60000`).
- Before enabling `arkik_app` in staging/production runtime (`P0.4.5-C`), apply role-level defaults in Neon via `ALTER ROLE arkik_app SET statement_timeout = '8000'`, `lock_timeout = '3000'`, `idle_in_transaction_session_timeout = '10000'` as defense-in-depth alongside per-transaction `SET LOCAL`.

### Future Migration Ownership & Privilege Strategy (`P0.4.5-C`+)

- **Evaluated mechanisms:**
  1. `ALTER DEFAULT PRIVILEGES FOR ROLE arkik_migrator IN SCHEMA public`: automatically grants blanket table/sequence privileges, **rejected** for tables/views because PostgreSQL default privileges do not support column-level grants (`admin_credentials`, `config`) and cannot differentiate append-only/no-`DELETE` tables (`bookings`, `audit_log`, `idempotency_keys`) from tables permitting `DELETE` (`availability`, `admin_sessions`). Default `REVOKE ALL` remains in effect.
  2. Execution strictly under `arkik_migrator` identity: guarantees consistent table/sequence ownership so DDL, indexes, and future `ALTER TABLE` never fail on mixed `neondb_owner` ownership.
  3. Explicit least-privilege `GRANT` statements embedded in each future SQL migration file: allows exact table, sequence, and column scoping reviewed via SHA-256 migration checksums.
- **Adopted policy:** All schema migrations execute strictly as `arkik_migrator` (`DIRECT_DATABASE_URL`) and every migration adding new objects must include explicit, minimal `GRANT` statements for `arkik_app` / `arkik_admin` (zero reliance on blanket `ALTER DEFAULT PRIVILEGES` on tables, zero implicit `PUBLIC` grants).

### Read-Only Staging Preflight (`scripts/preflight-neon-staging.js`)

Before provisioning roles on a Staging branch (`P0.4.5-B`), run local read-only verification using strictly temporary env vars (`NEON_STAGING_PREFLIGHT_DIRECT_URL`, `NEON_STAGING_PREFLIGHT_POOLED_URL`, `NEON_STAGING_EXPECTED_ENDPOINT_ID`) inside `BEGIN READ ONLY ... ROLLBACK` blocks, then remove those temporary variables from `.env.local` immediately after completion (never add them to Vercel).

- `001_initial_schema.sql`: bookings, availability, audit_log, config,
  admin_credentials, admin_sessions, idempotency_keys, rate_limits.
- `002_indexes.sql`: performance indexes.
- `003_config_seed.sql`: catalog/geo/pricing seeds.

## Key constraints

- `bookings.code` UNIQUE.
- `bookings.status` CHECK in (pendiente, confirmada, realizada, cancelada).
- `idempotency_keys.key` PRIMARY KEY → bookings.id (CASCADE).
- Advisory lock `pg_advisory_xact_lock` per date serializes capacity writers.

## Seeding

`db/seed-dev.js` (npm run db:seed:dev) only in development. Production must
use `SEED_MODE=false` and never run seed-dev against production.

## Backups

Use Neon's built-in backup/branching. No destructive migrations without
explicit approval and verified backup.