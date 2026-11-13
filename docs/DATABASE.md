# Arkik Productions — Database

## Engine

Neon PostgreSQL via `@neondatabase/serverless`. Connection string in
`DATABASE_URL` (server-side only).

## Migrations

`db/migrations/*.sql` applied by `node db/migrate.js` (npm run db:migrate),
idempotently, each file in its own transaction, recorded in `schema_migrations`.
Never DROP/TRUNCATE.

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