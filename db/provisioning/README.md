# Neon STAGING — Least-Privilege Provisioning (P0.4.5-C, prepared, NOT executed)

This directory holds SQL and procedures prepared during P0.4.5-B2. **Nothing here has been executed.** All files are templates that require explicit authorization before running against Neon STAGING.

## Preconditions (must all hold before execution)

1. `APP_ENV=staging`, `SEED_MODE=false`, no `VERCEL`/`VERCEL_ENV`, `NODE_ENV != production`.
2. Preflight `scripts/preflight-neon-staging.js` returned `READY` (P0.4.5-B2).
3. Connected as `neondb_owner` to the STAGING **direct** endpoint (not `-pooler`).
4. Endpoint ID matches `NEON_STAGING_EXPECTED_ENDPOINT_ID` (verified by preflight).
5. Virgin or known schema state confirmed by preflight inventory (Block E `PASS`).
6. Passwords for `arkik_migrator`, `arkik_admin`, `arkik_app` supplied from a secure store; never committed.

## Execution order

1. `001_create_roles.sql` — create the three least-privilege roles (run as `neondb_owner`).
2. Run existing migrations 001–003 as `arkik_migrator` (via `npm run db:migrate` with `DIRECT_DATABASE_URL` pointing to `arkik_migrator`).
3. `db/migrations/004_least_privilege_grants.sql` — grants app/admin on the created tables (runs automatically as part of migrate step 2 if present in `db/migrations/`).
4. `002_grants_extra.sql` — any grants not covered by migration 004 (admin pin management objects).
5. `003_role_timeouts.sql` — align role-level timeouts.
6. Post-provisioning verification (read-only): role existence, memberships, privileges, table inventory, timeouts.

## Identity separation

| Role | Connection variable | Endpoint | Purpose |
|---|---|---|---|
| `arkik_migrator` | `DIRECT_DATABASE_URL` | direct (no `-pooler`) | DDL/migrations only |
| `arkik_admin` | `DIRECT_ADMIN_DATABASE_URL` | direct (no `-pooler`) | Admin PIN verification/rotation, session revocation |
| `arkik_app` | `DATABASE_URL` | pooled (`-pooler`) | Runtime (bookings, availability, audit, config, auth, rate limits) |

Code already separates these identities (`db/migrate.js` uses `DIRECT_DATABASE_URL`; `db/manage-admin-pins.js` uses `DIRECT_ADMIN_DATABASE_URL`; `api/_lib/db.js` uses `DATABASE_URL`). No application code changes are required.

## Password supply (secure)

Passwords are passed via psql variables, never stored in files:

```
psql "$DIRECT_ADMIN_OR_MIGRATOR_URL" \
  -v migrator_password="$ARKIK_MIGRATOR_PASSWORD" \
  -v admin_password="$ARKIK_ADMIN_PASSWORD" \
  -v app_password="$ARKIK_APP_PASSWORD" \
  -f db/provisioning/001_create_roles.sql
```

For Neon, use the Neon SQL Editor or `psql` with the direct connection string. Never paste passwords into chat or commit them.

## Rollback

- Role creation: `DROP ROLE IF EXISTS arkik_app, arkik_admin, arkik_migrator;` (only if no objects depend on them; run before any migration).
- Grants: `REVOKE ...` per table (prepared in each grant file as commented rollback blocks).
- Migrations: handled by `schema_migrations` checksums; rollback of DDL is manual and must be reviewed per migration. Migration 001–003 are idempotent (`CREATE ... IF NOT EXISTS`, `ON CONFLICT DO NOTHING`), so re-running is safe.
- Timeouts: `ALTER ROLE ... RESET ...` restores defaults.

## Post-provisioning verification (read-only)

- `SELECT rolname, rolcanlogin, rolcreaterole FROM pg_roles WHERE rolname IN (...)`.
- `SELECT ... FROM pg_auth_members` (memberships).
- `SELECT has_table_privilege('arkik_app','bookings','INSERT')`, etc.
- `SELECT current_setting('statement_timeout')` per role.
- Re-run `scripts/preflight-neon-staging.js` to confirm schema non-virgin state is acceptable (Block E will now report the migrated objects; review unknown objects).

## Note on temporary variables

`NEON_STAGING_PREFLIGHT_DIRECT_URL`, `NEON_STAGING_PREFLIGHT_POOLED_URL`, and `NEON_STAGING_EXPECTED_ENDPOINT_ID` remain in `.env.local` for traceability. Remove them from `.env.local` before any Production use (per `docs/VERCEL_STAGING_GUIDE.md`).
