# Neon STAGING — Provisioning Plan & Matrices (P0.4.5-C, prepared)

Prepared during P0.4.5-B2. No execution performed.

## Role matrix

| Role | Login | Superuser | Createdb | Createrole | Replication | BypassRLS | Purpose |
|---|---|---|---|---|---|---|---|
| `neondb_owner` | yes | no (Neon-managed) | yes | yes (inherited) | yes | yes | Provisioner only; not used by app/migrations at runtime |
| `arkik_migrator` | yes | no | no | no | no | no | DDL/migrations via `DIRECT_DATABASE_URL` (direct endpoint) |
| `arkik_admin` | yes | no | no | no | no | no | Admin PIN verify/rotate, session revocation via `DIRECT_ADMIN_DATABASE_URL` (direct) |
| `arkik_app` | yes | no | no | no | no | no | Runtime via `DATABASE_URL` (pooled endpoint) |

## Privilege matrix (after migration 004)

| Table | arkik_app | arkik_admin | arkik_migrator |
|---|---|---|---|
| bookings | SELECT, INSERT, UPDATE | SELECT | owner (ALL) |
| availability | SELECT, INSERT, UPDATE, DELETE | SELECT | owner |
| audit_log | SELECT, INSERT | SELECT, INSERT | owner |
| config | SELECT, INSERT, UPDATE | SELECT | owner |
| admin_credentials | SELECT, UPDATE | SELECT, UPDATE | owner |
| admin_sessions | SELECT, INSERT, UPDATE, DELETE | SELECT, DELETE | owner |
| idempotency_keys | SELECT, INSERT | — | owner |
| rate_limits | SELECT, INSERT, UPDATE | — | owner |
| schema_migrations | SELECT | — | owner |
| sequences (audit_log_id_seq) | USAGE | — | owner |

Schema: `arkik_migrator` has USAGE+CREATE on public; `arkik_app`/`arkik_admin` have USAGE only. `public` role has no CREATE.

## Timeout matrix

| Role | statement_timeout | lock_timeout | idle_in_transaction_session_timeout |
|---|---|---|---|
| arkik_app | 8s | 3s | 10s |
| arkik_admin | 8s | 3s | 10s |
| arkik_migrator | 60s | 10s | 60s |

## Identity separation

- `DATABASE_URL` → arkik_app → pooled endpoint (runtime).
- `DIRECT_DATABASE_URL` → arkik_migrator → direct endpoint (migrations).
- `DIRECT_ADMIN_DATABASE_URL` → arkik_admin → direct endpoint (admin pins).

Application code already uses these variables correctly; no code changes required.

## Migration order

1. `001_initial_schema.sql`
2. `002_indexes.sql`
3. `003_config_seed.sql`
4. `004_least_privilege_grants.sql` (prepared)

Provisioning (before migrations): `db/provisioning/001_create_roles.sql` → run migrations → `002_grants_extra.sql` → `003_role_timeouts.sql`.

## Backup & recovery strategy

- Pre-migration: take a Neon branch snapshot (Neon branching) before first DDL; keep as rollback point.
- Migrations are transactional (BEGIN/COMMIT, ROLLBACK on failure) and idempotent (CREATE ... IF NOT EXISTS, ON CONFLICT DO NOTHING).
- Checksums recorded in `schema_migrations`; drift detection blocks re-application.
- Advisory lock prevents concurrent migration runs.
- Rollback of DDL is manual; review each migration. For a clean reset on an empty staging DB, drop and recreate the branch.
- Secrets/credentials: never backed up in repo; stored in secure store / env.

## Integration test plan (post-provisioning, STAGING)

- Auth: owner/it login, session sliding, logout, RBAC (IT receives 403 on owner routes).
- Booking flow: create, idempotency replay, status transitions, availability overrides.
- Admin: pricing/availability CRUD, audit log, dashboard hydration.
- Readiness: `/api/ready` returns 200 connected with SELECT 1 under bounded timeouts.
- Liveness: `/api/health` stays DB-free 200.
- Timeout: statement_timeout 8s enforced (57014 on overrun).
- Connection identity: runtime uses pooled endpoint, migrator/admin use direct.

## Post-migration verification (read-only)

- Re-run `scripts/preflight-neon-staging.js` (expect non-virgin inventory; review unknown objects).
- `SELECT rolname, rolcanlogin FROM pg_roles WHERE rolname IN (...)`.
- `SELECT has_table_privilege('arkik_app','bookings','INSERT')` etc.
- `SHOW statement_timeout` per role.
- Application smoke tests against STAGING URL.

## Rollback procedure

- Before any migration: Neon branch snapshot.
- Role creation rollback: `DROP ROLE IF EXISTS arkik_app, arkik_admin, arkik_migrator;` (only if no dependent objects).
- Grant rollback: REVOKE per table (commented in grant files).
- Timeout rollback: `ALTER ROLE ... RESET ...`.
- Migration rollback: manual; restore from Neon branch snapshot if needed.
