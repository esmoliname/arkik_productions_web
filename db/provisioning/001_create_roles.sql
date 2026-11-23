-- Arkik Productions - Prepared role creation (P0.4.5-C)
-- STATUS: PREPARED, NOT EXECUTED.
-- Run as neondb_owner against the STAGING DIRECT endpoint only.
-- Supply passwords via psql variables: -v migrator_password=... -v admin_password=... -v app_password=...
-- Example:
--   psql "$DIRECT_URL" -v migrator_password="$ARKIK_MIGRATOR_PASSWORD" \
--     -v admin_password="$ARKIK_ADMIN_PASSWORD" -v app_password="$ARKIK_APP_PASSWORD" \
--     -f db/provisioning/001_create_roles.sql

\set ON_ERROR_STOP on

-- Pass psql variables into session-level config (transaction-local) so they can be
-- read inside the dollar-quoted DO block via current_setting(). This avoids the
-- invalid :'var' interpolation inside $$...$$.
BEGIN;
SELECT set_config('arkik.migrator_pw', :'migrator_password', true),
       set_config('arkik.admin_pw', :'admin_password', true),
       set_config('arkik.app_pw', :'app_password', true);

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'arkik_migrator') THEN
    EXECUTE format(
      'CREATE ROLE arkik_migrator LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',
      current_setting('arkik.migrator_pw')
    );
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'arkik_admin') THEN
    EXECUTE format(
      'CREATE ROLE arkik_admin LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',
      current_setting('arkik.admin_pw')
    );
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'arkik_app') THEN
    EXECUTE format(
      'CREATE ROLE arkik_app LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',
      current_setting('arkik.app_pw')
    );
  END IF;
END
$$;
COMMIT;

-- Database connect
GRANT CONNECT ON DATABASE neondb TO arkik_migrator, arkik_admin, arkik_app;

-- Schema usage: migrator can create; app/admin use only
GRANT USAGE, CREATE ON SCHEMA public TO arkik_migrator;
GRANT USAGE ON SCHEMA public TO arkik_admin, arkik_app;

-- Rollback (manual, only if no objects depend on these roles):
-- REVOKE ALL ON SCHEMA public FROM arkik_migrator, arkik_admin, arkik_app;
-- REVOKE CONNECT ON DATABASE neondb FROM arkik_migrator, arkik_admin, arkik_app;
-- DROP ROLE IF EXISTS arkik_app, arkik_admin, arkik_migrator;
