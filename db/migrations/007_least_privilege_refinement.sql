-- Migration 007: Least-privilege refinement for arkik_app / arkik_admin
-- Forward-only. No historical migration is modified.
--
-- Preflight (must hold before applying):
--   1. arkik_app runtime in api/_lib/repo.js only reads/updates columns
--      failed_attempts, lock_level, locked_until, updated_at on public.admin_credentials.
--   2. arkik_app never reads public.schema_migrations (verified by static grep of api/).
--   3. arkik_admin (manage-admin-pins.js) never reads public.config, public.bookings, or public.availability.
--   4. arkik_app writes public.config via putConfigValue (INSERT ... ON CONFLICT
--      DO UPDATE SET value, updated_at) used by PUT /api/admin/pricing; only
--      value and updated_at are mutated. namespace and key are never mutated.
--
-- Reversibility: Each REVOKE/GRANT pair below is reversible by re-running the
-- equivalent GRANT from 004/005. Apply via a controlled staging verification
-- before production.

-- 1. arkik_app must not see schema_migrations (no runtime consumer).
REVOKE SELECT ON TABLE public.schema_migrations FROM arkik_app;

-- 2. arkik_app UPDATE on admin_credentials restricted to the columns it actually
--    mutates (failed_attempts, lock_level, locked_until, updated_at). pin_hash and
--    role remain read-only for arkik_app.
REVOKE UPDATE ON TABLE public.admin_credentials FROM arkik_app;
GRANT UPDATE (failed_attempts, lock_level, locked_until, updated_at) ON TABLE public.admin_credentials TO arkik_app;

-- 3. arkik_app UPDATE on public.config restricted to the columns it actually
--    mutates (value, updated_at). namespace and key remain read-only for
--    arkik_app (the UPSERT in putConfigValue updates only value + updated_at).
--    INSERT and SELECT on public.config are preserved from 004.
REVOKE UPDATE ON TABLE public.config FROM arkik_app;
GRANT UPDATE (value, updated_at) ON TABLE public.config TO arkik_app;

-- 4. arkik_admin does not need read access to config, bookings, or availability.
REVOKE SELECT ON TABLE public.config FROM arkik_admin;
REVOKE SELECT ON TABLE public.bookings FROM arkik_admin;
REVOKE SELECT ON TABLE public.availability FROM arkik_admin;

-- Preserve arkik_app SELECT on admin_credentials (credential lookup) and the
-- arkik_admin grants from 004/005/006 (unchanged).
