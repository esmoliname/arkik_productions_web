-- Arkik Productions - 004 least-privilege grants (Neon PostgreSQL)
-- PREPARED during P0.4.5-B2; NOT EXECUTED yet.
-- Runs after 001-003. Grants are explicit per table (no blanket ALTER DEFAULT PRIVILEGES).
-- Executed as arkik_migrator (table owner) or neondb_owner.

-- Runtime application role (arkik_app) — pooled endpoint, DATABASE_URL
GRANT SELECT, INSERT, UPDATE ON bookings TO arkik_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON availability TO arkik_app;
GRANT SELECT, INSERT ON audit_log TO arkik_app;
GRANT SELECT, INSERT, UPDATE ON config TO arkik_app;
GRANT SELECT, UPDATE ON admin_credentials TO arkik_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON admin_sessions TO arkik_app;
GRANT SELECT, INSERT ON idempotency_keys TO arkik_app;
GRANT SELECT, INSERT, UPDATE ON rate_limits TO arkik_app;
GRANT SELECT ON schema_migrations TO arkik_app;
GRANT USAGE ON SEQUENCE audit_log_id_seq TO arkik_app;

-- Admin identity role (arkik_admin) — direct endpoint, DIRECT_ADMIN_DATABASE_URL
GRANT SELECT, UPDATE ON admin_credentials TO arkik_admin;
GRANT SELECT, DELETE ON admin_sessions TO arkik_admin;
GRANT SELECT, INSERT ON audit_log TO arkik_admin;
GRANT SELECT ON config TO arkik_admin;
GRANT SELECT ON bookings TO arkik_admin;
GRANT SELECT ON availability TO arkik_admin;

-- Migrator already owns created objects; ensure schema usage retained.
GRANT USAGE ON SCHEMA public TO arkik_app, arkik_admin;

-- Rollback (manual):
-- REVOKE ALL ON bookings, availability, audit_log, config, admin_credentials, admin_sessions,
--   idempotency_keys, rate_limits, schema_migrations FROM arkik_app;
-- REVOKE ALL ON admin_credentials, admin_sessions, audit_log, config, bookings, availability FROM arkik_admin;
