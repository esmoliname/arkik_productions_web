-- Arkik Productions - 006 admin audit_log sequence grant (Neon PostgreSQL)
-- Prepared during P0.4.5-D.
-- rotate writes to audit_log (bigserial id), requiring USAGE on audit_log_id_seq for arkik_admin.

GRANT USAGE, SELECT ON SEQUENCE audit_log_id_seq TO arkik_admin;
