-- Arkik Productions - 005 admin credentials insert grant (Neon PostgreSQL)
-- Prepared during P0.4.5-D.
-- The upsert in manage-admin-pins (INSERT ... ON CONFLICT) requires INSERT on admin_credentials
-- for arkik_admin, in addition to the SELECT/UPDATE granted in 004.

GRANT INSERT ON admin_credentials TO arkik_admin;
