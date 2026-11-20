-- Arkik Productions - Prepared role timeout alignment (P0.4.5-C)
-- STATUS: PREPARED, NOT EXECUTED.
-- Run as neondb_owner or a role with ALTER ROLE privilege.

-- Runtime app: bounded timeouts aligned with app-level 12s operation timeout
ALTER ROLE arkik_app SET statement_timeout = '8s';
ALTER ROLE arkik_app SET lock_timeout = '3s';
ALTER ROLE arkik_app SET idle_in_transaction_session_timeout = '10s';

-- Admin identity: same bounds
ALTER ROLE arkik_admin SET statement_timeout = '8s';
ALTER ROLE arkik_admin SET lock_timeout = '3s';
ALTER ROLE arkik_admin SET idle_in_transaction_session_timeout = '10s';

-- Migrator: generous bounds for DDL
ALTER ROLE arkik_migrator SET statement_timeout = '60s';
ALTER ROLE arkik_migrator SET lock_timeout = '10s';
ALTER ROLE arkik_migrator SET idle_in_transaction_session_timeout = '60s';

-- Rollback:
-- ALTER ROLE arkik_app RESET statement_timeout;
-- ALTER ROLE arkik_app RESET lock_timeout;
-- ALTER ROLE arkik_app RESET idle_in_transaction_session_timeout;
-- (repeat for arkik_admin, arkik_migrator)
