-- Arkik Productions - 002 indexes (idempotent)

-- Active bookings per date (capacity / availability hot path).
CREATE INDEX IF NOT EXISTS idx_bookings_selected_date_active
  ON bookings (selected_date) WHERE status <> 'cancelada';

CREATE INDEX IF NOT EXISTS idx_bookings_status ON bookings (status);
CREATE INDEX IF NOT EXISTS idx_bookings_created_at ON bookings (created_at DESC);

-- Replay lookups for POST /api/bookings.
CREATE UNIQUE INDEX IF NOT EXISTS idx_bookings_idempotency_key
  ON bookings (idempotency_key) WHERE idempotency_key IS NOT NULL;

-- Audit browsing.
CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_entity ON audit_log (entity_type, entity_id);

-- Session sweep / expiry checks.
CREATE INDEX IF NOT EXISTS idx_admin_sessions_expires_at ON admin_sessions (expires_at);

-- Rate limiter window pruning.
CREATE INDEX IF NOT EXISTS idx_rate_limits_window_start ON rate_limits (window_start);
