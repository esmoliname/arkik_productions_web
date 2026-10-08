-- Arkik Productions - 001 initial schema (Neon PostgreSQL)
-- Idempotent: CREATE TABLE IF NOT EXISTS only. Never DROP/TRUNCATE here.

CREATE TABLE IF NOT EXISTS schema_migrations (
  version    text PRIMARY KEY,
  applied_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS bookings (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  code              text NOT NULL UNIQUE,
  status            text NOT NULL DEFAULT 'pendiente'
                      CHECK (status IN ('pendiente','confirmada','realizada','cancelada')),
  client_name       text NOT NULL,
  client_phone      text NOT NULL,
  client_email      text,
  event_type        text NOT NULL,
  service_id        integer NOT NULL,
  service_name      text NOT NULL,
  setup_display     text,
  teardown_display  text,
  selected_date     date NOT NULL,
  selected_time     text NOT NULL CHECK (selected_time ~ '^(0[8-9]|1[0-9]|2[0-3]):00$'),
  province          text NOT NULL,
  canton            text NOT NULL,
  address           text,
  subtotal          integer NOT NULL CHECK (subtotal >= 0),
  travel_surcharge  integer NOT NULL DEFAULT 0 CHECK (travel_surcharge >= 0),
  grand_total       integer NOT NULL CHECK (grand_total >= 0),
  deposit_amount    integer NOT NULL CHECK (deposit_amount >= 0),
  remaining_balance integer NOT NULL CHECK (remaining_balance >= 0),
  sinpe_reference   text,
  extras            jsonb NOT NULL DEFAULT '{}'::jsonb,
  voucher_image     text,
  voucher_mime      text,
  voucher_bytes     integer,
  idempotency_key   text,
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now(),
  confirmed_at      timestamptz,
  cancelled_at      timestamptz,
  completed_at      timestamptz
);

-- Calendar overrides: one row per blocked date.
CREATE TABLE IF NOT EXISTS availability (
  date       date PRIMARY KEY,
  state      text NOT NULL CHECK (state IN ('disabled','soldout')),
  reason     text CHECK (reason IS NULL OR char_length(reason) <= 120),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_log (
  id          bigserial PRIMARY KEY,
  action      text NOT NULL,
  entity_type text,
  entity_id   text,
  actor       text,
  metadata    jsonb,
  created_at  timestamptz NOT NULL DEFAULT now()
);

-- Runtime configuration (logistics, pricing, geo, sinpe).
CREATE TABLE IF NOT EXISTS config (
  namespace text NOT NULL,
  key       text NOT NULL,
  value     jsonb NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (namespace, key)
);

-- One row per admin role, seeded by db/migrate.js from env pins (never rotated on deploy).
CREATE TABLE IF NOT EXISTS admin_credentials (
  role           text PRIMARY KEY CHECK (role IN ('owner','it')),
  pin_hash       text NOT NULL,
  failed_attempts integer NOT NULL DEFAULT 0,
  lock_level     integer NOT NULL DEFAULT 0,
  locked_until   timestamptz,
  updated_at     timestamptz NOT NULL DEFAULT now()
);

-- Sliding sessions; only the HMAC-SHA256 of the token is stored.
CREATE TABLE IF NOT EXISTS admin_sessions (
  token_hash   text PRIMARY KEY,
  role         text NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS idempotency_keys (
  key         text PRIMARY KEY,
  booking_id  uuid NOT NULL REFERENCES bookings(id) ON DELETE CASCADE,
  created_at  timestamptz NOT NULL DEFAULT now()
);

-- Fixed-window rate limiter buckets.
CREATE TABLE IF NOT EXISTS rate_limits (
  bucket       text PRIMARY KEY,
  window_start timestamptz NOT NULL,
  count        integer NOT NULL DEFAULT 0
);
