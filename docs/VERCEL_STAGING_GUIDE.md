# Arkik Productions — Vercel + Neon Staging Deployment & Verification Guide

**Purpose:** Repeatable deployment and verification checklist for moving the Arkik Productions application from local verification to live Vercel Preview/Staging and Production with Neon PostgreSQL.

---

## 1. Required Environment Variables (Vercel Project Settings)

Configure separately for **Preview (Staging)** and **Production** (using distinct Neon databases/branches and distinct secrets):

| Variable | Staging / Production Value | Notes |
|---|---|---|
| `DATABASE_URL` | Neon **pooled** Postgres connection string (`-pooler`, `sslmode=require`, runtime role `arkik_app`) | Required for authoritative DB auth, sessions, audit log, rate limits, bookings. **Never place `DIRECT_DATABASE_URL` or `DIRECT_ADMIN_DATABASE_URL` in Vercel.** |
| `ADMIN_SESSION_SECRET` | `openssl rand -hex 32` (64+ hex chars) | **Mandatory in Staging, Preview, Production, Cloud, and whenever `DATABASE_URL` is configured** (`config.js` throws `503` if missing/placeholder when `!isExplicitLocalDev`; `'dev-secret-change-me'` fallback is restricted to explicit local `APP_ENV=development` without DB or cloud/staging/prod flags) |
| `ADMIN_OWNER_PIN` | Pre-hashed `scrypt$...` string (recommended) or plaintext PIN (`>= 6` chars) | Used locally by `npm run db:migrate` (`DIRECT_DATABASE_URL`) to seed `admin_credentials` if missing (**never overwrites existing rows**), and verified/rotated via `DIRECT_ADMIN_DATABASE_URL` |
| `ADMIN_IT_PIN` | Pre-hashed `scrypt$...` string (recommended) or plaintext PIN (`>= 6` chars) | Distinct credential for `it` role |
| `APP_ENV` | `staging` (Preview) / `production` (Prod) | Reflected in environment resolution; stateless fallback without `DATABASE_URL` requires explicit `APP_ENV=development` locally |
| `SEED_MODE` | `false` | Keep `false` in staging/prod so demo fixtures are never injected (`db/seed-dev.js` also blocks non-development/remote targets) |
| `ALLOWED_ORIGINS` | Leave empty for same-origin, or comma-separated exact HTTPS origins | Cross-origin requests outside list get no ACAO and `403` on preflight |
| `PUBLIC_APP_URL` | `https://<staging-or-prod-domain>` | Optional operational metadata (not required by `api/`) |

---

## 2. Generating Pre-Hashed `scrypt$` PINs Locally

Instead of placing plaintext PINs in Vercel env vars, generate `scrypt$` hashes locally and store only the hashes in `ADMIN_OWNER_PIN` / `ADMIN_IT_PIN` before running `db/migrate.js`:

```bash
node -e "const auth = require('./api/_lib/auth'); console.log(auth.hashPin(process.argv[1]));" "<YOUR_STRONG_PIN>"
```

`db/migrate.js` detects valid `scrypt$...` strings automatically and stores them directly without double-hashing.

---

## 3. Preflight Read-Only (`P0.4.5-B`), Schema Migrations & Role Cutover (`P0.4.5-C`)

1. **Read-only Staging preflight (temporary local vars only, removed right after):**
   With local `APP_ENV=staging`, `SEED_MODE=false`, `NEON_STAGING_EXPECTED_ENDPOINT_ID`, `NEON_STAGING_PREFLIGHT_DIRECT_URL`, and `NEON_STAGING_PREFLIGHT_POOLED_URL` (zero Vercel usage, zero fallback):
   ```bash
   node scripts/preflight-neon-staging.js
   ```
   Confirm `verdict: "READY"`, verify `timeoutsDirect` / `timeoutsPooled` (`statement_timeout = 8s`, `lock_timeout = 3s`, `idle_in_transaction_session_timeout = 10s`, `transaction_read_only = on`), confirm zero unknown pre-existing objects, and then delete the three temporary `NEON_STAGING_PREFLIGHT_*` / `NEON_STAGING_EXPECTED_ENDPOINT_ID` vars from `.env.local`.

2. **Schema migrations & least-privilege roles (`P0.4.5-C`):**
   With `.env.local` (never committed) setting `DIRECT_DATABASE_URL` (`arkik_migrator`) and `DIRECT_ADMIN_DATABASE_URL` (`arkik_admin`) to your target Neon **direct** (non-`-pooler`) endpoints:

```bash
npm run db:migrate
```

Verify output shows:
- `001_initial_schema.sql`, `002_indexes.sql`, `003_config_seed.sql` applied or skipped cleanly.
- `[ARKIK DB] admin credentials bootstrapped for role "owner"` and `"it"`.
- No warning about empty `admin_credentials`.
- Explicit least-privilege `GRANT` statements applied to `arkik_app` and `arkik_admin` (future migrations running as `arkik_migrator` must embed explicit `GRANT` statements per table/column instead of blanket `ALTER DEFAULT PRIVILEGES`), and `arkik_app` role timeouts aligned (`statement_timeout = '8000'`, `lock_timeout = '3000'`, `idle_in_transaction_session_timeout = '10000'`, where `10000` ms is the open-transaction inactivity limit vs `11000` ms `query_timeout` / `12000` ms `DEFAULT_OPERATION_TIMEOUT_MS`).

---

## 4. Live Staging Verification Checklist (Run Against Vercel Preview HTTPS URL)

Because local sandboxes lack live Neon/Vercel credentials, execute these checks once deployed to Preview:

1. **Liveness & Readiness checks**:
   - `GET https://<preview>/api/health` returns `200` with `status: "ok"` and `database: "not_checked"` (pure liveness, zero database queries even if Neon is unavailable).
   - `GET https://<preview>/api/ready` returns `200` with `ready: true` and `database: "connected"` after executing a single `SELECT 1` (`503` when `"unconfigured"` or `"unavailable"`).
2. **Valid Owner login**:
   - Open Admin Modal -> select Propietario -> enter Owner PIN -> confirm `200` `/api/admin/login`, `Set-Cookie: __Host-session=...; HttpOnly; Secure; SameSite=Strict`, portal loads without console errors.
   - Verify database-backed authentication is used exclusively whenever `DATABASE_URL` is set (even if `ADMIN_OWNER_PIN` / `ADMIN_IT_PIN` are also present in Vercel for initial bootstrap).
3. **RBAC check**:
   - Log in as Ingeniero TI -> confirm `/api/admin/dashboard` returns `200` and `/api/admin/pricing` `PUT` returns `403 forbidden`.
4. **Logout & session revocation**:
   - Click Cerrar Sesión -> confirm `POST /api/admin/logout` sets `Max-Age=0` and subsequent `GET /api/admin/dashboard` returns `401`.
5. **Infrastructure error honesty**:
   - Verify no `503` error in browser ever renders `"Credenciales inválidas"`.
6. **Important Cookie & HSTS Notes**:
   - When `NODE_ENV=production`, `VERCEL_ENV=production`, `VERCEL=1`, or `VERCEL_ENV=preview`, cookies use `__Host-session=...; Secure`. Testing production/preview env flags over plain `http://localhost` (without TLS) will cause browsers to drop `Secure` cookies; always test HTTPS previews or keep `NODE_ENV=development` for plain HTTP local runs.
   - `vercel.json` sets `Strict-Transport-Security: max-age=31536000` without `includeSubDomains` so future subdomains under custom domains (staging, assets, third-party CNAMEs) are never blocked before TLS provisioning. Notice Preview (`*.vercel.app`) inherits Vercel's platform HSTS while Production uses the explicit header for the configured domain.
   - Use `ALLOWED_ORIGINS` (never `ALLOWED_ORIGIN`) if cross-origin access is ever required; leave empty for strict same-origin.

