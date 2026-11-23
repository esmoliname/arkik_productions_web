# Arkik Productions — Deployment Guide (Vercel + Neon)

## Environments

Development (local), Preview (Vercel preview), Production (Vercel prod). Each
uses its own DATABASE_URL and credentials.

## Environment variables

- DATABASE_URL (Neon connection string; Preview -> Neon Staging, Production -> separate Neon Production project)
- APP_ENV (`development`, `staging`, `preview`, `production`; local stateless fallback without `DATABASE_URL` requires explicit `APP_ENV=development` and zero cloud/production flags)
- SEED_MODE (false in production)
- ADMIN_OWNER_PIN, ADMIN_IT_PIN (bootstrap / CLI rotation only; DB auth stays exclusive when DATABASE_URL is set)
- ADMIN_SESSION_SECRET (mandatory in both Production and Cloud/Preview runtimes — missing/placeholder throws `503`)
- ALLOWED_ORIGINS (optional comma-separated origins; empty = same-origin default)
- PUBLIC_APP_URL (optional operational metadata; not required by `api/`)

Set in Vercel Project Settings → Environment Variables per environment.
Never commit `.env`.

## Deploy steps

1. Connect repo to Vercel.
2. Set env vars for Preview (Neon Staging) and Production (separate Neon Production project).
3. Run local read-only staging preflight first (`APP_ENV=staging SEED_MODE=false node scripts/preflight-neon-staging.js` with temporary `NEON_STAGING_PREFLIGHT_*` + `NEON_STAGING_EXPECTED_ENDPOINT_ID`, removed immediately afterwards). Then set local `DIRECT_DATABASE_URL` (`arkik_migrator` for `npm run db:migrate`) and `DIRECT_ADMIN_DATABASE_URL` (`arkik_admin` for `npm run admin:verify` / `admin:rotate`), both Neon Direct endpoints never added to Vercel; run `npm run db:migrate`, apply least-privilege role grants (`P0.4.5-C`), and run `npm run admin:verify`.
4. (Local dev PostgreSQL only, never Staging/Preview/Prod) `SEED_MODE=true APP_ENV=development npm run db:seed:dev`.
5. Deploy (Vercel auto-build). Verify `GET /api/health` (`200`, `database: "not_checked"`, pure liveness) and `GET /api/ready` (`200`, `ready: true`, `database: "connected"` via `SELECT 1`).
6. Configure custom domain via Vercel Domains (owner approval required). `vercel.json` emits `Strict-Transport-Security: max-age=31536000` without `includeSubDomains` so future subdomains are never prematurely locked out.

## PostgreSQL Runtime Timeouts (`AUD-04`)

- Runtime transactions (`api/_lib/db.js`) enforce `lock_timeout = 3000` ms, `statement_timeout = 8000` ms, and `idle_in_transaction_session_timeout = 10000` ms (inactivity limit inside an open transaction, not total operation duration which is bounded by `query_timeout = 11000` ms and `DEFAULT_OPERATION_TIMEOUT_MS = 12000` ms). Match these values on `ALTER ROLE arkik_app`. Direct admin CLI (`arkik_admin`) operates independently with `statement_timeout = 10000`, `lock_timeout = 3000`, `idle_in_transaction_session_timeout = 15000`.

## Node

Engines node >=22. Vercel must use Node 22.