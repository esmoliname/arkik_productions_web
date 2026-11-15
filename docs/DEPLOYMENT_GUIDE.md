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
3. Run `npm run db:migrate` against the target Neon DB.
4. (Optional, dev only) `npm run db:seed:dev`.
5. Deploy (Vercel auto-build). Verify `GET /api/health` (`200`, `database: "not_checked"`, pure liveness) and `GET /api/ready` (`200`, `ready: true`, `database: "connected"` via `SELECT 1`).
6. Configure custom domain via Vercel Domains (owner approval required). `vercel.json` emits `Strict-Transport-Security: max-age=31536000` without `includeSubDomains` so future subdomains are never prematurely locked out.

## Node

Engines node >=22. Vercel must use Node 22.