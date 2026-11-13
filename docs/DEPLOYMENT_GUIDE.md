# Arkik Productions — Deployment Guide (Vercel + Neon)

## Environments

Development (local), Preview (Vercel preview), Production (Vercel prod). Each
uses its own DATABASE_URL and credentials.

## Environment variables

- DATABASE_URL (Neon connection string)
- APP_ENV (development/preview/production)
- SEED_MODE (false in production)
- ADMIN_OWNER_PIN, ADMIN_IT_PIN
- ADMIN_SESSION_SECRET (required in prod)
- ALLOWED_ORIGINS (optional, same-origin default)
- PUBLIC_APP_URL

Set in Vercel Project Settings → Environment Variables per environment.
Never commit `.env`.

## Deploy steps

1. Connect repo to Vercel.
2. Set env vars for Preview and Production.
3. Run `npm run db:migrate` against the target Neon DB.
4. (Optional, dev only) `npm run db:seed:dev`.
5. Deploy (Vercel auto-build). Verify `/api/health` → database:true.
6. Configure custom domain via Vercel Domains (owner approval required).

## Node

Engines node >=22. Vercel must use Node 22.