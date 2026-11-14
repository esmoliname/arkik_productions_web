# Arkik Productions — Vercel + Neon Staging Deployment & Verification Guide

**Purpose:** Repeatable deployment and verification checklist for moving the Arkik Productions application from local verification to live Vercel Preview/Staging and Production with Neon PostgreSQL.

---

## 1. Required Environment Variables (Vercel Project Settings)

Configure separately for **Preview (Staging)** and **Production** (using distinct Neon databases/branches and distinct secrets):

| Variable | Staging / Production Value | Notes |
|---|---|---|
| `DATABASE_URL` | Neon pooled Postgres connection string (`sslmode=require`) | Required for authoritative DB auth, sessions, audit log, rate limits, bookings |
| `ADMIN_SESSION_SECRET` | `openssl rand -hex 32` (64+ hex chars) | **Mandatory in production** (`config.js` throws if missing when `VERCEL_ENV=production` or `NODE_ENV=production`) |
| `ADMIN_OWNER_PIN` | Pre-hashed `scrypt$...` string (recommended) or plaintext PIN | Used by `npm run db:migrate` to seed `admin_credentials` if missing; **never overwrites existing rows** |
| `ADMIN_IT_PIN` | Pre-hashed `scrypt$...` string (recommended) or plaintext PIN | Distinct credential for `it` role |
| `APP_ENV` | `staging` (Preview) / `production` (Prod) | Reflected in `/api/health` |
| `SEED_MODE` | `false` | Keep `false` in staging/prod so demo fixtures are never injected |
| `ALLOWED_ORIGINS` | Leave empty for same-origin, or comma-separated exact HTTPS origins | Cross-origin requests outside list get no ACAO and `403` on preflight |
| `PUBLIC_APP_URL` | `https://<staging-or-prod-domain>` | Used in customer emails/links |

---

## 2. Generating Pre-Hashed `scrypt$` PINs Locally

Instead of placing plaintext PINs in Vercel env vars, generate `scrypt$` hashes locally and store only the hashes in `ADMIN_OWNER_PIN` / `ADMIN_IT_PIN` before running `db/migrate.js`:

```bash
node -e "const auth = require('./api/_lib/auth'); console.log(auth.hashPin(process.argv[1]));" "<YOUR_STRONG_PIN>"
```

`db/migrate.js` detects valid `scrypt$...` strings automatically and stores them directly without double-hashing.

---

## 3. Running Schema Migrations & Bootstrapping Admin Credentials

With `.env.local` (never committed) pointing to your target Neon branch:

```bash
npm run db:migrate
```

Verify output shows:
- `001_initial_schema.sql`, `002_indexes.sql`, `003_config_seed.sql` applied or skipped cleanly.
- `[ARKIK DB] admin credentials bootstrapped for role "owner"` and `"it"`.
- No warning about empty `admin_credentials`.

---

## 4. Live Staging Verification Checklist (Run Against Vercel Preview HTTPS URL)

Because local sandboxes lack live Neon/Vercel credentials, execute these checks once deployed to Preview:

1. **Health check**: `GET https://<preview>/api/health` returns `200` with `database: "connected"` and `migrated: true`.
2. **Valid Owner login**:
   - Open Admin Modal -> select Propietario -> enter Owner PIN -> confirm `200` `/api/admin/login`, `Set-Cookie: __Host-session=...; HttpOnly; Secure; SameSite=Strict`, portal loads without console errors.
3. **RBAC check**:
   - Log in as Ingeniero TI -> confirm `/api/admin/dashboard` returns `200` and `/api/admin/pricing` `PUT` returns `403 forbidden`.
4. **Logout & session revocation**:
   - Click Cerrar Sesión -> confirm `POST /api/admin/logout` sets `Max-Age=0` and subsequent `GET /api/admin/dashboard` returns `401`.
5. **Infrastructure error honesty**:
   - Verify no `503` error in browser ever renders `"Credenciales inválidas"`.
6. **Important Cookie Note**:
   - When `NODE_ENV=production` or `VERCEL_ENV=production`, cookies use `__Host-session=...; Secure`. Testing production env flags over plain `http://localhost` (without TLS) will cause browsers to drop `Secure` cookies; always test HTTPS previews or keep `NODE_ENV=development` for plain HTTP local runs.

