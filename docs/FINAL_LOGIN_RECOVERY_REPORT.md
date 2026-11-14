# Arkik Productions — Final Login Recovery Report

**Incident:** P0 Critical Authentication Failure — Administrative PIN Login Unusable / Broken Error Feedback  
**Date:** 2026-11-13  
**Outcome:** Architectural & code repairs complete and verified against 7 automated suites locally; live Neon & Vercel HTTPS Preview verification marked `BLOCKED / NOT VERIFIED` pending environment credentials.

---

## 1. Root Causes Identified & Resolved

Full technical evidence is recorded in [`docs/AUTHENTICATION_ROOT_CAUSE.md`](AUTHENTICATION_ROOT_CAUSE.md). Summary of fixes:

1. **Split-Brain Auth Bypass (`api/admin/login.js`, `api/_lib/auth.js`)**:
   - **Before**: Presence of *any* env PIN bypassed `service.login()`, PostgreSQL `admin_credentials`, `admin_sessions`, distributed `rate_limits`, and `audit_log`, breaking DB-rotated credentials and partial role configurations.
   - **Fix**: `service.login()` (PostgreSQL) is now authoritative whenever `config.databaseUrl` is set. Stateless env-PIN fallback only runs when `DATABASE_URL` is absent. `requireAdmin()` rejects stateless `v1.` tokens whenever `DATABASE_URL` is configured.
2. **Migration Double-Hashing & Alias Mismatch (`db/migrate.js`)**:
   - **Before**: `bootstrapAdmins()` ran `auth.hashPin(pin)` even when `ADMIN_OWNER_PIN` / `ADMIN_IT_PIN` already held a pre-hashed `scrypt$...` value, producing unmatchable hashes in PostgreSQL, and ignored `ADMIN_PIN_OWNER`/`ADMIN_PIN_IT`.
   - **Fix**: Added `auth.isValidScryptHash()` check in `bootstrapAdmins()` so pre-hashed `scrypt$` credentials are stored directly (or rejected explicitly if malformed), supported both env aliases, and preserved `ON CONFLICT (role) DO NOTHING`.
3. **PIN Input Mutation Mismatch (`js/app.js`, `api/admin/login.js`, `api/_lib/auth.js`, `index.html`)**:
   - **Before**: `SecurityModule.normalizePin()`, `sanitizePin()`, and `verifyEnvPin()` stripped non-digit characters (`.replace(/\D/g, '')`), and `#admin-pin` capped length at `8`, contradicting `db/migrate.js` / `service.login()`.
   - **Fix**: Unified on `.trim()` (max 64 chars in validators, `maxlength="32"` on `#admin-pin`) without stripping valid characters, preserving numeric keypad UX (`inputmode="numeric"`).
4. **Silent `503` / Network Masking & False Lockout (`js/app.js`)**:
   - **Before**: Database outages (`503`), missing API routes (`404`), `5xx`, and network errors (`0`) were turned into `"Credenciales inválidas"` and counted toward local brute-force lockout.
   - **Fix**: `SecurityModule.verifyPin` and `AdminModule.attemptLogin` now isolate infrastructure/connectivity errors (`infraError: true`) from authentication rejections (`401`/`403`) and server lockouts (`429`), preventing false lockouts and preserving existing Glassmorphism UI/UX.
5. **Broken Logout Cookie Clearing & Stats Schema Drift (`api/admin/logout.js`, `api/_lib/service.js`, `api/admin/dashboard.js`)**:
   - **Before**: `logout.js` aborted with `503` before emitting `clearSessionCookie()` when DB failed or token was `v1.`, and `dashboard.js` swallowed `503` with mismatched `DEFAULT_STATS` fields even when `DATABASE_URL` existed.
   - **Fix**: `logout.js` always emits `clearSessionCookie()`, `service.logout` handles `v1.` tokens cleanly, `dashboard.js` aligns `DEFAULT_STATS` with `repo.getStats()` and only uses fallback when `!config.databaseUrl`, and `service.login()` distinguishes uninitialized `admin_credentials` (`503`) from wrong PIN (`401`).

---

## 2. Verification Matrix

| Check | Status | Details |
|---|---|---|
| `npm run check` | PASS | `js/app.js`, `js/data.js`, `js/api.js` |
| `npm test` | PASS | 7/7 suites passed, including `test/auth-recovery.test.cjs` (20 scenarios + HTTP E2E handler dispatch + `SecurityModule` VM checks) |
| `npm ls --depth=0` | PASS | Clean dependency tree |
| `git diff --check` | PASS | Clean working tree formatting |
| Secret scan (`node`) | PASS | 0 hardcoded PINs, hashes, or Postgres URIs in source |
| `npm audit` / `--omit=dev` | BLOCKED | Offline sandbox (`ENOTFOUND registry.npmjs.org`) |
| Live Neon DB migration & SQL session roundtrip | BLOCKED / NOT VERIFIED | Requires real `DATABASE_URL` in operator environment |
| Live Vercel Preview HTTPS cookie & multi-instance rate limit | NOT VERIFIED / BLOCKED | Requires Vercel Preview deploy (`docs/VERCEL_STAGING_GUIDE.md`) |

---

## 3. Preserved History & Documentation Created

- All 7 prior commits on `main` (`5d029a2`..`0ecd4a3`) remain untouched.
- Documentation set delivered in `docs/`:
  - [`docs/AUTHENTICATION_ARCHITECTURE.md`](AUTHENTICATION_ARCHITECTURE.md)
  - [`docs/AUTHENTICATION_ROOT_CAUSE.md`](AUTHENTICATION_ROOT_CAUSE.md)
  - [`docs/VERCEL_STAGING_GUIDE.md`](VERCEL_STAGING_GUIDE.md)
  - [`docs/SECURITY_AUDIT.md`](SECURITY_AUDIT.md)
  - [`docs/QA_REPORT.md`](QA_REPORT.md)
  - [`docs/FINAL_PRE_PRODUCTION_AUDIT.md`](FINAL_PRE_PRODUCTION_AUDIT.md)
  - [`docs/FINAL_LOGIN_RECOVERY_REPORT.md`](FINAL_LOGIN_RECOVERY_REPORT.md)

