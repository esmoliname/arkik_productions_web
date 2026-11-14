# Arkik Productions — Authentication Root Cause Analysis

**Date:** 2026-11-13  
**Mission:** P0 Critical Authentication Recovery & Production Hardening  
**Scope:** End-to-end administrative PIN authentication flow (`index.html` -> `js/app.js` -> `js/api.js` -> `/api/admin/login` -> `api/_lib/service.js` / `api/_lib/auth.js` -> PostgreSQL `admin_credentials` / `admin_sessions` / `rate_limits` / `audit_log` -> `/api/admin/session` / `/api/admin/dashboard` / `/api/admin/logout`)

---

## Executive Summary

The administrative PIN login fails across real-world local preview, staging, and production configurations because **seven interacting architectural defects** broke the contract between credential seeding (`db/migrate.js`), runtime login (`api/admin/login.js`, `api/_lib/auth.js`, `api/_lib/service.js`), session management (`api/admin/logout.js`, `api/admin/dashboard.js`), and frontend error/input handling (`js/app.js`, `index.html`).

Crucially, there is no single "missing line" — different failure modes occur depending on which environment variables are present, whether `ADMIN_OWNER_PIN` or `ADMIN_IT_PIN` is pre-hashed (`scrypt$...`) or plaintext, whether the PIN contains non-numeric characters, whether PostgreSQL/Neon is reachable, and whether `NODE_ENV=production` is tested over plain HTTP vs HTTPS. Furthermore, the frontend collapses infrastructure/database errors (`503`, `500`, `404`, network `0`) into `"Credenciales inválidas"` while charging client-side brute-force lockout counters, hiding the actual failure from operators and users.

---

## End-to-End Authentication Lifecycle Trace

1. **UI Trigger (`index.html`, `js/app.js`)**:
   - User opens "Acceso Staff" (`AdminModule.open()`), selects role (`owner` or `it`), enters PIN in `#admin-pin`, submits `#admin-login-form` -> `AdminModule.attemptLogin()` -> `SecurityModule.verifyPin(roleId, pin)`.
2. **Backend Login (`api/admin/login.js`, `api/_lib/service.js`, `api/_lib/auth.js`)**:
   - Receives `POST /api/admin/login` with `{ role, pin }`.
   - Authenticates against `admin_credentials` (Neon PostgreSQL) or (previously unconditionally!) env vars.
   - Issues session cookie (`__Host-session` in production, `arkik_session` otherwise).
3. **Session & Protected Data Hydration (`api/admin/session.js`, `api/admin/dashboard.js`, `api/_lib/auth.js`)**:
   - `AdminModule.attemptLogin()` calls `loadProtectedAdminData()` -> `GET /api/admin/dashboard` (or `GET /api/admin/session` on restore).
   - `auth.requireAdmin(req)` parses cookie, accepts either `v1.<payload>.<sig>` stateless token OR SHA-256 HMAC lookup in `admin_sessions`.
4. **Logout (`api/admin/logout.js`, `api/_lib/service.js`)**:
   - `POST /api/admin/logout` revokes DB session and clears cookie.

---

## Confirmed Root Causes

### RC-1: Split-Brain Dual Auth Path & One-Role Lockout (`api/admin/login.js:72-103`, `api/_lib/auth.js:95-120`)
- **Defect**: `api/admin/login.js` checks `if (auth.hasEnvPinsConfigured())` *before* calling `service.login(...)`. `hasEnvPinsConfigured()` returns `true` whenever **either** `ADMIN_OWNER_PIN` or `ADMIN_IT_PIN` (or `ADMIN_PIN_OWNER`/`ADMIN_PIN_IT`) is set.
- **Impact**:
  1. `.env.example` and `DEPLOYMENT_GUIDE.md` instruct operators to set `ADMIN_OWNER_PIN` and `ADMIN_IT_PIN` for `db/migrate.js`. Leaving those env vars set in Vercel causes `api/admin/login.js` to **completely bypass** PostgreSQL `admin_credentials`, `admin_sessions`, `rate_limits`, and `audit_log` — even when `DATABASE_URL` is configured and rotated hashes live in Neon!
  2. If only `ADMIN_OWNER_PIN` is set in env (because IT was rotated in DB), logging in as `it` returns `401` even though `it` exists in `admin_credentials`.
  3. Env-PIN rate limiting relies on an in-memory `Map` (`ENV_ATTEMPTS`), which resets on cold starts and does not coordinate across serverless instances.
  4. In env mode, `auth.verifyEnvPin()` uses SHA-256 comparison for plaintext env vars rather than the `scrypt$` verification contract.

### RC-2: Double-Hashing & Seed Alias Mismatch in Migration (`db/migrate.js:53-80`)
- **Defect**: `bootstrapAdmins()` reads only `ADMIN_OWNER_PIN` and `ADMIN_IT_PIN` (ignoring `ADMIN_PIN_OWNER` / `ADMIN_PIN_IT`) and unconditionally passes the env string to `auth.hashPin(pin)` even when the operator supplied a pre-hashed `scrypt$<salt>$<hash>` string (as explicitly recommended in `docs/SECURITY_AUDIT.md`).
- **Impact**: Pre-hashed env vars are hashed a second time (`hashPin("scrypt$...")`), inserting an unmatchable hash into `admin_credentials` so valid plaintext PIN logins permanently fail against PostgreSQL. Additionally, `db/migrate.js` exits silently with code `0` even if `admin_credentials` ends up completely empty, leaving operators unaware that zero admin accounts were provisioned.

### RC-3: PIN Sanitization Mismatch Across UI, Migration, Env Verify, and DB Verify (`js/app.js:2905-2908`, `api/admin/login.js:23-26`, `api/_lib/auth.js:111`, `db/migrate.js:65`, `index.html:2196`)
- **Defect**:
  - Frontend `SecurityModule.normalizePin()` strips all non-digits (`replace(/\D/g, "")`) and truncates to 12 chars.
  - Backend `api/admin/login.js:sanitizePin()` and `auth.js:verifyEnvPin()` also strip `\D` (`replace(/\D/g, "")`).
  - Meanwhile, `db/migrate.js` trims whitespace *without* stripping non-digits, and `service.login()` verifies the raw `pin` string against `admin_credentials.pin_hash`.
- **Impact**: If an env PIN or DB PIN includes hyphens, letters, or symbols (e.g. a passphrase PIN), or exceeds 8 digits in `#admin-pin` (`maxlength="8"`), the UI silently transforms or truncates what the user typed before sending it to `/api/admin/login`, causing systematic `401` rejections with no user-visible indication that characters were stripped. (Also `#admin-login-form` / `api/admin/login.js:107` falls back to un-sanitized `body.pin` only on one branch, making sanitization inconsistent across paths.)

### RC-4: Infrastructure / Schema / Network Errors Masked as `"Credenciales inválidas"` & False Brute-Force Lockout (`js/app.js:3003-3086`)
- **Defect**: `SecurityModule.verifyPin()` fetches `/api/admin/login` directly and routes **every** non-200 response other than `429` — including `503` (`no_database` / `db_unavailable`), `500`, `404`, and `0` (network/CORS failure) — into `this.registerFailedAttempt(now, { message: "Credenciales inválidas" })`.
- **Impact**:
  1. When Neon is unconfigured (`DATABASE_URL` missing), paused, or unmigrated, or when the static site is served without serverless functions (`404`), the UI falsely tells the user **"Credenciales inválidas"**.
  2. After 3 infrastructure failures, the UI locks the user out locally for 30+ seconds and escalates `lockoutLevel`.
  3. On `api/admin/login.js:79,88`, 429 error text has corrupted UTF-8 mojibake (`'Credenciales invǭlidas'`).

### RC-5: Broken `logout` Under DB Outage & Stateless Token Replay (`api/admin/logout.js:18-22`, `api/_lib/service.js:626-643`)
- **Defect**: `api/admin/logout.js` awaits `service.logout(token)` *before* setting `Set-Cookie: auth.clearSessionCookie()`. Inside `service.logout()`, `repo.deleteSession()` requires a working DB connection and throws `503 db_unavailable` when `DATABASE_URL` is absent or Neon is unreachable.
- **Impact**: Logging out when the DB is unavailable or while using a `v1.` stateless token throws HTTP `503` without emitting `Set-Cookie` to clear the client's cookie. In addition, `v1.` stateless tokens cannot be revoked in `admin_sessions` on logout.

### RC-6: Silent `503` Swallowing & Stats Schema Mismatch in `api/admin/dashboard.js` (`api/admin/dashboard.js:9-66`)
- **Defect**: `dashboard.js` catches `err.status === 503` around `Promise.all([loadConfig(), repo.listBookings(), repo.getStats()])` and silently substitutes `DEFAULT_STATS` whose keys (`totalBookings`, `confirmedCount`, `pendingCount`, ...) do **not** match `repo.getStats()` (`total`, `pendiente`, `confirmada`, ...), and hides genuine DB/migration failures when `DATABASE_URL` is configured.
- **Impact**: In a broken/unmigrated DB deployment, `/api/admin/dashboard` can return fabricated zeroed stats with mismatched keys instead of surfacing `503`, or pass `v1.` token claims even when DB tables are missing.

### RC-7: Missing DB Credential Distinction, Production Cookie HTTP Local-Test Trap, & Duplicate Event Listeners (`api/_lib/service.js`, `api/_lib/auth.js:173-182`, `index.html:2173-2234` + `js/app.js:10210-10222`)
- **Defect**:
  1. If `db/migrate.js` succeeded in creating tables (`001_initial_schema.sql`) without seeding `admin_credentials` (e.g., `ADMIN_OWNER_PIN` unset during migration), `service.login` looks up `findCredentialByRole(role)`, gets `null`, and returns `401 Credenciales inválidas` indistinguishable from a wrong PIN, leaving operators blind unless they inspect SQL.
  2. Setting `NODE_ENV=production` on plain `http://localhost` emits `__Host-session=...; Secure; ...`, which browsers refuse to store/send over HTTP, causing `login 200` followed immediately by `dashboard 401`.
  3. Inline `onclick="AdminModule.setRole(...)"` in `index.html` coexists with `addEventListener('click', ...)` in `js/app.js`, firing role selection handlers twice per click (benign visually, noisy in state resets).

---

## Multi-Agent Architectural Repair Plan

1. **Unify Auth Authority (`api/admin/login.js`, `api/_lib/service.js`, `api/_lib/auth.js`)**:
   - Make PostgreSQL (`service.login` -> `admin_credentials` + `admin_sessions` + distributed `rate_limits` + `audit_log`) the **single authoritative path** whenever `config.databaseUrl` is configured — regardless of whether `ADMIN_OWNER_PIN`/`ADMIN_IT_PIN` are present in environment variables.
   - Allow stateless env-PIN fallback **only** when `!config.databaseUrl && auth.hasEnvPinsConfigured()`. When `!config.databaseUrl && !auth.hasEnvPinsConfigured()`, fail closed with `503 service_unavailable` (`no_database`).
   - Support scrypt-formatted env PINs (`scrypt$...`) cleanly in `verifyEnvPin` as well as `scrypt` verification for plaintext env PINs (avoiding weak SHA-256 fallback).
   - Ensure `service.login` records structured internal diagnostics (`admin_credential_missing` in server logs without leaking PINs/hashes) and still returns standardized HTTP status (`503` when credentials table has zero seeded admins or DB unreachable; `401` generic `"Credenciales inválidas"` when credential exists and PIN mismatches). Wait: returning `503` (`admin_not_initialized`, generic message `"Servicio de autenticación no inicializado"`) when `admin_credentials` is completely empty prevents silent lockout after fresh migrations while preserving anti-enumeration between valid/invalid roles once at least one credential exists! Let's verify security invariants: never leak which role exists vs wrong PIN (`401 Credenciales inválidas`) once initialized, and fail closed (`503`) if zero admin credentials exist in DB.
2. **Fix Credential Seeding & Prevent Double Hashing (`db/migrate.js`)**:
   - Accept both `ADMIN_OWNER_PIN || ADMIN_PIN_OWNER` and `ADMIN_IT_PIN || ADMIN_PIN_IT`.
   - Check `auth.isValidScryptHash(raw)` before calling `auth.hashPin(raw)`: store pre-hashed `scrypt$...` values verbatim (after validating format/salt/keylen), hash plaintext values cleanly with `auth.hashPin(trimmed)`.
   - Never overwrite existing rows (`ON CONFLICT (role) DO NOTHING`), matching the security policy. Log clear operator warning if `admin_credentials` count is `0` after migration.
3. **Standardize PIN Input Handling (`index.html`, `js/app.js`, `api/admin/login.js`, `api/_lib/auth.js`)**:
   - Preserve all non-control characters on `.trim()` (length 1..64) instead of silently stripping `\D` (`replace(/\D/g, '')`), eliminating mismatch between UI input, `migrate.js`, and `service.login` while still supporting `inputmode="numeric"` keypad UX and existing 4–12 digit PINs. Raise `#admin-pin` `maxlength` from `8` to `32` cleanly without altering any CSS classes or DOM structure.
4. **Harden Logout & Dashboard (`api/admin/logout.js`, `api/_lib/service.js`, `api/admin/dashboard.js`)**:
   - Clear the session cookie **unconditionally** (`res.setHeader('Set-Cookie', auth.clearSessionCookie())`) before or regardless of DB session deletion result; handle stateless `v1.` tokens cleanly without throwing `503` when no DB exists.
   - Align `DEFAULT_STATS` in `api/admin/dashboard.js` with `repo.getStats` schema (`total`, `pendiente`, `confirmada`, `realizada`, `cancelada`, `totalRevenue`, `pendingDeposits`), and only fall back to stateless empty/default dashboard data when `!config.databaseUrl` (stateless env-auth mode), NOT when `DATABASE_URL` is configured and broken!
5. **Fix Frontend Error Discrimination & State Integrity (`js/app.js`)**:
   - Update `SecurityModule.verifyPin()` to distinguish:
     - `200`: clear lockout, return verified role.
     - `401` / `403`: increment local failed attempts, show `"Credenciales inválidas"`.
     - `429`: set lockout timer from server `retryAfterMs` WITHOUT falsely double-counting local attempt counter on top of wait, show wait message.
     - `503` / `500` / `404` / `0` (network): do **NOT** register failed attempt, do **NOT** say `"Credenciales inválidas"` — return explicit infrastructure/connectivity error message from backend envelope or actionable status.
   - Update `AdminModule.attemptLogin()` to surface infrastructure/rate-limit/auth errors accurately, clear `#admin-pin` cleanly, load protected dashboard data only after confirmed login, and keep all visual classes/animations intact.
   - Remove redundant inline `onclick` duplication or guard cleanly without touching CSS/DOM visuals.

