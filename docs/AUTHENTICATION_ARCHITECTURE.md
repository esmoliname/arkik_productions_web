# Arkik Productions — Authentication Architecture

**Version:** 2.0 (Post-P0 Login Recovery)  
**Primary Authority:** PostgreSQL (Neon) vía `DATABASE_URL` (endpoint Pooled `-pooler`, rol runtime mínimo `arkik_app`) cuando `DATABASE_URL` está configurada
**Direct CLI Boundary:** `db/migrate.js` opera exclusivamente con `DIRECT_DATABASE_URL` (`arkik_migrator`) y `db/manage-admin-pins.js` con `DIRECT_ADMIN_DATABASE_URL` (`arkik_admin`) en local/CI (ninguna se configura en Vercel; sin fallback cruzado)
**Fallback Mode:** Stateless HMAC-signed env-PIN mode *strictly* when `config.isExplicitLocalDev` holds (`!DATABASE_URL`, explicit `APP_ENV=development`, zero cloud/production flags, and `ADMIN_OWNER_PIN` / `ADMIN_IT_PIN` configured)

---

## 1. End-to-End Flow

```text
Browser (#admin-pin + role tab)
  │
  ├─► SecurityModule.normalizePin(pin) ──► trim().slice(0, 64) [preserves non-digit chars]
  │
  ▼ POST /api/admin/login (credentials: 'same-origin')
api/admin/login.js
  ├─► config.databaseUrl present? ──YES──► service.login() [AUTHORITATIVE DB PATH]
  │                                          ├─ ratelimit.enforce (ip & ip:role)
  │                                          ├─ repo.getCredentialForUpdate(role)
  │                                          ├─ empty admin_credentials? ──► 503 service_unavailable
  │                                          ├─ auth.isValidScryptHash + auth.verifyPin (scrypt + timingSafeEqual)
  │                                          ├─ repo.createSession(HMAC-SHA256(token), role, expiresAt)
  │                                          ├─ repo.insertAudit(ADMIN_LOGIN / ADMIN_LOGIN_FAILED)
  │                                          └─ Set-Cookie (HttpOnly; SameSite=Strict; Path=/; Max-Age=900 [+ __Host- & Secure en Prod/Cloud/Preview HTTPS])
  │
  └─► config.isExplicitLocalDev && hasEnvPinsConfigured()? ──YES──► Stateless env fallback (explicit local APP_ENV=development only)
                                                       └─ Otherwise (Cloud/Preview/Staging/Prod/Implicit without DB)? ──► 503 service_unavailable
```

---

## 2. Cryptographic & Session Model

- **PIN Hashing (`api/_lib/auth.js`)**:
  - Algorithm: `crypto.scryptSync` (`N=16384`, `r=8`, `p=1`, `keylen=64`, `saltBytes=16`).
  - Format: `scrypt$16384$8$1$<salt_hex>$<hash_hex>`.
  - Strict validation via `isValidScryptHash()` before verification and during migration bootstrap (`db/migrate.js`) so pre-hashed `scrypt$` values are stored directly without double-hashing.
  - Comparison uses `crypto.timingSafeEqual`.
- **Session Tokens (`admin_sessions` + `api/_lib/auth.js`)**:
  - Random 32-byte URL-safe token (`newSessionToken()`).
  - Never stored in plaintext in PostgreSQL; hashed with HMAC-SHA256 (`ADMIN_SESSION_SECRET`) before `INSERT`/`SELECT`/`DELETE`.
  - Never returned in HTTP JSON bodies (`{ role, expiresAt }` only).
  - `requireAdmin(req)` rejects `v1.` stateless tokens whenever `!config.isExplicitLocalDev` (any `DATABASE_URL`, Cloud/Preview, Staging, Production, or unset `APP_ENV`), preventing unrevocable token replay.
  - Sliding window: `SESSION_TTL_MS = 900000` (15 minutes), refreshed via `repo.touchSession` when `now - last_seen_at > 60000` and re-emitted via `Set-Cookie` when `requireAdmin(req, res)` refreshes the window.
- **Cookie Security**:
  - Production or Cloud/Preview (`config.isProduction || config.isCloud`, including `VERCEL=1` and `VERCEL_ENV=preview`): `__Host-session=<token>; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=900`. Note: `__Host-` + `Secure` requires HTTPS, and `ADMIN_SESSION_SECRET` is mandatory (`503` if missing).
  - Local HTTP / Non-production (e.g. `APP_ENV=staging` with `NODE_ENV=development` on `http://localhost`): `arkik_session=<token>; HttpOnly; SameSite=Strict; Path=/; Max-Age=900`.
- **Logout (`api/admin/logout.js`, `api/_lib/service.js`)**:
  - Always emits `Set-Cookie: clearSessionCookie()` (`Max-Age=0`), even if PostgreSQL is temporarily unreachable or the token is a `v1.` stateless token, and deletes the DB row + records `ADMIN_LOGOUT` when DB is active.

---

## 3. Role-Based Access Control (RBAC)

- **Roles**: `owner` (Propietario) and `it` (Ingeniero TI).
- `auth.requireAdmin(req, res)`: Permits `owner` and `it` (`GET /api/admin/session`, `GET /api/admin/dashboard`, `GET /api/admin/stats`, `GET /api/admin/audit`, `GET /api/admin/pricing`, `GET /api/bookings`, `GET /api/bookings/[code]`).
- `auth.requireOwner(req, res)`: Requires `session.role === 'owner'`; returns `403 forbidden` to `it` (`PUT /api/admin/pricing`, `PUT /api/availability`, `DELETE /api/availability`, `PATCH /api/bookings/[code]`, `PATCH /api/bookings/[code]/status`, `PATCH /api/bookings/[code]/reschedule`).

---

## 4. Rate Limiting & Anti-Lockout Architecture

- Distributed fixed-window PostgreSQL UPSERT in `rate_limits`:
  - `login:<ip>`: max 10 requests / 1 hour.
  - `login:<ip>:<role>`: max 5 requests / 15 minutes.
- **No global per-role lockout**: a third party guessing wrong PINs for `owner` from one IP cannot lock out the legitimate owner logging in from another IP.
- `429` responses include `Retry-After` (seconds) and JSON `error.retryAfterMs` (ms).

---

## 5. Frontend Error Discrimination (`js/app.js`)

- `SecurityModule.verifyPin` and `AdminModule.attemptLogin` differentiate:
  - `200 OK`: clears lockout state, closes login modal, calls `loadProtectedAdminData(role)`.
  - `401 / 403`: increments client attempt state and shows generic `"Credenciales inválidas"`.
  - `429`: starts UI lockout countdown using server `retryAfterMs`.
  - `503 / 500 / 404 / status 0`: surfaces an explicit operational diagnostic (`infraError: true`) **without** blaming the user's PIN and **without** incrementing failed-attempt counters.

