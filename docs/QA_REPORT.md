# Arkik Productions — QA Report

## Automated Test Suites

`npm test` (2026-11-13): **PASS** — 7 test files, 0 failures.

| Suite | Scope | Status |
|---|---|---|
| `test/api-client.test.cjs` | `ArkikApi` client contract, idempotency headers, 409/429/network error mapping | PASS |
| `test/auth-recovery.test.cjs` | 20-scenario auth recovery suite: Owner/IT `scrypt` login, malformed hash rejection, missing env/DB outage/schema mismatch `5xx`, per-IP+role rate limit (`429`), hashed sessions, sliding expiry, expiration, tampered/`v1.` token rejection, logout & replay block, dev vs prod cookies, Owner vs IT RBAC (`403`), CORS, `db/migrate.js` pre-hashed `scrypt$` seeding, E2E HTTP router, and `js/app.js` `SecurityModule` VM error discrimination | PASS |
| `test/behavior.test.cjs` | 13 checks (HTTP contracts, auth gating, `503` without `DATABASE_URL`) | PASS |
| `test/contract.test.cjs` | 30 checks (availability range validation, public pricing, admin auth gating) | PASS |
| `test/load.test.cjs` | 24 checks (concurrency/load logic harness) | PASS |
| `test/logic.test.cjs` | 30 checks (pricing, capacity, state machine, validation) | PASS |
| `test/security.test.cjs` | 15 checks (auth gating, log redaction, anti-lockout, no global bucket) | PASS |

## Quality Gates & Dependency Inspection

- `npm run check`: **PASS** (`node --check js/app.js && node --check js/data.js && node --check js/api.js`)
- `npm ls --depth=0`: **PASS** (`@neondatabase/serverless@0.10.4`, `serve@14.2.8`)
- `git diff --check`: **PASS** (0 whitespace errors)
- `npm audit` / `npm audit --omit=dev`: **BLOCKED** in offline sandbox (`ENOTFOUND registry.npmjs.org`)

## Real Integration & Staging Checks

- **Live Neon PostgreSQL integration (`npm run db:migrate`, live SQL queries)**: **BLOCKED / NOT VERIFIED** — `DATABASE_URL` and Neon credentials are not present in this environment. Tested locally with controlled in-memory PostgreSQL pool simulation only.
- **Live Vercel Preview HTTPS (`__Host-session; Secure` browser cookies, multi-instance Lambda rate limiting)**: **NOT VERIFIED / BLOCKED** — awaits deployment to Vercel Preview by the repository owner (`docs/VERCEL_STAGING_GUIDE.md`).
- **Loopback TCP socket probe inside restricted sandbox**: Sandbox denied local TCP port connect (`EACCES`); full HTTP handler cycle was verified in-process across the real handler functions (`login`, `session`, `dashboard`, `pricing`, `availability`, `logout`).
