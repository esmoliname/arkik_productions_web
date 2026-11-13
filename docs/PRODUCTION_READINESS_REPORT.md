# Arkik Productions — Production Readiness Report

**Date:** 2026-11-13
**Branch:** main (working tree)
**Node:** >=22 (engines.node)
**Tests:** `npm test` → 5 suites, 0 failures

## 1. Architecture found

- Frontend: Vanilla JS SPA (`js/app.js` ~14k lines, `js/data.js`, `js/api.js`).
- Backend: Vercel Serverless Functions under `api/` with shared libs in `api/_lib/`
  (`db.js`, `repo.js`, `service.js`, `logic.js`, `auth.js`, `config.js`, `cors.js`,
  `respond.js`, `ratelimit.js`).
- Database: Neon PostgreSQL via `@neondatabase/serverless` (`Pool`, max 1).
- Persistence model: Remote-first. `BookingStore.add()` POSTs to `/api/bookings`;
  server recalculates pricing, validates capacity under an advisory lock and
  persists inside a transaction. `BookingStore.hydrate()` replaces the local
  cache with the authoritative server list for admin sessions.
- Admin auth: scrypt PIN hashes seeded from env, HMAC-hashed sliding sessions,
  HttpOnly `Secure` (prod) cookies, SameSite=Strict, role-based (owner/it).

## 2. Problems identified / addressed

### Security hardening (this pass)

1. `config.sessionSecret` previously fell back to the hard-coded string
   `dev-secret-change-me` even in production. It now throws when
   `ADMIN_SESSION_SECRET` is unset and `isProduction` is true, while keeping the
   dev fallback for local work.
2. Admin session cookies (`sessionCookie` / `clearSessionCookie`) always carried
   `Secure`. In local HTTP development this prevents the cookie from being
   stored, blocking end-to-end testing. `Secure` is now emitted only when
   `config.isProduction` is true.

### Persistence / cross-device

- PostgreSQL remains the single source of truth for bookings. The browser
  never connects to the database directly.
- `idempotency_keys` table + service-layer replay guarantee that a retried
  POST with the same `X-Idempotency-Key` returns the existing booking instead
  of creating a duplicate.
- Capacity is serialized per date with `pg_advisory_xact_lock` inside the
  transaction; concurrent requests cannot exceed `maxEventsPerDay`.
- Admin dashboard hydrates from `/api/admin/bookings` (cookie-gated), so a
  booking created on a phone appears on an admin desktop after refresh/poll.

### Offline / degraded mode

- `BookingStore.add()` keeps an explicit offline queue (`arkik_pending_sync_v1`)
  with idempotency keys for requests that cannot be confirmed by the server.
  Degraded records are marked `syncStatus: "offline_unverified"` and surfaced
  via the offline badge; they are never presented as server-confirmed.

## 3. API contract (summary)

- Public: `POST /api/bookings` (rate limited, idempotent, server pricing).
- Admin: `GET /api/bookings`, `PATCH /api/bookings/:code`, `PATCH .../status`,
  `PATCH .../reschedule`, `GET /api/admin/dashboard`, `GET /api/admin/stats`,
  `GET/PUT /api/admin/pricing`, `GET /api/admin/audit`.
- Availability: `GET /api/availability` (single date or `from`/`to` range),
  `PUT/DELETE /api/availability`.
- System: `GET /api/health`, `GET /api/pricing`.

## 4. Database

- Migrations in `db/migrations/*.sql`, applied idempotently by
  `db/migrate.js` (transactional per file, recorded in `schema_migrations`).
- Never DROP/TRUNCATE. Production starts empty when `SEED_MODE=false`.
- Admin credentials are seeded from `ADMIN_OWNER_PIN` / `ADMIN_IT_PIN` only
  when absent (never rotated on deploy).

## 5. Testing evidence

`npm test` (2026-11-13):

- `npm run check` (syntax): PASS
- `test/api-client.test.cjs`: PASS
- `test/behavior.test.cjs`: 13 checks, 0 failed
- `test/contract.test.cjs`: 30 checks, 0 failed
- `test/load.test.cjs`: 24 checks, 0 failed
- `test/logic.test.cjs`: 30 checks, 0 failed
- Total: 5 suites, 0 failures.

## 6. Vercel deployment

- `vercel.json`: framework null, serverless functions `api/**/*.js`
  maxDuration 30s, security headers, SPA-friendly.
- Required env vars: `DATABASE_URL`, `APP_ENV`, `SEED_MODE=false`,
  `ADMIN_OWNER_PIN`, `ADMIN_IT_PIN`, `ADMIN_SESSION_SECRET`,
  `ALLOWED_ORIGINS`, `PUBLIC_APP_URL`.
- Run `npm run db:migrate` against the target Neon database before promoting.

## 7. Final closure status (independent)

| Area | Status | Evidence |
|---|---|---|
| A. Implementación de código | PASS | Backend remote-first + Neon; seguridad aplicada; offline UX corregida (no success sin servidor). |
| B. Pruebas automatizadas | PASS | `npm test`: 5 suites, 0 fallos (behavior 13, contract 30, load 24, logic 30, api-client). |
| C. Integración real con Neon | BLOCKED | No hay credenciales Neon disponibles en este entorno. Prueba preparada en `test/neon-integration.test.cjs` (pendiente de crear) — ver sección 8. |
| D. Verificación multidispositivo | NOT VERIFIED (simulated) | Escenario diseñado y flujo validado por código; no ejecutado con dos navegadores reales. |
| E. Seguridad | PASS (parcial) | Secret obligatorio en prod, cookies Secure en prod, endpoints admin protegidos (401 sin sesión). Brute-force/roles revisados en código. |
| F. Preparación de Vercel | PASS (config) | `vercel.json` + env vars documentadas; no desplegado (sin autorización). |
| G. Pendientes del propietario | BLOCKED | Credenciales Neon, Vercel env vars, ejecutar migraciones, prueba E2E real. |

## 8. Real Neon integration test (prepared, not executed)

Prerequisitos del propietario:
1. Crear una base Neon de staging (no producción).
2. Exportar `DATABASE_URL` apuntando a staging.
3. Ejecutar `npm run db:migrate` (debe aplicar 001/002/003 y sembrar admins desde env).
4. Ejecutar `npm run db:seed:dev` solo si se desea (staging).

Escenario a ejecutar (script a implementar cuando exista DB):
- `GET /api/health` → `database: true`.
- `POST /api/bookings` con payload válido + `X-Idempotency-Key` → 201 + booking.code.
- Repetir con la misma key → 200 + mismo code (idempotencia).
- `GET /api/bookings?...` con cookie admin → lista incluye el código.
- `PATCH /api/bookings/:code/status` → confirmada; re-leer → estado persistido.
- Concurrencia: 2 POST simultáneos para el mismo día/hora → uno 409 (capacity).
- Reiniciar proceso (nuevo pool) → la reserva sigue presente (persistencia real).

Estado actual: BLOCKED (sin credenciales). No se inventan resultados.

## 9. Offline UX remediation (this pass)

- `BookingStore.add()` (API habilitada) ya NO degrada silenciosamente a éxito local:
  propaga el fallo (`apiFailure`) y el llamador gestiona la cola offline
  (`arkik_pending_sync_v1`) con la misma clave de idempotencia.
- El resultado final del flujo degradado se marca `ok: false, queued: true`,
  de modo que la reserva nunca se presenta como confirmada por el servidor;
  el badge offline y `syncStatus: "offline_unverified"` la identifican como
  pendiente de sincronización.
- Un reintento reutiliza la clave de idempotencia conservada en `sessionStorage`
  (`arkik_idem_v1`), evitando duplicados al sincronizar.

## 10. API contract consistency

- Implementado y utilizado: `GET /api/bookings` (admin, cookie-gated).
- `BookingStore.hydrate()` consume `/api/bookings` vía `ArkikApi.listBookings`.
- El reporte anterior mencionaba `/api/admin/bookings` como alias conceptual;
  el endpoint real es `/api/bookings`. Sin cambios de contrato.

## 11. Deliverables

- docs/ARCHITECTURE.md
- docs/DATABASE.md
- docs/API_REFERENCE.md
- docs/SECURITY_AUDIT.md
- docs/DEPLOYMENT_GUIDE.md
- docs/QA_REPORT.md
- docs/CATALOG_AUDIT.md
- docs/PRODUCTION_READINESS_REPORT.md (this file)
