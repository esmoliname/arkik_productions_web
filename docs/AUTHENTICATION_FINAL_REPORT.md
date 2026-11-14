# Arkik Productions — Reporte Final de Recuperación de Autenticación (P0.2)

> Consolida las causas raíz halladas, las correcciones en código y las validaciones reales ejecutadas sobre `scripts/dev-server.js`, `api/_lib/auth.js`, `api/admin/*`, `db/manage-admin-pins.js` y `js/app.js` (véase también [AUTHENTICATION_ROOT_CAUSE.md](./AUTHENTICATION_ROOT_CAUSE.md)).

## 1. Causas Raíz Corregidas (P0 + P0.2)

1. **Mutación de PIN alfanumérico (`\D` stripping)** (`api/_lib/auth.js`, `js/app.js`): normalizado con `.trim()`, soporte `1..64` chars (`maxlength="32"` en `#admin-pin`).
2. **Split-Brain DB vs Env PINs** (`api/admin/login.js`): `service.login` y PostgreSQL (`admin_credentials`, `admin_sessions`, `rate_limits`) son autoritativos siempre que `DATABASE_URL` está configurada.
3. **Doble Hashing en `db/migrate.js`**: `bootstrapAdmins` valida formato `scrypt$` mediante `auth.isValidScryptHash` sin re-hashear valores pre-hasheados.
4. **Tokens alternativos `v1.` rechazados con DB activa** (`api/_lib/auth.js`): `requireAdmin` rechaza tokens stateless `v1.` si `config.databaseUrl` existe.
5. **Secuestro HTML en desarrollo local (`serve -s .`)**: reemplazado `npm run dev` por [dev-server.js](../scripts/dev-server.js) y agregada detección explícita `static_server_html` en `SecurityModule.verifyPin` (`js/app.js`) sin consumir intentos fallidos.
6. **Lock-in silencioso en `admin_credentials`**: `db/migrate.js` ahora advierte `CORRUPTED_HASH`/`MISMATCH` sin sobrescribir automáticamente; [manage-admin-pins.js](../db/manage-admin-pins.js) permite `verify`, `hash` y `rotate --confirm` auditado. Además se corrigió la orden de validación CLI para rechazar `--pin` por `argv`, rol inválido o falta de `--confirm` **antes** de abrir pool DB, y lectura tolerante de `stdin` en Windows.
7. **UX de Login y Lockout en `#adminLoginModal`** (`js/app.js`, `index.html`): el modal solo se cierra tras `GET /api/admin/dashboard` `200`, restaura cuenta regresiva en `AdminModule.open()`, hidrata `auditEvents` en Tab 04 y protege `#login-website-trap` contra autofill (`data-lpignore`, `data-1p-ignore`, `data-bwignore`).
8. **Cookies `__Host-session` en Preview/Producción** (`api/_lib/auth.js`): `isSecureCookieContext()` activa `__Host-session` con `HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=900` cuando `isProduction`, `VERCEL=1` o `VERCEL_ENV=preview`, y `arkik_session` en HTTP local.
9. **Falta de `ADMIN_SESSION_SECRET` en producción** (`api/_lib/config.js`): devuelve HTTP `503 service_unavailable` controlado.

## 2. Validación Operativa Ejecutada (`npm run dev` en TCP Loopback Live + Suite P0.2)

Prueba real contra `node scripts/dev-server.js` en `http://127.0.0.1:3456` (credenciales efímeras de prueba en memoria, eliminadas al terminar):
- `GET /` -> `200 text/html; charset=utf-8` (`PASS`)
- `GET /api/health` -> `200 application/json` (`PASS`)
- `POST /api/admin/login` (PIN inválido) -> `401 application/json; charset=utf-8` (`PASS`)
- `POST /api/admin/login` (Owner válido) -> `200 application/json`, `Set-Cookie: arkik_session=...; HttpOnly; SameSite=Strict; Path=/; Max-Age=900` (`PASS`)
- `GET /api/admin/dashboard` (con cookie Owner) -> `200 application/json`, `data.role === "owner"` (`PASS`)
- `POST /api/admin/login` (IT válido) + `GET /api/admin/dashboard` -> `200 application/json`, `data.role === "it"` (`PASS`)
- `PUT /api/admin/pricing` (con cookie IT) -> `403` (`PASS`)
- `POST /api/admin/logout` (con cookie Owner) -> `200`, `Set-Cookie` incluye `Max-Age=0` (`PASS`)
- `POST /api/does-not-exist` -> `404 application/json` (nunca HTML SPA) (`PASS`)
- `GET /.env.example` -> `404` bloqueado (`PASS`)

Escenarios adicionales verificados en [auth-recovery.test.cjs](../test/auth-recovery.test.cjs) (escenarios 1–30): `tests 24, pass 24, fail 0, skipped 0`:
- Infraestructura degradada (`503` sin DB, `ECONNREFUSED`, `42P01`, falta de `ADMIN_SESSION_SECRET`) -> **PASS**.
- Bloqueo por fuerza bruta (`429 Retry-After`), expiración deslizante, logout y rechazo post-logout -> **PASS**.
- Emisión `__Host-session; HttpOnly; Secure; SameSite=Strict; Path=/` en `VERCEL_ENV=preview` / `NODE_ENV=production` -> **PASS**.

## 3. Controles Pendientes de Entorno Externo

- Login real contra instancia PostgreSQL **Neon Staging** (`DATABASE_URL` real) y **Vercel Preview HTTPS** en dominio externo: **BLOCKED / NOT VERIFIED** (sin `DATABASE_URL` ni credenciales Vercel en este workspace).
