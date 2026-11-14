# Arkik Productions — Reporte Final de Seguridad Administrativa & RBAC (P0.2)

> Consolida la auditoría completa de endpoints de escritura, cookies, rate limiting, CORS, validación de entrada y logs (véase [SECURITY_AUDIT.md](./SECURITY_AUDIT.md)).

## 1. Matriz Completa RBAC en Servidor (Task 4)

| Operación / Endpoint | Método | Anónimo | Rol `it` | Rol `owner` | Mecanismo Servidor |
|---|---|---|---|---|---|
| Salud pública `/api/health` | `GET` | `200 / 503` | `200 / 503` | `200 / 503` | Sin secretos |
| Precios públicos `/api/pricing` | `GET` | `200` | `200` | `200` | Solo lectura |
| Disponibilidad `/api/availability` | `GET` | `200` | `200` | `200` | Solo lectura |
| Crear reserva `/api/bookings` | `POST` | `201 / 200` | `201 / 200` | `201 / 200` | Rate limit + idempotencia + cálculo CRC en servidor |
| Autenticación `/api/admin/login`, `/logout` | `POST` | `200/401/429` | `200/401/429` | `200/401/429` | `scrypt` + cookie `HttpOnly` + lockout |
| Lectura Admin (`session`, `dashboard`, `stats`, `audit`, `pricing`, `bookings`, `bookings/[code]`) | `GET` | **`401`** | `200` | `200` | `auth.requireAdmin` |
| Bloquear/liberar fecha `/api/availability` | `PUT`, `DELETE` | **`401`** | **`403`** | `200` | `auth.requireOwner` |
| Modificar tarifas `/api/admin/pricing` | `PUT` | **`401`** | **`403`** | `200` | `auth.requireOwner` |
| Editar contacto reserva `/api/bookings/[code]` | `PATCH` | **`401`** | **`403`** | `200` | `auth.requireOwner` |
| Cambiar estado / cancelar `/api/bookings/[code]/status` | `PATCH` | **`401`** | **`403`** | `200` | `auth.requireOwner` |
| Reprogramar fecha `/api/bookings/[code]/reschedule` | `PATCH` | **`401`** | **`403`** | `200` | `auth.requireOwner` |
| Eliminación física de reservas o rotación PIN HTTP | N/A | Inexistente | Inexistente | Solo CLI | Eliminación prohibida; rotación solo vía `db/manage-admin-pins.js rotate --confirm` |

Verificado automáticamente para todos los endpoints de escritura en Escenario 27 de [auth-recovery.test.cjs](../test/auth-recovery.test.cjs).

## 2. Pruebas de Sesión, Cookies y Controles Criptográficos (Task 5)

| Control | Estado | Evidencia Observada |
|---|---|---|
| Cookie `__Host-session` + `Secure` en `VERCEL_ENV=preview` / `production` | **PASS** | Escenario 28: `Set-Cookie: __Host-session=...; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=900`. |
| Cookie `arkik_session` en HTTP local dev + limpieza `Max-Age=0` en logout | **PASS** | Probe TCP live `http://127.0.0.1:3456` + Escenario 30. |
| Rechazo de tokens `v1.` cuando `DATABASE_URL` está configurada | **PASS** | `api/_lib/auth.js` (`requireAdmin`), verificado en Escenarios 11–15. |
| Sesiones revocadas tras logout o rotación | **PASS** | Escenarios 11–15 (post-logout replay `401`) y Escenario 21 (`DELETE FROM admin_sessions WHERE role`). |
| Rate limiting compartido en `rate_limits` entre instancias independientes | **PASS (simulado)** / **NOT VERIFIED (live multi-instancia)** | Simulado entre dos cargas independientes de `ratelimit.js` compartiendo estado `rate_limits` (Escenario 28); pendiente prueba live en múltiples lambdas Vercel + Neon. |
| CORS estricto (`ALLOWED_ORIGINS`) y preflight `OPTIONS` | **PASS** | Escenarios 16–18 (`403` origen no permitido, `204` origen permitido). |
| Ausencia de secretos en logs y bundle cliente | **PASS** | Escaneo en repo sin coincidencias + `test/security.test.cjs` (15/15 PASS) + `predeploy:check`. |
| `npm audit` y `npm audit --omit=dev` | **BLOCKED** | Sin acceso a `registry.npmjs.org` (`ENOTFOUND`) en el sandbox. |
