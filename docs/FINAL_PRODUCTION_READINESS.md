# Arkik Productions — Evaluación Final de Preparación para Producción (P0.2)

**Estado:** CÓDIGO Y AUTOMATIZACIÓN LISTOS Y VALIDADOS EN LOCAL; **PENDIENTE DE EJECUCIÓN EN VIVO CONTRA NEON STAGING Y VERCEL PREVIEW**.

## Matriz Consolidada de Resultados (`PASS | FAIL | BLOCKED | NOT VERIFIED`)

| Categoría / Control | Estado | Comando / Evidencia Real |
|---|---|---|
| `npm run check` | **PASS** | Verificación sintáctica JS/CLI sin errores (`exit 0`). |
| `npm test` | **PASS** | `tests 24, pass 24, fail 0, skipped 0` across all test files (`api-client`, `auth-recovery` escenarios 1–30, `contract` 30 checks, `load` 24 checks, `logic` 30 checks, `security` 15 checks). |
| `npm run predeploy:check` | **PASS** | Sintaxis + Tests + invariantes RBAC/secretos + 3 migraciones SQL (`exit 0`). |
| `npm run dev` HTTP Loopback Real (`127.0.0.1:3456`) | **PASS** | `GET /` `200 text/html`, `/api/health` `200`, `POST /api/admin/login` `401`/`200 application/json`, cookie conservada en `/api/admin/dashboard`, `PUT /api/admin/pricing` IT `403`, `/api/admin/logout` `200` `Max-Age=0`, `/api/unknown` `404 JSON`, `/.env.example` `404`. |
| `db/manage-admin-pins.js` (`hash` stdin, rechazo `--pin` sin DB, rollback) | **PASS** | Stdin Pipe PowerShell `hash` -> `scrypt$...`; `--pin` rechazado antes de DB; rollback verificado en Escenario 26. |
| RBAC completo endpoints de escritura | **PASS** | Escenario 27: anónimo `401`, IT `403`, Owner `200` en pricing, availability y bookings `PATCH`. |
| Flujo de Negocio Reservas (con DB mock SQL) | **PASS** | Escenario 29: creación `201`, idempotencia `200`, dashboard, `confirmada`, lectura en 2da sesión, `cancelada` y `audit_log`. |
| `npm ls --depth=0` y `git diff --check` | **PASS** | Dependencias íntegras (`@neondatabase/serverless@0.10.4`, `serve@14.2.8`); diff limpio (`exit 0`) y 7 commits previos preservados. |
| `npm audit` y `npm audit --omit=dev` | **BLOCKED** | `getaddrinfo ENOTFOUND registry.npmjs.org` (entorno sin salida a internet). |
| Neon Staging (conexión real, `db:migrate`, `admin:verify`, concurrencia) | **BLOCKED** | Sin `DATABASE_URL` de staging ni salida de red en este workspace. |
| Vercel Preview HTTPS (cookies `__Host-session` live, rate limit multi-instancia, reservas entre dispositivos reales) | **NOT VERIFIED** | Sin credenciales/CLI Vercel ni despliegue Preview ejecutado desde este sandbox. |

## Instrucciones Exactas para el Propietario (Cerrar Bloques Pendientes)

1. **Preparar Neon Staging** (rama/proyecto separado de producción en Neon Console) y copiar su `DATABASE_URL`.
2. **Validar dependencias y DB desde tu máquina con internet**:
   ```bash
   npm audit --omit=dev
   # Exportar en tu shell (o .env.local, nunca en git) DATABASE_URL=<STAGING_URL>, ADMIN_SESSION_SECRET, ADMIN_OWNER_PIN, ADMIN_IT_PIN
   npm run db:migrate
   npm run admin:verify
   # Si admin:verify reporta MISMATCH o CORRUPTED_HASH:
   npm run admin:rotate -- --role owner --confirm --from-env ADMIN_OWNER_PIN --reason "staging-sync"
   npm run admin:rotate -- --role it --confirm --from-env ADMIN_IT_PIN --reason "staging-sync"
   ```
3. **Configurar Vercel Preview (NO Production aún)** con `DATABASE_URL` (staging), `ADMIN_SESSION_SECRET`, `ADMIN_OWNER_PIN`, `ADMIN_IT_PIN` y `ALLOWED_ORIGINS` vacío (same-origin).
4. **Verificar en la URL Preview HTTPS**: login Owner e IT (verificando cabecera `Set-Cookie: __Host-session=...; HttpOnly; Secure`), creación/confirmación/cancelación de reserva desde dos dispositivos, y límite `429` ante 6+ intentos fallidos antes de promover a Production.
