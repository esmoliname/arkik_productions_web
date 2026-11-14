# Arkik Productions — Security Audit

**Fecha de auditoría:** 2026-11-13
**Alcance:** Revisión completa tras remediación P0 del sistema de autenticación administrativa, secretos, sesiones, cookies, RBAC, protección anti-abuso, seguridad de API y pruebas automatizadas.

## 1. Alcance

- Archivos inspeccionados: `api/_lib/*.js`, `api/admin/*.js`, `api/bookings/**/*.js`, `api/availability/index.js`, `api/pricing.js`, `api/health.js`, `db/migrate.js`, `db/migrations/*.sql`, `js/app.js`, `js/api.js`, `js/data.js`, `index.html`, `vercel.json`, `.env.example`, `package.json`, `test/*.test.cjs`.
- Entornos considerados: desarrollo local (sin credenciales Neon/Vercel), Vercel Preview/Staging (pendiente de ejecución real), Vercel Production (pendiente de ejecución real).
- No se realizaron pruebas destructivas ni contra servicios externos.

## 2. Controles verificados

- **Secretos y código fuente**: escaneo sobre JS/HTML/CJS (`api/`, `js/`, `db/`, `index.html`) — 0 PINs hardcoded, 0 cadenas `postgres://` reales, 0 hashes reales embebidos.
- **SQL Injection**: todas las consultas en `api/_lib/repo.js` y `db/migrate.js` usan placeholders parametrizados (`$1..$N`).
- **Hashing y comparación**: `scryptSync` (`N=16384, r=8, p=1`, salt aleatorio de 16 bytes, clave de 64 bytes) con validación estricta `isValidScryptHash` y `crypto.timingSafeEqual`.
- **Sesiones y cookies**: tokens de 256 bits aleatorios almacenados únicamente como HMAC-SHA256 (`hashToken`); tokens nunca expuestos en JSON de respuesta; cookies `HttpOnly; SameSite=Strict; Path=/; Max-Age=900` (`__Host-session` + `Secure` en producción).
- **Redacción de logs**: `api/_lib/log.js` redacta claves sensibles (`pin`, `token`, `password`, `secret`, `database_url`, etc.).

## 3. Hallazgos y remediaciones (incluye recuperación P0 de login)

| ID | Archivo | Descripción | Severidad | Evidencia | Corrección | Estado |
|---|---|---|---|---|---|---|
| SA-01..SA-13 | Varios | Hardening previo de cookies, `sessionSecret`, `requireOwner`, eliminación de bucket global por rol, CORS preflight, IP proxy, redacción de logs y cola offline. | HIGH–CRITICAL | Commits `5d029a2`..`bf81bbb` | Implementado en commits previos y preservado. | REMEDIATED |
| SA-14 | `api/admin/login.js`, `api/_lib/auth.js` | **Split-brain auth bypass**: presencia de un env PIN (`ADMIN_OWNER_PIN`/`ADMIN_IT_PIN`) puenteaba `service.login`, PostgreSQL `admin_credentials`, `admin_sessions`, `rate_limits` y `audit_log`, e imposibilitaba login del rol faltante. | CRITICAL | `hasEnvPinsConfigured()` corría antes que `service.login()`. | `service.login()` es autoritativo siempre que `DATABASE_URL` esté configurado; env fallback limitado exclusivamente a entornos sin `DATABASE_URL`; `requireAdmin` rechaza tokens `v1.` cuando `DATABASE_URL` está activo. | REMEDIATED |
| SA-15 | `db/migrate.js` | **Double hashing en seed**: `bootstrapAdmins()` aplicaba `hashPin()` incluso si `ADMIN_OWNER_PIN` / `ADMIN_IT_PIN` ya venía pre-hasheado con `scrypt$...`, rompiendo el login en PostgreSQL. | HIGH | `auth.hashPin(pin)` incondicional; faltaban aliases `ADMIN_PIN_*`. | Validación `auth.isValidScryptHash` para almacenar `scrypt$` sin re-hashear, rechazo explícito de formatos `scrypt$` corruptos y soporte de ambos aliases manteniendo `ON CONFLICT DO NOTHING`. | REMEDIATED |
| SA-16 | `js/app.js`, `api/admin/login.js`, `api/_lib/auth.js`, `index.html` | **Desajuste de sanitización de PIN**: `.replace(/\D/g, '')` y `maxlength="8"` truncaban silenciosamente PINs con caracteres no numéricos o >8 caracteres respecto a `db/migrate.js` y `service.login`. | MEDIUM | Inconsistencia entre normalizadores y hasher. | Estandarizado `.trim()` (sin destruir caracteres válidos) en UI (`SecurityModule.normalizePin`, `maxlength="32"`), `sanitizePin`, `verifyEnvPin` y `service.login`. | REMEDIATED |
| SA-17 | `js/app.js` | **Enmascaramiento de errores 503/5xx/red**: cualquier fallo de infraestructura se reportaba como `"Credenciales inválidas"` y cargaba el contador de bloqueo local. | HIGH | `verifyPin` llamaba `registerFailedAttempt()` ante `503`/`500`/`404`/red. | Discriminación explícita (`infraError: true` en `503`/`5xx`/`404`/`status 0`) sin tocar el contador de intentos ni mostrar `"Credenciales inválidas"`. | REMEDIATED |
| SA-18 | `api/admin/logout.js`, `api/_lib/service.js` | **Cookie huérfana en logout si DB falla**: `logout.js` fallaba con `503` antes de emitir `Set-Cookie: clearSessionCookie()` cuando la DB no respondía o el token era `v1.`. | MEDIUM | `await service.logout(token)` previo a `res.setHeader('Set-Cookie', ...)`. | `clearSessionCookie()` se emite siempre antes de limpiar la sesión en DB; tokens `v1.` se manejan limpiamente y fallos de DB no dejan cookie activa en el navegador. | REMEDIATED |
| SA-19 | `api/admin/dashboard.js`, `api/_lib/service.js` | **Ocultación de DB rota y tablas vacías**: `dashboard.js` tragaba errores `503` devolviendo `DEFAULT_STATS` incompatibles incluso con `DATABASE_URL` activo; `service.login` confundía `admin_credentials` vacía con `401`. | MEDIUM | Fallback en `dashboard.js` y lookup único en `service.login`. | `dashboard.js` solo usa `DEFAULT_STATS` (ya alineado al esquema de `repo.getStats`) cuando `!config.databaseUrl`; `service.login` devuelve `503` explícito si `admin_credentials` tiene 0 filas o hash corrupto (anti-enumeración mantenida cuando existen roles). | REMEDIATED |

## 4. Pruebas de seguridad ejecutadas

- `npm run check` — **PASS** (0 errores de sintaxis).
- `npm test` — **PASS** (7/7 archivos de suite, 14/14 tests en runner principal + sub-checks; incluye `test/auth-recovery.test.cjs` con 20 escenarios + servidor HTTP local/en-memoria + VM `SecurityModule`, y `test/security.test.cjs`).
- `git diff --check` — **PASS** (0 errores de whitespace).
- Escaneo de secretos en árbol de trabajo (`node`) — **PASS** (`SECRET_SCAN_HITS: 0`).
- `npm audit` y `npm audit --omit=dev` — **BLOCKED** en este entorno offline (`ENOTFOUND registry.npmjs.org`).

## 5. Riesgos residuales y controles NO VERIFICADOS

- **Integración Neon PostgreSQL real**: **NOT VERIFIED / BLOCKED** (sin `DATABASE_URL` ni credenciales en este workspace).
- **Cookies `__Host-session; Secure` sobre HTTPS real en Vercel Preview/Production**: **NOT VERIFIED / BLOCKED** (pendiente de deploy del propietario).
- **Rate limiting distribuido multi-instancia bajo concurrencia real**: **NOT VERIFIED / BLOCKED** (probado contra pool simulado único, no en múltiples lambdas Vercel simultáneas).
- **Auditoría npm en línea (`npm audit`)**: **BLOCKED** por falta de acceso de red al registry desde el sandbox.
- **CSRF adicional**: mitigado por `SameSite=Strict`; sin token CSRF explícito separado (riesgo bajo en navegadores modernos, documentado).
- **Política de PIN en env**: recordar usar hashes `scrypt$` al poblar `ADMIN_OWNER_PIN` / `ADMIN_IT_PIN` según `docs/VERCEL_STAGING_GUIDE.md`.
