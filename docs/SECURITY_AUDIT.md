# Arkik Productions — Security Audit

**Fecha de auditoría:** 2026-11-13
**Alcance:** Revisión pre-commit del código pendiente, auditoría de secretos, autenticación, protección anti-abuso, seguridad de API, dependencias y documentación.

## 1. Alcance

- Archivos inspeccionados: código JavaScript (frontend y backend), configuración, migraciones, tests, documentación, historial Git.
- Entornos considerados: desarrollo local, Vercel Preview, Vercel Production.
- No se realizaron pruebas destructivas ni contra terceros.

## 2. Archivos inspeccionados

- `api/_lib/config.js`, `api/_lib/auth.js`, `api/_lib/db.js`, `api/_lib/cors.js`, `api/_lib/ratelimit.js`, `api/_lib/service.js`, `api/_lib/respond.js`, `api/_lib/log.js`, `api/_lib/repo.js`
- `api/admin/*.js`, `api/bookings/**/*.js`, `api/availability/index.js`, `api/pricing.js`, `api/health.js`
- `js/app.js`, `js/data.js`, `js/api.js`, `index.html`
- `.env.example`, `.gitignore`, `vercel.json`, `package.json`, `package-lock.json`
- `test/*.test.cjs`, `docs/*`, `README.md`

## 3. Amenazas identificadas

- Fuerza bruta / credential stuffing contra el login administrativo.
- Bloqueo de administrador legítimo por intentos fallidos de terceros (anti-lockout).
- Exposición de secretos en código, historial Git o frontend.
- Spoofing de IP para evadir rate limiting.
- Cross-origin abuse / CORS permisivo.
- Escalada de privilegios (IT realizando operaciones de Owner).
- Simulación de éxito offline en reservas.
- Abuso de endpoints (spam, duplicados, manipulación de precios).
- Vulnerabilidades en dependencias de desarrollo.

## 4. Hallazgos y remediaciones

| ID | Archivo | Descripción | Severidad | Evidencia (no sensible) | Corrección | Estado |
|---|---|---|---|---|---|---|
| SA-01 | `api/_lib/config.js` | `sessionSecret` devolvía fallback en producción si no estaba configurado. | HIGH | Getter sin validación de entorno. | Ahora lanza error en producción si `ADMIN_SESSION_SECRET` no está configurado. | REMEDIATED |
| SA-02 | `api/_lib/auth.js` | Cookie `Secure` siempre activa, rompía desarrollo HTTP. | MEDIUM | Atributo Secure incondicional. | `Secure` condicionado a `isProduction`. | REMEDIATED |
| SA-03 | `api/_lib/auth.js` | Sin verificación de rol Owner para operaciones sensibles. | MEDIUM | `requireAdmin` no distinguía roles. | Añadido `requireOwner`; pricing PUT y availability PUT/DELETE lo usan. | REMEDIATED |
| SA-04 | `api/_lib/service.js` | Lockout por rol tras 3 intentos permitía DoS al administrador. | CRITICAL | `locked_until` por rol en DB. | Eliminado lockout por rol; throttling por IP, IP+rol y global por rol con backoff temporal. | REMEDIATED |
| SA-05 | `api/admin/login.js` | Lockout en memoria con 3 intentos/30s permitía DoS y no se compartía entre instancias. | HIGH | `ENV_ATTEMPTS` Map, 3 intentos. | Umbral a 5, backoff progresivo hasta 15 min, solo por origen. | REMEDIATED (parcial) |
| SA-06 | `api/_lib/respond.js` | `clientIp` confiaba en `X-Forwarded-For` sin validar proxy. | HIGH | Spoofing posible. | Solo confía en `X-Forwarded-For` en Vercel/producción; fallback a socket address. | REMEDIATED |
| SA-07 | `api/_lib/cors.js` | Preflight `OPTIONS` respondía 204 incluso para orígenes no permitidos. | MEDIUM | Sin validación de origin en preflight. | Preflight rechaza orígenes no permitidos con 403 cuando hay allowlist. | REMEDIATED |
| SA-08 | `api/_lib/ratelimit.js` | `enforce` no exponía `retryAfterMs` en el error. | LOW | Sin header Retry-After. | `retryAfterMs` incluido en `extra`; `handleError` y login setean `Retry-After`. | REMEDIATED |
| SA-09 | `js/app.js` | Fallback offline simulaba confirmación de reserva exitosa. | HIGH | `isDegradedOrOffline = true` siempre. | Eliminado fallback que simulaba éxito; ahora propaga fallo. | REMEDIATED |
| SA-10 | `package-lock.json` | 4 vulnerabilidades high en dependencias dev. | LOW | `npm audit` report. | `npm audit fix` aplicado; 0 vulnerabilidades. | REMEDIATED |
| SA-11 | Historial Git | Sin secretos reales encontrados en historial ni archivos actuales. | INFO | `git grep` sobre todos los commits. | N/A — no se requiere acción. | VERIFIED |
| SA-12 | Frontend | Sin secretos privados en HTML/JS entregado al navegador. | INFO | Búsqueda de patrones. | N/A. | VERIFIED |

## 5. Pruebas ejecutadas

- `npm run check` — 0 errores de sintaxis.
- `npm test` — 5/5 suites pasan (api-client, behavior, contract, load, logic).
- `npm audit` — 0 vulnerabilidades.
- `git diff --check` — sin errores de whitespace.
- Búsqueda de secretos en archivos actuales e historial Git — sin hallazgos.

## 6. Riesgos residuales

- CSRF: mitigado por `SameSite=Strict`; no hay token CSRF separado. (NOT VERIFIED en producción con navegadores legacy.)
- Tokens stateless (`v1.`) no son invalidables antes de su expiración (15 min). Un token capturado sigue siendo válido hasta expirar. Recomendación: reducir TTL o implementar lista de revocación si se requiere invalidación inmediata.
- Rate limiting ENV path usa memoria local (no compartida entre instancias serverless). Aceptable como degradación cuando la DB no está disponible. (NOT VERIFIED en multi-instancia.)
- No hay WAF ni protección DDoS a nivel de aplicación; se confía en la plataforma Vercel.
- Procedimiento de rotación de secretos no documentado.
- `ADMIN_OWNER_PIN`/`ADMIN_IT_PIN` pueden almacenarse en texto plano en env (por diseño del propietario). Recomendación: usar hashes scrypt (`scrypt$...`) en env para mayor seguridad.

## 7. Recomendaciones operativas

1. Configurar `ADMIN_SESSION_SECRET` (64+ chars) en Vercel antes de producción.
2. Configurar `SEED_MODE=false` en producción.
3. Usar PINs como hashes scrypt en variables de entorno (`ADMIN_OWNER_PIN=scrypt$...`).
4. Revisar logs de auditoría periódicamente (`/api/admin/audit`).
5. Rotar `ADMIN_SESSION_SECRET` si se sospecha compromiso (invalida todas las sesiones).
6. Mantener `ALLOWED_ORIGINS` vacío (same-origin) salvo necesidad explícita.

## 8. Controles no probados (NOT VERIFIED)

- Pruebas de fuerza bruta en staging (Test D) — no ejecutadas contra entorno real.
- Rate limiting distribuido multi-instancia (Test E) — no verificado.
- Pruebas de carga moderadas (Test I) — no ejecutadas.
- Verificación de cookies en producción HTTPS — no verificada en este entorno.
