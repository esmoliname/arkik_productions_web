# Arkik Productions — Final Pre-Production Audit

**Fecha:** 2026-11-13
**Rama:** main (6 commits ahead of origin/main)
**Node:** >=22 (engines.node)
**Auditor:** Principal Security Architect (AI-assisted)

---

## FASE 1 — Auditoría del estado Git

| Control | Estado | Evidencia |
|---|---|---|
| Working tree limpio | PASS | `git status --short` → sin salida |
| 6 commits intactos | PASS | `git log -6 --oneline` lista los 6 commits |
| Sin cambios sin registrar | PASS | `git status --short` vacío |
| `git diff --check` | PASS | Sin errores de whitespace (solo warnings LF/CRLF) |
| Rama actual | PASS | `main` |
| Relación con remoto | INFO | `origin/main: ahead 6` — cambios locales no publicados (push no realizado) |
| Integridad de commits | PASS | Cada commit tiene mensaje descriptivo y cambios coherentes |
| Archivos inesperados | PASS | No se detectaron archivos .env, secretos ni node_modules staged |

**Riesgo residual:** Ninguno. Los cambios están listos para push cuando el propietario lo autorice.

---

## FASE 2 — Validación de autenticación

| Control | Estado | Evidencia |
|---|---|---|
| PIN validado en servidor | PASS | `service.login` y `verifyEnvPin` solo server-side; frontend no contiene PIN |
| Hash scrypt con salt único | PASS | `hashPin` usa `crypto.randomBytes(16)` salt; `verifyPin` compara con `timingSafeEqual` |
| Validación timing-safe | PASS | `crypto.timingSafeEqual` en `verifyPin` y `verifyEnvPin` |
| Roles Owner/IT separados | PASS | `requireAdmin` retorna role; `requireOwner` rechaza non-owner (403) |
| Cookies HttpOnly | PASS | `sessionCookie` incluye `HttpOnly` |
| Cookie Secure en producción | PASS | `secure = config.isProduction ? ' Secure;' : ''` |
| SameSite=Strict | PASS | Cookie incluye `SameSite=Strict` |
| Expiración deslizante 15 min | PASS | `SESSION_TTL_MS = 15*60*1000`, touch cada 60s |
| Logout y revocación DB-backed | PASS | `logout` llama `repo.deleteSession`; fila eliminada |
| Sesiones stateless (`v1.`) | PASS (limitado) | Firmadas con HMAC-SHA256, exp verificada. No revocables antes de expiración (documentado) |
| Tokens expirados rechazados | PASS | `verifyStatelessToken` verifica `exp <= Date.now()` |
| Tokens alterados rechazados | PASS | `timingSafeEqual` de firma HMAC |
| Credenciales no en logs | PASS | `SENSITIVE_KEY` regex redacta pin/token/password/secret/etc. Test G3-G7 PASS |
| Credenciales no en respuestas | PASS | Login retorna solo `{role, expiresAt}`. Test G1 PASS |
| Rutas sensibles sin auth → 401 | PASS | behavior.test.cjs: 13 checks PASS |

**Riesgo residual:** Sesiones stateless no revocables (documentado). Migración a `session_version` recomendada.

---

## FASE 3 — Validación de rate limiting

| Control | Estado | Evidencia |
|---|---|---|
| Bucket `login:{ip}` (10/h) | PASS (código) | `service.login` llama `ratelimit.enforce` |
| Bucket `login:{ip}:{role}` (5/15min) | PASS (código) | Presente en `service.login` |
| Sin bucket global por rol | PASS | Test A1 verifica ausencia de `login:role:` en service.js |
| Backoff progresivo | PASS (código) | `LOCK_BASE_MS * 2^level` (DB path eliminado lockout); ENV path backoff hasta 15 min |
| Cabecera Retry-After | PASS | `handleError` y login handler setean `Retry-After` |
| UPSERT atómico en PostgreSQL | PASS (código) | `hitRateLimit` usa `INSERT ... ON CONFLICT` |
| Expiración de ventanas | PASS (código) | `window_start <= $3 (now - windowMs)` resetea ventana |
| ENV fallback sin DB | PASS (código) | `login.js` ENV path con Map en memoria |
| Límites compartidos entre instancias | NOT VERIFIED | Requiere 2+ instancias serverless + misma DB. No ejecutado. |
| Prueba concurrente multi-instancia | NOT VERIFIED | Sin infraestructura disponible. |
| Atacante no bloquea a todos los admins | PASS (código) | Sin bucket global por rol (A1). |
| NAT no causa bloqueos desproporcionados | PASS (diseño) | Bucket por IP+rol, no solo IP. |

**Riesgo residual:** Rate limiting distribuido no verificado con instancias independientes (BLOCKED por falta de infraestructura).

---

## FASE 4 — Validación de reservas

| Control | Estado | Evidencia |
|---|---|---|
| Cálculo de precios en servidor | PASS | `logic.computePricing` en `createBooking`; `clientGrandTotal` verificado |
| Control de capacidad | PASS | `assertCapacity` verifica maxEventsPerDay y buffer |
| Transacciones PostgreSQL | PASS (código) | `withTransaction` con BEGIN/COMMIT/ROLLBACK |
| Advisory locks | PASS (código) | `pg_advisory_xact_lock` por fecha |
| Idempotencia | PASS (código + test) | `getIdempotencyBooking` + replay; api-client test PASS |
| Persistencia centralizada | PASS (diseño) | Neon es fuente de verdad; hydrate desde `/api/bookings` |
| Reintentos offline | PASS (código) | Cola `arkik_pending_sync_v1` con idempotency key |
| Sin confirmaciones falsas | PASS | Fallback offline eliminado; `ok: false, queued: true` |
| Protección contra duplicados | PASS (código) | `codeExists` check + advisory lock |
| Manipulación de precios rechazada | PASS (código) | `price_mismatch` → 400 |
| Fallo de Neon → no confirmación | PASS (código) | `handleError` → 503 `service_unavailable` |

**Riesgo residual:** Integración real con Neon no verificada (BLOCKED por falta de credenciales).

---

## FASE 5 — Pruebas de integración y carga

| Prueba | Estado | Evidencia |
|---|---|---|
| Solicitudes concurrentes | NOT VERIFIED | Requiere DB real |
| Login válido/inválido | PASS (local, sin DB) | behavior.test.cjs + security.test.cjs |
| Rate limiting | PASS (código) | security.test.cjs B1-B2 |
| Expiración de sesiones | PASS (código) | `verifyStatelessToken` + `getSession` |
| Logout | PASS (código) | `logout` + `deleteSession` |
| Roles y permisos | PASS (local) | security.test.cjs F1-F3 |
| Creación de reservas | PASS (local, sin DB) | api-client.test.cjs + logic.test.cjs |
| Idempotencia | PASS (local) | api-client.test.cjs |
| Errores de base de datos | PASS (local) | behavior.test.cjs (503) |
| Cookies bajo HTTPS | NOT VERIFIED | Requiere entorno HTTPS real |
| Pruebas de carga | NOT VERIFIED | No ejecutadas (restricción: no ataques) |

---

## FASE 6 — Configuración Vercel + Neon

| Variable | Estado | Notas |
|---|---|---|
| `DATABASE_URL` | NOT VERIFIED | No disponible en este entorno. Requerida en producción. |
| `ADMIN_OWNER_PIN` | NOT VERIFIED | No configurada. Requerida. Recomendación: hash scrypt. |
| `ADMIN_IT_PIN` | NOT VERIFIED | No configurada. Requerida. |
| `ADMIN_SESSION_SECRET` | NOT VERIFIED | No configurada. Obligatoria en producción (getter lanza si falta). |
| `ALLOWED_ORIGINS` | NOT VERIFIED | Recomendado vacío (same-origin). |
| `PUBLIC_APP_URL` | NOT VERIFIED | Requerida para links/emails. |
| `APP_ENV` | NOT VERIFIED | Debe ser `production` en prod. |
| `SEED_MODE` | NOT VERIFIED | Debe ser `false` en prod. |

| Control | Estado | Evidencia |
|---|---|---|
| Migraciones | NOT VERIFIED | No ejecutadas (sin DB). `db/migrate.js` disponible. |
| Índices | NOT VERIFIED | `002_indexes.sql` existe. |
| Restricciones de esquema | NOT VERIFIED | Requiere DB real. |
| Compatibilidad | PASS (código) | Migraciones idempotentes (`ON CONFLICT`). |

**Riesgo residual:** Configuración de producción no verificada (BLOCKED por falta de credenciales/autorización).

---

## FASE 7 — Seguridad adicional

| Control | Estado | Evidencia |
|---|---|---|
| CORS | PASS (código) | Same-origin por defecto; allowlist explícita; preflight restringido |
| CSRF | PASS (diseño) | SameSite=Strict mitiga; sin token CSRF separado (documentado) |
| XSS | PASS (código) | `sanitizeInput` en frontend; sin `innerHTML` sin sanitizar en paths críticos |
| SQL Injection | PASS (código) | SQL parametrizado en `repo.js`; sin interpolación de input de usuario |
| Validación de entradas | PASS (código) | `logic.js` valida payloads, filtros, rangos |
| Cabeceras HTTP | PASS (config) | `vercel.json`: nosniff, frame deny, referrer, permissions-policy |
| Exposición de errores internos | PASS (código) | `handleError` retorna mensaje genérico; logs redactan |
| Dependencias | PASS | `npm audit` + `npm audit --omit=dev`: 0 vulnerabilidades |
| Secretos en frontend/bundles | PASS | Búsqueda de patrones: sin hallazgos |
| Logs sensibles | PASS | `SENSITIVE_KEY` regex + `redactString` |
| Endpoints públicos | PASS (código) | Rate limited (create), validación server-side |

---

## FASE 8 — Pruebas finales

| Comando | Estado | Resultado |
|---|---|---|
| `npm run check` | PASS | 0 errores de sintaxis |
| `npm test` | PASS | 6/6 suites, 0 fallos |
| `npm audit` | PASS | 0 vulnerabilidades |
| `npm audit --omit=dev` | PASS | 0 vulnerabilidades |
| `npm ls --depth=0` | PASS | @neondatabase/serverless@0.10.4, serve@14.2.8 |
| `git diff --check` | PASS | Sin errores de whitespace |

---

## Matriz de riesgos priorizada

| Prioridad | Riesgo | Severidad | Estado | Acción |
|---|---|---|---|---|
| 1 | Integración real con Neon no verificada | HIGH | BLOCKED | Propietario: crear DB staging, ejecutar migraciones, correr tests |
| 2 | Rate limiting distribuido no verificado multi-instancia | MEDIUM | NOT VERIFIED | Propietario: probar con 2 instancias + misma DB |
| 3 | Sesiones stateless no revocables | MEDIUM | NOT VERIFIED | Implementar `session_version` (futuro) |
| 4 | Configuración de producción no verificada | HIGH | BLOCKED | Propietario: configurar env vars en Vercel |
| 5 | PINs en texto plano en env | LOW | NOT VERIFIED | Propietario: usar hashes scrypt |
| 6 | Cookies HTTPS no verificadas | LOW | NOT VERIFIED | Verificar en deploy preview |
| 7 | Pruebas de carga no ejecutadas | LOW | NOT VERIFIED | Ejecutar en staging |

---

## Acciones que requieren intervención del propietario

1. Crear base de datos Neon de staging.
2. Configurar variables de entorno en Vercel (DATABASE_URL, ADMIN_OWNER_PIN, ADMIN_IT_PIN, ADMIN_SESSION_SECRET, APP_ENV, SEED_MODE=false, ALLOWED_ORIGINS, PUBLIC_APP_URL).
3. Ejecutar `npm run db:migrate` contra la base de staging.
4. Ejecutar pruebas de integración con DB real.
5. Verificar cookies bajo HTTPS en Vercel Preview.
6. Probar rate limiting con múltiples instancias serverless.
7. Autorizar push y deploy cuando todo esté verificado.

---

## Conclusión

**Arkik Productions NO puede declararse producción-segura** hasta que los controles BLOCKED (integración Neon, configuración Vercel) se verifiquen.

Los controles de código (autenticación, rate limiting, reservas, seguridad de API) son **PASS** en revisión estática y pruebas locales.

Los controles que requieren infraestructura externa (Neon, Vercel, HTTPS) son **BLOCKED/NOT VERIFIED** y requieren intervención del propietario.

**Recomendación:** Proceder a staging con la lista de acciones del propietario. No hacer push a producción hasta completar la verificación.

**ARKIK PRODUCTIONS — SECURITY FIRST. EVIDENCE BEFORE RELEASE.**
