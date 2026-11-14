# Arkik Productions — Final Pre-Production Audit

**Fecha:** 2026-11-13
**Rama:** `main` (7 commits locales preservados sobre `origin/main` + cambios de recuperación P0 de login)
**Node:** `>=22` (`engines.node`)

---

## FASE 1 — Estado Git

| Control | Estado | Evidencia |
|---|---|---|
| 7 commits previos intactos | PASS | `git log -8 --oneline` confirma `5d029a2`..`0ecd4a3` preservados |
| `git diff --check` | PASS | Sin errores de whitespace (solo avisos LF/CRLF de Windows) |
| Sin secretos ni `.env` en working tree | PASS | Escaneo automático sobre código (`SECRET_SCAN_HITS: 0`) |
| Push / deploy sin autorización | PASS | No ejecutados |

---

## FASE 2 — Validación de Autenticación (Post-Recuperación P0)

| Control | Estado | Evidencia |
|---|---|---|
| PIN validado server-side (`scrypt` + `timingSafeEqual`) | PASS | `api/_lib/auth.js`, `api/_lib/service.js`; `test/auth-recovery.test.cjs` |
| Neon `admin_credentials` autoritativo cuando existe `DATABASE_URL` | PASS | `api/admin/login.js` prioriza `service.login()` siempre que `config.databaseUrl` esté definido |
| Pre-hashed `scrypt$` en `db/migrate.js` sin doble hash | PASS | `bootstrapAdmins` valida `isValidScryptHash` antes de `hashPin` (`test/auth-recovery.test.cjs` #19) |
| Consistencia de sanitización UI ↔ Backend ↔ Migración | PASS | `.trim()` sin `.replace(/\D/g, '')` destructivo; `#admin-pin` `maxlength="32"` |
| Roles Owner / IT separados (`requireAdmin` vs `requireOwner`) | PASS | IT recibe `403` en `PUT /api/admin/pricing` y `PUT /api/availability`; Owner `200` |
| Cookies `HttpOnly`, `SameSite=Strict`, `Secure` (`__Host-session`) en prod | PASS | Verificado en test #16 (atributos emitidos) / HTTPS real: **NOT VERIFIED** |
| Tokens `v1.` stateless rechazados cuando `DATABASE_URL` está activo | PASS | `auth.requireAdmin` rechaza `v1.` si `config.databaseUrl` existe (#13) |
| Sesiones DB con expiración deslizante, logout y bloqueo post-logout | PASS | Verificado localmente con pool simulado (#11–#15) |
| Logout limpia cookie incluso ante falla temporal de DB | PASS | `api/admin/logout.js` emite `clearSessionCookie()` antes de limpiar sesión |
| Frontend distingue errores `503`/`5xx`/`404`/red vs `401` | PASS | `SecurityModule.verifyPin` marca `infraError: true` sin consumir intentos (#20 VM) |

---

## FASE 3 — Rate Limiting, CORS y Seguridad API

| Control | Estado | Evidencia |
|---|---|---|
| Buckets por origen (`login:{ip}` 10/h, `login:{ip}:{role}` 5/15m) | PASS | Test #9 (`429` con `Retry-After` y sin bloqueo cross-IP) y `security.test.cjs` A1 |
| CORS allowlist y preflight `403` | PASS | `api/_lib/cors.js`, test #18 |
| Fallo cerrado ante ausencia de `DATABASE_URL`, caída Neon o schema inválido | PASS | Tests #6–#8 (`503`/`500`, cero cookies emitidas) |
| Redacción de logs y ausencia de tokens en cuerpo HTTP | PASS | `security.test.cjs` G1–G8, `auth-recovery.test.cjs` #1 |
| Concurrencia multi-instancia real en Vercel + Neon | NOT VERIFIED | **BLOCKED** (requiere infraestructura Vercel + Neon) |

---

## FASE 4 — Puertas de Calidad (Última Ejecución)

| Comando | Estado | Resultado |
|---|---|---|
| `npm run check` | PASS | 0 errores de sintaxis (`js/app.js`, `js/data.js`, `js/api.js`) |
| `npm test` | PASS | 7/7 archivos, 14/14 tests en runner principal (`auth-recovery` + 6 suites previas) |
| `npm ls --depth=0` | PASS | `@neondatabase/serverless@0.10.4`, `serve@14.2.8` |
| `git diff --check` | PASS | 0 errores de whitespace |
| `npm audit` | BLOCKED | Entorno sandbox offline (`ENOTFOUND registry.npmjs.org`) |
| `npm audit --omit=dev` | BLOCKED | Entorno sandbox offline (`ENOTFOUND registry.npmjs.org`) |

---

## Acciones Requeridas del Propietario Antes de Producción

1. Configurar `DATABASE_URL`, `ADMIN_SESSION_SECRET`, `ADMIN_OWNER_PIN`, `ADMIN_IT_PIN`, `APP_ENV`, `SEED_MODE=false` en Vercel Preview/Production (`docs/VERCEL_STAGING_GUIDE.md`).
2. Ejecutar `npm run db:migrate` contra Neon staging y luego producción.
3. Ejecutar `npm audit --omit=dev` en entorno con acceso a red.
4. Verificar login Owner/IT, cookies `__Host-session; Secure` y logout end-to-end sobre la URL HTTPS de Vercel Preview.

---

## Conclusión

- **Código, pruebas automatizadas locales y contratos de seguridad**: **PASS**
- **Integración real con Neon, Vercel HTTPS y `npm audit` en línea**: **BLOCKED / NOT VERIFIED** en este entorno offline.

No declarar apto para tráfico productivo hasta completar la verificación en Vercel Preview + Neon descrita en `docs/VERCEL_STAGING_GUIDE.md`.
