# Arkik Productions — Session Handoff (2026-11-13)

**Rama:** `main`
**Commit de implementación P0.2:** `a6f9904` (`feat: complete P0.2 authentication and security hardening`)
**Commits previos preservados:** `87ae290`..`0ecd4a3` intactos sin modificaciones ni reescritura de historia.
**Push / Deploy:** NO realizado (`working tree` respaldado únicamente en local).

---

## A. Estado del Proyecto

- **Arquitectura Actual:** SPA estática (`index.html`, `css/styles.css`, `js/{data,api,app}.js`) servida junto con API serverless Vercel (`api/**/*.js`) respaldada por PostgreSQL en Neon (`db/migrations/001`–`003`) y servidor local full-stack (`scripts/dev-server.js`).
- **Frontend:** Endurecido en `js/app.js` e `index.html` (pin normalization sin `\D` stripping, detección explícita de `static_server_html` sin sumar intentos, retención de `#adminLoginModal` mientras `loadProtectedAdminData` valida `/api/admin/dashboard`, restauración de lockout countdown al reabrir, hidratación de `auditEvents` reales en Consola IT Tab 04, y `#login-website-trap` con atributos anti-autofill). Auditoría estática DOM: 255 IDs únicos, 0 duplicados, 6 refs locales válidas, 0 `<img>` sin `alt`.
- **Backend:** Handlers bajo `api/` con envelope JSON consistente, timeout health check, CORS estricto same-origin por defecto (`ALLOWED_ORIGINS`) y errores mapeados limpiamente (`503 service_unavailable` también si falta `ADMIN_SESSION_SECRET` en producción en `api/_lib/config.js`).
- **Autenticación:** `scrypt` (`N=16384`), sesiones HMAC-SHA256 almacenadas como hash en `admin_sessions` (TTL deslizante 15 min), cookie `__Host-session` (`HttpOnly; Secure; SameSite=Strict; Path=/`) cuando `isProduction || VERCEL === '1' || VERCEL_ENV === 'preview'` y `arkik_session` en HTTP local; rechazo estricto de tokens `v1.` siempre que exista `DATABASE_URL`; CLI segura `db/manage-admin-pins.js` (`verify`, `rotate --confirm`, `hash`) con transacción/rollback, validación previa a DB y sin impresión ni argumentos CLI de secretos.
- **RBAC:** `auth.requireAdmin` para lecturas administrativas (`GET`) y `auth.requireOwner` obligatorio para todas las escrituras administrativas (`PUT /api/admin/pricing`, `PUT`/`DELETE /api/availability`, `PATCH /api/bookings/[code]`, `/status`, `/reschedule`). Rol `it` recibe `403`.
- **PostgreSQL / Neon:** Migraciones `001_initial_schema.sql`, `002_indexes.sql` y `003_config_seed.sql` revisadas; `db/migrate.js` conserva `ON CONFLICT DO NOTHING` sin sobrescribir credenciales existentes y advierte `CORRUPTED_HASH`/`MISMATCH` sin filtrar secretos. Aún no ejecutado contra Neon real en este entorno.
- **Vercel:** Configuración en `vercel.json` y guía actualizada en `docs/VERCEL_NEON_DEPLOYMENT_GUIDE.md`; pendiente despliegue a Vercel Preview.
- **Seguridad:** Cero secretos o connection strings en código rastreado; `.gitignore` excluye `.env`, `.env.local`, `.env.*.local`, `.env.production`, `.vercel`, `*.log`, `node_modules/`.

---

## B. Trabajo Completado (P0.2)

- Correcciones e integraciones guardadas en commit `a6f9904` (33 archivos).
- **Validaciones con resultado PASS antes del commit:**
  - `npm run check`: **PASS** (exit 0).
  - `npm test`: **PASS** (`tests 24, pass 24, fail 0, skipped 0` incluyendo escenarios 1–30 en `test/auth-recovery.test.cjs` + `api-client`, `contract`, `load`, `logic`, `security`).
  - `npm run predeploy:check`: **PASS** (exit 0; invariantes RBAC/secretos + 3 migraciones SQL).
  - Prueba TCP loopback en vivo `scripts/dev-server.js` (`http://127.0.0.1:3456`, credenciales efímeras fuera de disco): **PASS** (`/` HTML `200`, `/api/health` `200`, `/api/admin/login` `401`/`200 JSON` con cookie, `/api/admin/dashboard` `200` Owner/IT, `/api/admin/pricing` `PUT` IT `403`, `/api/admin/logout` `200` `Max-Age=0`, `/api/does-not-exist` `404 JSON`, `/.env.example` `404`).
  - Prueba CLI `db/manage-admin-pins.js`: **PASS** (`hash` por `stdin` en PowerShell -> `scrypt$...`; `--pin` en `argv` rechazado antes de conectar DB; rollback transaccional verificado en escenario 26).
  - `npm ls --depth=0`: **PASS** (`@neondatabase/serverless@0.10.4`, `serve@14.2.8`).
  - `git diff --check`: **PASS** (exit 0).

---

## C. Limitaciones Pendientes (Honestidad Operativa)

- **Neon Staging real:** **BLOCKED** (sin `DATABASE_URL` de staging ni conectividad externa en el entorno).
- **Vercel Preview HTTPS:** **NOT VERIFIED** (sin CLI/credenciales ni acceso externo para validar dominio HTTPS real).
- **Rate limiting multiinstancia real:** **NOT VERIFIED** en lambdas Vercel reales contra Neon (únicamente verificado simulando dos instancias independientes contra mock de tabla `rate_limits` en escenario 28).
- **Auditoría npm (`npm audit` / `npm audit --omit=dev`):** **BLOCKED** por conectividad (`getaddrinfo ENOTFOUND registry.npmjs.org`).
- **Restauración de backups en Neon:** **Pendiente de evidencia real** (runbook documentado en `docs/BACKUP_AND_RECOVERY.md` y rollback de rotación probado solo contra mock SQL; `pg_dump` / PITR / restore en Neon real aún no ejecutados).

---

## D. Orden Exacto de Trabajo para la Próxima Sesión

1. Confirmar checkpoint Git local (`git status`, `git log -2 --oneline`, rama `main`).
2. Configurar un proyecto/rama **Neon Staging** aislado de producción.
3. Configurar variables de entorno localmente en `.env.local` (nunca rastreado por Git): `DATABASE_URL` (staging), `ADMIN_SESSION_SECRET`, `ADMIN_OWNER_PIN`, `ADMIN_IT_PIN`.
4. Ejecutar migraciones únicamente contra Staging (`npm run db:migrate`).
5. Ejecutar `npm run admin:verify`.
6. Corregir/sincronizar credenciales únicamente si `admin:verify` reporta `MISMATCH` o `CORRUPTED_HASH` usando `npm run admin:rotate -- --role <owner|it> --confirm --from-env <VAR> --reason "staging-sync"`.
7. Ejecutar smoke tests transaccionales reales contra Neon Staging (reserva, idempotencia, confirmación Owner, lectura segunda sesión, cancelación, `audit_log` y prueba de backup/restore).
8. Configurar variables de entorno en **Vercel Preview** (apuntando a Neon Staging, `ALLOWED_ORIGINS` vacío o dominio preview exacto).
9. Desplegar únicamente a **Vercel Preview** cuando exista autorización explícita.
10. Validar en Preview HTTPS cookies `__Host-session`, autenticación Owner e IT, RBAC (`403` IT en escrituras) y persistencia entre dispositivos.
11. Verificar rate limiting (`429 Retry-After`) entre instancias serverless independientes contra PostgreSQL Neon Staging.
12. Ejecutar `npm audit --omit=dev`, revisar resultados reales y completar la auditoría final previa a Producción.

---

## E. Instrucciones de Seguridad

- **Production permanece completamente intacta**: no se tocó infraestructura productiva, no se corrieron migraciones sobre datos reales ni se ejecutó `git push` o despliegue alguno.
- **Cero secretos en Git**: jamás commitear `.env`, `.env.local`, PINs en texto plano, hashes reales de producción/staging, `ADMIN_SESSION_SECRET` ni URIs `DATABASE_URL` con credenciales.
- Mantener sin modificaciones las protecciones `requireOwner`, detección `static_server_html` y rechazo de tokens `v1.` con DB activa.
