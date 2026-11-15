# Arkik Productions — Guía de Despliegue (Vercel + Neon PostgreSQL)

> Complementa [DEPLOYMENT_GUIDE.md](./DEPLOYMENT_GUIDE.md) y [VERCEL_STAGING_GUIDE.md](./VERCEL_STAGING_GUIDE.md) con las validaciones finales actualizadas.

## 1. Variables de Entorno Requeridas en Vercel

| Variable | Obligatoria | Propósito | Notas de Seguridad |
|---|---|---|---|
| `DATABASE_URL` | Sí | Pool TLS hacia Neon PostgreSQL | Debe usar SSL (`?sslmode=require`); jamás exponer en cliente. |
| `ADMIN_SESSION_SECRET` | Sí (Staging, Preview, Prod, Cloud y cualquier entorno con `DATABASE_URL`) | Firma HMAC-SHA256 de tokens y hash de sesiones | Mínimo 32 bytes aleatorios. Si falta o usa `'dev-secret-change-me'` fuera de `APP_ENV=development` explícito sin DB, la API responde `503`. |
| `ADMIN_OWNER_PIN` | Sí (bootstrap) | PIN o hash `scrypt$` inicial del rol `owner` | Mínimo 6+ caracteres; puede almacenarse ya hasheado con `npm run admin:hash`. |
| `ADMIN_IT_PIN` | Sí (bootstrap) | PIN o hash `scrypt$` inicial del rol `it` | Acepta caracteres alfanuméricos y símbolos sin ser mutilados. |
| `ALLOWED_ORIGINS` | Condicional | Lista separada por comas para CORS | Vacío => estrictamente Same-Origin (recomendado). |

## 2. Secuencia de Despliegue y Smoke Tests (Preview / Staging -> Production)

1. **Verificación previa en local / CI**:
   ```bash
   npm ci
   npm run predeploy:check
   npm audit --omit=dev
   ```
2. **Aplicar migraciones y verificar credenciales contra Neon**:
   ```bash
   npm run db:migrate
   npm run admin:verify
   ```
   Si `admin:verify` reporta `MISMATCH` o `CORRUPTED_HASH`, ejecutar `npm run admin:rotate -- --role <owner|it> --confirm --from-env <VAR> --reason "deploy-sync"`.
3. **Desplegar en Vercel Preview (conectado exclusivamente a Neon Staging)** y ejecutar smoke tests reales:
   - `GET https://<preview>/api/health` -> `200 OK` con `database: "not_checked"` (liveness puro, cero consultas SQL).
   - `GET https://<preview>/api/ready` -> `200 OK` con `ready: true` y `database: "connected"` (verificado mediante un único `SELECT 1`).
   - `POST https://<preview>/api/admin/login` (role `owner` + PIN real en DB) -> `200 OK` + cabecera `Set-Cookie: __Host-session=...; HttpOnly; SameSite=Strict; Secure` (en Preview/Production HTTPS) y sin tokens `v1.` cuando `DATABASE_URL` está configurada.
   - `GET https://<preview>/api/admin/dashboard` (con cookie) -> `200 OK` incluyendo `bookings`, `stats`, `pricing`, `availability` y `auditEvents`.
   - Confirmar RBAC: sesión `it` recibe `403` en `PUT /api/admin/pricing`, `PUT /api/availability` y `PATCH /api/bookings/<code>*`.
4. **Promover a Producción** únicamente tras pasar los 3 pasos anteriores sin errores, usando un **proyecto Neon Production independiente** (`DATABASE_URL`, `ADMIN_SESSION_SECRET` y PINs exclusivos de producción).

## 3. Política HSTS, `.vercelignore` y Seguridad de Credenciales

- **HSTS (`vercel.json`):** `Strict-Transport-Security: max-age=31536000` (sin `includeSubDomains`). En Preview (`*.vercel.app`) Vercel aplica HTTPS administrado por plataforma; en Production con dominio personalizado se protege el dominio principal por 1 año sin imponer HSTS forzado sobre futuros subdominios que aún no tengan TLS configurado.
- **`.vercelignore`:** Excluye artefactos locales (`scripts/`, `db/`, `test/`, `docs/`, `backups/`, `.env*`) del bundle de Vercel, pero **no oculta** archivos ya presentes en el historial Git de GitHub.
- **Rotación prioritaria sobre limpieza de historial:**
  1. Generar nuevos PINs fuertes (`owner` e `it`, jamás reutilizando valores históricos previos a P0.2) y un nuevo `ADMIN_SESSION_SECRET` por ambiente.
  2. Ejecutar `npm run admin:rotate -- --role owner --confirm --from-env NEW_OWNER_PIN --reason "credential-rotation"` y su equivalente para `it`.
  3. Solo tras completar la rotación en todos los entornos activos, evaluar si procede reescritura controlada de historial (`git filter-repo`) en ventana coordinada.

