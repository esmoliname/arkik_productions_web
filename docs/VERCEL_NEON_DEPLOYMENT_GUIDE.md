# Arkik Productions — Guía de Despliegue (Vercel + Neon PostgreSQL)

> Complementa [DEPLOYMENT_GUIDE.md](./DEPLOYMENT_GUIDE.md) y [VERCEL_STAGING_GUIDE.md](./VERCEL_STAGING_GUIDE.md) con las validaciones finales actualizadas.

## 1. Variables de Entorno Requeridas en Vercel

| Variable | Obligatoria | Propósito | Notas de Seguridad |
|---|---|---|---|
| `DATABASE_URL` | Sí | Pool TLS hacia Neon PostgreSQL | Debe usar SSL (`?sslmode=require`); jamás exponer en cliente. |
| `ADMIN_SESSION_SECRET` | Sí (Prod) | Firma HMAC-SHA256 de tokens y hash de sesiones | Mínimo 32 bytes aleatorios. Si falta en producción, la API responde `503`. |
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
3. **Desplegar en Vercel Preview (Staging)** y ejecutar smoke tests reales:
   - `GET https://<preview>/api/health` -> `200 OK` con conectividad DB `ok`.
   - `POST https://<preview>/api/admin/login` (role `owner` + PIN real) -> `200 OK` + cabecera `Set-Cookie: arkik_session=...; HttpOnly; SameSite=Strict; Secure`.
   - `GET https://<preview>/api/admin/dashboard` (con cookie) -> `200 OK` incluyendo `bookings`, `stats`, `pricing`, `availability` y `auditEvents`.
   - Confirmar RBAC: sesión `it` recibe `403` en `PUT /api/admin/pricing`, `PUT /api/availability` y `PATCH /api/bookings/<code>*`.
4. **Promover a Producción** únicamente tras pasar los 3 pasos anteriores sin errores.

