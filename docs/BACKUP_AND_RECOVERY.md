# Arkik Productions — Backup, Restore & Credential Recovery Runbook

## 1. Respaldo de Datos de Negocio (Neon PostgreSQL)

1. **Snapshot / Point-In-Time Recovery (PITR) en Neon**: Antes de cada migración mayor o rotación masiva de configuración, crear un branch/restore point en Neon Console o exportar dump lógico con `pg_dump --format=custom --no-owner --no-acl "$DATABASE_URL" > arkik_backup_$(date +%F).dump`.
2. **Respaldo Operativo desde Consola IT (Tab 04 — Database Vault)**: Permite exportar snapshot JSON y SQL del estado cargado en el portal para archivo operativo. Nota: las operaciones destructivas del navegador ("Limpiar Caché Local" / "Restablecer Estado de Fábrica") solo reinician almacenamiento local transitorio y **no alteran** PostgreSQL Neon.

## 2. Runbook de Recuperación de Acceso Admin (`PIN` inválido / `MISMATCH` / `CORRUPTED_HASH` / Lockout)

> **Regla**: Nunca ejecutar `TRUNCATE`, `DELETE` masivos ni modificar manualmente `admin_credentials` sin auditoría.

1. **Diagnosticar sin riesgo** (apunta `.env.local` o entorno Vercel a `DATABASE_URL`):
   ```bash
   npm run admin:verify
   ```
   - `MATCH`: El hash en Neon coincide con la variable de entorno local (`ADMIN_OWNER_PIN` / `ADMIN_IT_PIN`).
   - `MISMATCH`: `admin_credentials` tiene un PIN distinto al de tus variables actuales (frecuente cuando `ON CONFLICT DO NOTHING` preservó un PIN inicial anterior).
   - `CORRUPTED_HASH`: La fila en Neon no cumple el formato `scrypt$N$r$p$saltHex$hashHex` (ej. doble-hashing previo).
   - `MISSING`: Faltan filas en `admin_credentials` -> correr `npm run db:migrate`.

2. **Rotar credencial afectada de forma transaccional y auditada**:
   ```bash
   # Opción A: usando variable en .env.local / shell
   npm run admin:rotate -- --role owner --confirm --from-env ADMIN_OWNER_PIN --reason "login-recovery"

   # Opción B: vía stdin para no dejar el PIN en historial
   npm run admin:rotate -- --role it --confirm --reason "login-recovery"
   ```
   Esta operación limpia `failed_attempts = 0, lock_level = 0, locked_until = NULL`, revoca las sesiones activas de ese rol en `admin_sessions` y registra `ADMIN_CREDENTIAL_ROTATED` en `audit_log`.

3. **Si el navegador muestra bloqueo local en `#adminLoginModal`**: esperar la cuenta regresiva mostrada en la interfaz (en local dev, usar un perfil limpio o esperar la expiración); cerrar y reabrir el modal muestra el tiempo restante exacto.

