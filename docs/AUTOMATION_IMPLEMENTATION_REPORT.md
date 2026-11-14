# Arkik Productions — Reporte de Automatización y Tooling Operativo

## 1. Scripts Incorporados en el Repositorio

| Script / Archivo | Comando `npm` | Función Principal |
|---|---|---|
| `scripts/dev-server.js` | `npm run dev` | Servidor local full-stack HTTP (`SPA` estática + enrutamiento directo `/api/*` incluyendo `[code]` dinámicos, carga de `.env`/`.env.local`, cabeceras de seguridad y bloqueo de archivos sensibles). |
| Static server legacy | `npm run dev:static` | Conserva `serve -s .` únicamente si se requiere modo estático puro sin API. |
| `db/manage-admin-pins.js` (`verify`) | `npm run admin:verify` | Diagnostica `admin_credentials` (`MATCH \| MISMATCH \| CORRUPTED_HASH \| MISSING`) y estado de bloqueo sin imprimir secretos ni hashes. |
| `db/manage-admin-pins.js` (`rotate`) | `npm run admin:rotate` | Rotación explícita con `--confirm --role <owner\|it>` en transacción única: actualiza hash `scrypt`, limpia `failed_attempts`/`locked_until`, revoca `admin_sessions` del rol y audita `ADMIN_CREDENTIAL_ROTATED`. |
| `db/manage-admin-pins.js` (`hash`) | `npm run admin:hash` | Genera hash `scrypt$` leyendo `--from-env <VAR>` o `stdin` (rechaza `--pin` en argv). |
| `scripts/predeploy-check.js` | `npm run predeploy:check` | Ejecuta `npm run check`, toda la suite `test/*.test.cjs`, validación de invariantes RBAC (`requireOwner`), ausencia de secretos en frontend y existencia de migraciones SQL. |

## 2. Flujo Recomendado de Desarrollo Local

```bash
# 1. Configurar .env.local (nunca commitear) con DATABASE_URL, ADMIN_SESSION_SECRET, ADMIN_OWNER_PIN, ADMIN_IT_PIN
npm run db:migrate
npm run admin:verify
npm run predeploy:check
npm run dev
```

