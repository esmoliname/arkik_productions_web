# Arkik Productions — Master System Architecture

> Referencia unificada de arquitectura end-to-end para producción en Vercel + Neon PostgreSQL (complementa [ARCHITECTURE.md](./ARCHITECTURE.md) y [API_REFERENCE.md](./API_REFERENCE.md)).

## 1. Visión General de Capas

```text
+-------------------------------------------------------------------+
| Navegador (SPA Estática: index.html + css/styles.css + js/*.js)   |
|  - Vista Pública: cotizador GAM, disponibilidad, galería, reserva |
|  - Bóveda Admin (#adminLoginModal -> #adminPortalModal):          |
|    * Owner: métricas financieras, reservas, precios, calendario   |
|    * IT: consola técnica, galería multimedia, audit_log, backups  |
+---------------------------------+---------------------------------+
                                  | HTTP Same-Origin + Cookie HttpOnly
                                  v
+-------------------------------------------------------------------+
| Edge / Serverless Runtime (Vercel Functions: api/**/*.js)         |
| Local Full-Stack Dev Server (scripts/dev-server.js: /api/* + SPA) |
|  - cors.js (preflight estricto + ALLOWED_ORIGINS)                 |
|  - auth.js (scrypt N=16384 + HMAC-SHA256 tokens + cookies)        |
|  - ratelimit.js (ventana fija en PostgreSQL / IP)                 |
|  - service.js -> repo.js -> db.js (@neondatabase/serverless)      |
+---------------------------------+---------------------------------+
                                  | TLS Pool (DATABASE_URL)
                                  v
+-------------------------------------------------------------------+
| PostgreSQL 16 (Neon Serverless)                                   |
|  bookings, availability, audit_log, config, admin_credentials,    |
|  admin_sessions, idempotency_keys, rate_limits, schema_migrations |
+-------------------------------------------------------------------+
```

## 2. Componentes Autorizados y Responsabilidades

| Capa | Archivo(s) | Responsabilidad |
|---|---|---|
| Cliente Web | `index.html`, `js/data.js`, `js/api.js`, `js/app.js` | UI pública y administrativa. Jamás contiene hashes, secretos ni `DATABASE_URL`. |
| API Pública | `api/health.js`, `api/pricing.js`, `api/availability/index.js`, `api/bookings/index.js` | Consulta de estado, precios vigentes, capacidad diaria y creación idempotente de reservas. |
| API Autenticación | `api/admin/login.js`, `api/admin/logout.js`, `api/admin/session.js` | Validación `scrypt`, cookies `HttpOnly; SameSite=Strict; Path=/`, expiración deslizante (`15 min`). |
| API Operativa RBAC | `api/admin/dashboard.js`, `api/admin/stats.js`, `api/admin/audit.js`, `api/admin/pricing.js`, `api/bookings/[code]/*.js` | Lectura admin (`requireAdmin`) y mutaciones restringidas a Owner (`requireOwner`). |
| Núcleo de Negocio | `api/_lib/{auth,config,cors,db,log,logic,ratelimit,registry,repo,respond,service}.js` | Validación estricta server-side, cálculo autoritativo de montos CRC, transacciones e invariantes de estado. |
| Automatización DB | `db/migrate.js`, `db/manage-admin-pins.js`, `db/seed-dev.js` | Migraciones SQL idempotentes, verificación/rotación auditada de PINs sin sobrescrituras silenciosas. |
| Dev & Gates | `scripts/dev-server.js`, `scripts/predeploy-check.js` | Entorno local full-stack sin secuestro HTML en `/api/*` y validación automática pre-deploy. |

## 3. Reglas Arquitectónicas No Negociables

1. **Autoridad de Base de Datos**: Cuando `DATABASE_URL` está definida, `admin_credentials` y `admin_sessions` en PostgreSQL son la única fuente de verdad (se rechazan tokens stateless `v1.` y no hay fallback a variables de entorno).
2. **RBAC Estricto en Servidor**: Toda mutación de reservas (`PATCH /api/bookings/[code]*`), precios (`PUT /api/admin/pricing`) y calendario (`PUT/DELETE /api/availability`) exige `auth.requireOwner(req)`.
3. **Fail-Closed ante Faltas Operativas**: Si `ADMIN_SESSION_SECRET` falta en producción (`api/_lib/config.js`) o Neon no está disponible (`api/_lib/db.js`), los endpoints responden `503 service_unavailable` sin revelar secretos ni degradar la seguridad.

