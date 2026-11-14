# Arkik Productions — Reporte Final de Base de Datos & Flujo de Negocio (P0.2)

> Complementa [DATABASE.md](./DATABASE.md). Documenta esquema, toolset operativo y resultados de flujo transaccional completo.

## 1. Esquema, Índices y Constraints Verificados (`db/migrations/*.sql`)

- `001_initial_schema.sql`: tablas `bookings`, `availability`, `audit_log` (`action`, `entity_type`, `entity_id`, `actor`, `metadata`, `created_at`), `config`, `admin_credentials` (`role`, `pin_hash`, `failed_attempts`, `lock_level`, `locked_until`, `updated_at`), `admin_sessions`, `idempotency_keys` (FK `ON DELETE CASCADE`), `rate_limits`.
- `002_indexes.sql`: índices en `bookings` (`selected_date` activo parcial, `status`, `created_at DESC`, `idempotency_key` único parcial), `audit_log` (`created_at DESC`, `(entity_type, entity_id)`), `admin_sessions (expires_at)` y `rate_limits (window_start)`.
- `003_config_seed.sql`: semilla idempotente (`pricing:catalog`, `geo:provinces`, `geo:gam`, `logistics:*`, `sinpe:config`).

## 2. Auditoría Exhaustiva de `db/manage-admin-pins.js`

| Control | Resultado | Evidencia |
|---|---|---|
| `hash` vía `stdin` en Windows | **PASS** | `"..." | node db/manage-admin-pins.js hash` generó `scrypt$16384$8$1$...` sin errores ni imprimir PIN. |
| Rechazo de `--pin` en `argv` (sin DB) | **PASS** | `node db/manage-admin-pins.js rotate --role owner --confirm --pin 123456` rechazado antes de abrir conexión (`Refusing --pin on command line argv`). |
| Guardia `--confirm` y `--role` | **PASS** | Aborta con error si falta `--confirm` o si `--role` no es `owner \| it`. |
| Transacción SQL y **Rollback** atómico | **PASS** | Escenario 26 en [auth-recovery.test.cjs](../test/auth-recovery.test.cjs): fallo simulado en `DELETE FROM admin_sessions` ejecuta `ROLLBACK`, manteniendo intactos `pin_hash`, sesiones previas y `audit_log`. |
| `verify` y `rotate` completo | **PASS** | Escenario 21: `verify` detecta `MATCH`/`CORRUPTED_HASH`/`MISMATCH`/`MISSING` sin imprimir secretos; `rotate` limpia lockout, revoca sesiones solo del rol rotado y registra `ADMIN_CREDENTIAL_ROTATED`. |

## 3. Flujo de Negocio de Reservas e Idempotencia (Task 6)

Verificado en Escenario 29 ([auth-recovery.test.cjs](../test/auth-recovery.test.cjs)) sobre pool en memoria simulando las consultas SQL exactas de [repo.js](../api/_lib/repo.js):
1. `POST /api/bookings` con `X-Idempotency-Key` -> `201` con precios CRC autoritativos calculados en servidor (`PASS`).
2. Replay con igual `X-Idempotency-Key` -> `200` devolviendo la misma reserva sin duplicar registro (`PASS`).
3. `GET /api/admin/dashboard` (sesión Owner 1) lista la reserva (`PASS`).
4. `PATCH /api/bookings/[code]/status` -> `confirmada` y lectura desde segunda sesión independiente Owner (`"dispositivo 2"`) -> persistencia `confirmada` confirmada (`PASS`).
5. Cancelación `confirmada -> cancelada` + `GET /api/admin/audit` verificando eventos `BOOKING_CREATED`, `BOOKING_CONFIRMED`, `BOOKING_CANCELLED` y `ADMIN_LOGIN` (`PASS`).

## 4. Validación Real Pendiente en Neon Staging

- Ejecución contra PostgreSQL Neon real (`SELECT 1`, `npm run db:migrate`, `npm run admin:verify`, concurrencia `pg_advisory_xact_lock` multi-instancia y persistencia real): **BLOCKED** en este entorno por falta de `DATABASE_URL` de staging y conectividad de red externa.
- Nunca se tocó ni ejecutó prueba alguna contra producción.
