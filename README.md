# Arkik Productions — Sistema Operativo Ejecutivo & Plataforma Web SPA

> **Producción:** Vercel Serverless + Neon PostgreSQL — Costa Rica (`America/Costa_Rica` / `UTC-6`)
>
> **Despliegue Oficial en Vivo:** https://arkik-productions.vercel.app/
> **Repositorio Fuente:** https://github.com/esmoliname/arkik_productions_web
> **Vista Previa Estática (GitHub Pages):** https://esmoliname.github.io/arkik_productions_web/

Plataforma web ejecutiva (SPA) y sistema operativo de reservas musicales, cotizaciones dinámicas, validación bancaria **SINPE Móvil**, consola administrativa Zero-Trust y exportación documental (**PDF A4** y **Word `.docx`**) para **Arkik Productions** (Granadilla, San José, Costa Rica).

---

## 1. Arquitectura del Sistema y Flujo de Datos

### Estructura real del proyecto

```
arkik_productions_web/
├── index.html                  # SPA única (cotizador, portal staff, biblioteca, docs)
├── css/styles.css              # Sistema de diseño Dark Obsidian / Glassmorphism
├── js/
│   ├── data.js                 # Catálogo, configuración, motor de calendario/precios
│   ├── api.js                  # Cliente HTTP tipado (Zero-Trust, sin montos en cliente)
│   └── app.js                  # Lógica de UI, wizard, RBAC, CloudSync, exportación
├── api/                        # Funciones Serverless Vercel (Node 22+)
│   ├── _lib/                   # Dominio puro, repositorio, servicio, auth, rate-limit
│   ├── bookings/, availability/, pricing/, health/, ready/
│   └── admin/                  # login, session, logout, dashboard, pricing, audit, stats
├── db/                         # Migraciones SQL, provisioning least-privilege, seeds
├── test/                       # 18+ suites offline (node:test), contrato y seguridad
├── scripts/                    # predeploy-check, dev-server, build-publish, preflight Neon
├── .github/workflows/          # GitHub Pages (preview) y Cloudflare Pages (preview)
├── vercel.json                 # Rewrites, headers de seguridad, cache
└── .env.example                # Plantilla de variables (sin valores reales)
```

### Arquitectura Híbrida / Dual-Branch

- **`main` — Producción Zero-Trust.** Respaldada por API Serverless (`api/bookings`, `api/availability`, `api/admin/*`) y base de datos PostgreSQL (Neon). Sesiones `HttpOnly` / `SameSite=Strict`, hashes `scrypt`, rate-limiting persistente en PostgreSQL y autoridad de precios exclusivamente en servidor (`PRICE_MISMATCH`).
- **`preview/cloudflare` — Vista previa estática.** Despliegue en GitHub Pages / Cloudflare Pages con motor resiliente `SafeStorage` / `MemoryStorage` y cliente HTTP fail-closed (sin colas offline no verificadas).

### Diagrama de flujo (cliente → persistencia → auditoría)

```
┌────────────────────┐      HTTPS Same-Origin      ┌──────────────────────────┐
│  Navegador (SPA)   │  ───────────────────────►  │  Vercel Serverless (Node) │
│  Wizard 4 pasos    │   POST /api/bookings        │  api/_lib/service.js      │
│  SINPE 50 %        │   (sin montos)             │  api/_lib/logic.js        │
│  compresión canvas │                            │  api/_lib/repo.js         │
└────────────────────┘                            └────────────┬─────────────┘
       ▲                                                      │
       │  CloudSync (focus/visibility, throttled)              │ Pooled TLS + SQL param.
       │  KPIs / calendario / auditoría                       ▼
┌──────┴──────────────┐                            ┌──────────────────────────┐
│  Portal Staff RBAC  │  ◄──────────────────────  │   Neon PostgreSQL        │
│  owner / it         │   GET /api/admin/*         │  bookings, availability, │
│  KPIs, tarifas,     │                            │  admin_sessions,         │
│  bloqueos, auditoría│                            │  rate_limits, config     │
└─────────────────────┘                            └──────────────────────────┘
```

---

## 2. Módulos Funcionales y Reglas de Negocio

### Cotizador Público Interactivo (Wizard en 4 Pasos)

- **Catálogo de formatos musicales y técnicos** con tiempos exactos de montaje y desmontaje.
- **Cálculo dinámico de extras:** horas adicionales al 50 % con tope máximo, DJ en recesos, subwoofers.
- **Recargo automático del 12 % de viáticos fuera del GAM**, evaluado por Provincia + Cantón (7 provincias / 84 cantones).
- **Motor de calendario y disponibilidad:** antelación mínima estricta de **72 horas**, horizonte de **365 días**, máximo 2 eventos diarios y margen logístico de traslado/descanso (5–6 horas) anti-colisiones.
- **Flujo SINPE Móvil:** prima del **50 %**, compresión nativa de comprobantes en `<canvas>` y generación de código único `ARK-XXXXXXXX` con envío estructurado a WhatsApp.

### Portal Staff con Control de Acceso Basado en Roles (RBAC)

- **Vista Propietario (`owner`):** KPIs financieros dinámicos con filtros temporales (`Hoy`, `Esta Semana`, `Este Mes`, `Este Año`, `Histórico Total`), gráfico de flujo de caja, gestión de estados de reserva (`pendiente → confirmada → realizada / cancelada`), reprogramación, bloqueo de fechas y gestión dinámica de tarifas.
- **Suite de Ingeniería TI (`it`):** matriz de tarifas en vivo, bloqueo/desbloqueo de fechas en agenda, gestor de biblioteca multimedia e integridad/respaldo de base de datos JSON. Sin permisos de mutación sobre precios, disponibilidad ni reservas.

> **Nota de seguridad:** este README no incluye PINs, contraseñas ni llaves privadas. Las credenciales se gestionan exclusivamente mediante variables de entorno y migraciones.

### RAG Analytics Studio & Motor de Exportación (PDF / DOCX)

- Indexación analítica de registros, cálculo de tasa de conversión en tiempo real y visor lateral de inspección.
- Generación de comprobantes/reportes en **PDF A4** (`html2pdf.js`) y **Word** (`docx`) con logotipo incrustado, con degradación limpia a vista de impresión controlada ante bloqueos de CDN.

### Rendimiento Móvil y Sistema de Diseño

- Estética Dark Obsidian / Glassmorphism, tipografía `Plus Jakarta Sans` + `JetBrains Mono`.
- `AnimationRegistry` con pausa automática de `requestAnimationFrame` en modales/scroll.
- Prevención de auto-zoom en iOS Safari (`16px` en inputs).

---

## 3. Seguridad Zero-Trust

- **Autenticación y Sesiones:** PINs administrativos validados exclusivamente en servidor con `scrypt` + salt único y comparación en tiempo constante. Sesiones persistidas en PostgreSQL (`admin_sessions`) con expiración deslizante de 15 minutos y cookie `__Host-session` (`HttpOnly; Secure; SameSite=Strict; Path=/`).
- **Autoridad de Precios (`PRICE_MISMATCH`):** El cliente **no** envía montos en `POST /api/bookings`. El servidor recalcula tarifa base, horas extra, DJ, subwoofers, recargo fuera de GAM (12 %) y adelanto SINPE (50 %) directamente desde PostgreSQL.
- **Rate Limiting Distribuido:** Control de tasa por IP real respaldado por PostgreSQL (`rate_limits`), complementado por `ClientThrottler` persistente en `SafeStorage`.
- **Zona Horaria Oficial (`UTC-6`):** Backend y calendario del cliente anclan "hoy", la antelación mínima de 72 horas y el horizonte de 365 días a hora fija de Costa Rica (`UTC-6`, sin DST).
- **Anti-XSS y Sanitización:** escape de entradas, lista blanca estricta de estados (`sanitizeBookingStatusClass`) y renderizado seguro con `textContent`.
- **Endurecimiento HTTP (`vercel.json`):** `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Permissions-Policy` y `Content-Security-Policy-Report-Only`.

---

## 4. Instalación Local, Variables de Entorno y Pruebas

### Requisitos

- **Node.js 22+** y **npm**
- Base de datos **Neon PostgreSQL**

### Instalación y configuración local

```bash
npm install
cp .env.example .env.local
```

Genera un secreto de sesión seguro (`ADMIN_SESSION_SECRET`, mínimo 64 caracteres hex):

```bash
node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
```

Completa en `.env.local` tu `DATABASE_URL` (pooled), `DIRECT_DATABASE_URL` (direct, solo migraciones), `ADMIN_OWNER_PIN`, `ADMIN_IT_PIN` y `ADMIN_SESSION_SECRET`. **Nunca subas `.env`, `.env.local` ni `.dev.vars` al repositorio.**

### Migraciones y arranque local

```bash
# Aplicar esquema y semillas de configuración inicial en Neon
npm run db:migrate

# Iniciar servidor full-stack local (SPA + /api/*)
npm run dev
```

### Validación y pruebas

```bash
# Verificación de sintaxis JS en frontend, DB y scripts
node --check js/app.js
node --check js/data.js
npm run check

# Suite completa de pruebas unitarias, de integración y seguridad (offline mocks)
npm test

# Compuerta completa pre-despliegue (sintaxis + 18+ suites + invariantes estáticos RBAC/SQL/headers)
npm run predeploy:check
```

---

## 5. Despliegue en Vercel + Neon

1. Conecta el repositorio en **Vercel** y configura las variables de entorno en **Project Settings > Environment Variables**:
   - `DATABASE_URL` (endpoint `-pooler` de Neon con rol mínimo `arkik_app`)
   - `ADMIN_SESSION_SECRET` (64+ caracteres aleatorios)
   - `APP_ENV=production`
   - `SEED_MODE=false`
   - `ALLOWED_ORIGINS` (vacío para *same-origin*)
   - *(No agregues `DIRECT_DATABASE_URL` ni `DIRECT_ADMIN_DATABASE_URL` al runtime de Vercel).*
2. Ejecuta `npm run db:migrate` desde tu entorno seguro apuntando a la base de producción antes del primer tráfico.
3. Verifica liveness y readiness tras el despliegue:
   - `GET /api/health` → `200 OK`
   - `GET /api/ready` → `200 OK` (confirma conectividad real con Neon `SELECT 1`)

El preview estático se publica automáticamente en **GitHub Pages** desde la rama `preview/cloudflare` y en **Cloudflare Pages** (`arkik-productions`, rama `cloudflare-preview`).

---

© 2026 **Arkik Productions** — Música en Vivo & Sonido Profesional — Granadilla, San José, Costa Rica.
