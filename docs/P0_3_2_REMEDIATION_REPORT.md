# Arkik Productions — Reporte de Remediación P0.3.2

> **Alcance:** Saneamiento controlado, endurecimiento de secretos por entorno (`M-01`), correcciones complementarias (`B-01`–`B-04`, `M-03`), análisis de compatibilidad gradual CSP/SRI (`M-02`), verificación automatizada y revisión independiente previa a consolidación Git / Neon Staging / Vercel Preview.
>
> **Reglas operativas respetadas:** Cero `git commit`, cero `git push`, cero reescritura de historial, cero despliegues en Vercel y cero conexiones o migraciones contra Neon remoto. Cero secretos, PINs, hashes, tokens o cookies impresos.

---

## 1. Resumen Ejecutivo y Veredicto P0.3.2

- **Estado de código, tests y documentación P0.3.2 local:** **PASS** (con alcance externo vivo pendiente).
- **Integración real externa (`Neon PostgreSQL`, `Vercel Preview HTTPS`, `npm audit --omit=dev`):** **BLOCKED / NOT VERIFIED** en este entorno offline sin credenciales remotas.
- **Saneamiento Git pendiente de aprobación humana:** Los 5 cambios preexistentes heredados en el working tree (`D sdd-init-results.json`, `M sdd/owner-dashboard-refactor/explore`, `D update_script*.js`) están diagnosticados y documentados sin haber ejecutado `commit`, `push` ni descartes destructivos.
- **Peer Review Independiente:** **PASS** (Ronda 2 aprobada tras creación de este informe y atención de 4 observaciones menores de la Ronda 1; ver Sección 9).

---

## 2. Estado Actual del Repositorio Git

Verificado directamente mediante comandos Git locales de solo lectura:

| Atributo Git | Valor Verificado | Estado |
|---|---|---|
| Rama local | `main` | **PASS** |
| `HEAD` local | `c942377c6f67fca45f2e7c065f29cbc7a63fa765` | **PASS** |
| Padre de `HEAD` (`HEAD~1`) | `fab11ff374268c1e2ba267ee38d9802c2508e19c` | **PASS** |
| `origin/main` local | `fab11ff374268c1e2ba267ee38d9802c2508e19c` (`ahead 1`) | **PASS** |
| Remoto `origin` | `https://github.com/esmoliname/arkik_productions_web.git` (`fetch`/`push`) | **PASS** |
| Área de staging (`git diff --cached --stat`) | Vacía (0 archivos staged) | **PASS** |
| Working tree total sin commitear | 22 entradas: 5 heredadas preexistentes + 16 modificadas en P0.3.2 + 1 nuevo reporte | **PARTIAL** *(requiere aprobación humana para staging/commit)* |

---

## 3. Diagnóstico Completo de los 5 Elementos Pendientes del Working Tree (Fase A)

Estos 5 elementos ya figuraban sin commitear en el working tree antes de P0.3.2. No se modificó ni se descartó su estado mediante comandos destructivos ni se creó commit:

| Elemento | Estado en Working Tree | Propósito y Contenido (sin secretos) | Riesgo e Impacto `HEAD` vs Historial | Decisión Propuesta |
|---|---|---|---|---|
| `sdd-init-results.json` | `D` (eliminado en disco; `42` líneas / `2356` bytes en `HEAD`) | Telemetría obsoleta de inicialización SDD (`2026-08-28`) que declaraba erróneamente ausencia de test runner y SPA estática sin backend. Cero secretos. | Bajo. Archivo redundante fuera de runtime y ya excluido por `.vercelignore`. | **Mantener eliminado** e incluir la eliminación en el próximo commit de saneamiento aprobado. |
| `sdd/owner-dashboard-refactor/explore` | `M` (modificado en disco; `84` líneas) | Nota exploratoria histórica del dashboard Owner. El diff reemplaza un literal numérico histórico de 4 dígitos en la línea 4 de `HEAD` por `[REDACTED_HISTORICAL_PIN]`. Líneas 1–84 verificadas sin otros literales de PIN. | Revertirlo reintroduciría el literal numérico de 4 dígitos en `HEAD`. Mantener la modificación no borra el commit histórico previo donde nació. | **Conservar modificación (`M`)** con `[REDACTED_HISTORICAL_PIN]` e incluirla en el próximo commit de saneamiento. |
| `update_script.js` | `D` (eliminado en disco; `296` líneas en `HEAD`) | Script puntual heredado previo a PostgreSQL para parchar código DOM/JS antiguo. En `HEAD` contenía dos digests hex SHA-256 heredados y dos fallbacks plaintext heredados de 4 dígitos `[REDACTED]` para WebCrypto cliente (no credenciales Neon `scrypt$` ni `ADMIN_SESSION_SECRET`). | Eliminarlo limpia `HEAD` futuro (`sdd/` y `update_script*.js` ya están excluidos en `.vercelignore`), pero los objetos permanecen en commits históricos en GitHub. **Prohibido** reescribir historial en este flujo. | **Mantener eliminado** en el próximo commit. **Acción operativa recomendada:** si alguno de esos códigos históricos heredados siguiera en uso vivo, rotarlo vía `npm run admin:rotate`. |
| `update_script_2.js` | `D` (eliminado en disco; `14` líneas en `HEAD`) | Parche histórico ya aplicado anteriormente sobre comentario/función legacy `resetAdminLock_legacy()`. Cero secretos. | Ningún riesgo funcional ni de seguridad. | **Mantener eliminado** en el próximo commit de saneamiento. |
| `update_script_3.js` | `D` (eliminado en disco; `17` líneas en `HEAD`) | Parche histórico puntual ya incorporado en `js/app.js` (coma antes de `enablePinUI(enabled)`). Cero secretos. | Ningún riesgo funcional ni de seguridad. | **Mantener eliminado** en el próximo commit de saneamiento. |

---

## 4. Remediación M-01 — Endurecimiento de `ADMIN_SESSION_SECRET`

En [`api/_lib/config.js`](../api/_lib/config.js#L67-L130) se resolvió la fuga de configuración donde `APP_ENV=staging` o entornos no declarados podían heredar el secreto por defecto `'dev-secret-change-me'`:

1. **Nuevo getter `isStagingOrPreview` (`L103-L113`):** detecta `APP_ENV=staging|preview`, `VERCEL_ENV=preview`, y overrides `NODE_ENV=staging|preview`.
2. **Aislamiento estricto en `isExplicitLocalDev` (`L123-L130`):** exige `!databaseUrl`, `!isProduction`, `!isCloud`, `!isStagingOrPreview`, `APP_ENV === 'development'` explícito y `NODE_ENV !== 'production'`.
3. **Fail-closed en `sessionSecret` (`L67-L82`):** cuando `ADMIN_SESSION_SECRET` está ausente, vacío o vale `'dev-secret-change-me'`, si `!this.isExplicitLocalDev` lanza error controlado (`arkikApp = true`, `code = 'service_unavailable'`, `status = 503`). El fallback `'dev-secret-change-me'` queda restringido **exclusivamente** a desarrollo local explícito (`APP_ENV=development`) sin `DATABASE_URL` y sin flags cloud, staging, preview o producción.
4. **Coherencia de arranque y gate:**
   - [`scripts/predeploy-check.js`](../scripts/predeploy-check.js#L47-L50) exige la presencia conjunta de `isExplicitLocalDev`, `isStagingOrPreview` y `isCloud` en `config.js`, y en `L104-L111` distingue `ADMIN_SESSION_SECRET=PLACEHOLDER` cuando vale `'dev-secret-change-me'`.
   - [`scripts/dev-server.js`](../scripts/dev-server.js#L248-L255) delega en `config.isExplicitLocalDev` como única fuente de verdad al imprimir el modo de fallback en consola.

---

## 5. Correcciones Complementarias Aplicadas (`B-01`–`B-04`, `M-03`)

| ID | Archivo(s) | Cambio Implementado | Estado |
|---|---|---|---|
| **B-01** | [`.gitignore`](../.gitignore#L13-L21), [`.env.example`](../.env.example#L29-L32) | Agregados `.env.development`, `.env.staging` y `.env.preview` al ignore junto con `!.env.example` explícito (verificado con `git check-ignore -v`); documentación actualizada en `.env.example`. | **PASS** |
| **B-02** | [`js/app.js`](../js/app.js#L11164-L11172) | Eliminado el fragmento comentado huérfano (`/** Persistencia en vivo ... reader.onerror ... */`) tras `generateSQLBackup()`, dejando limpia la transición a la sección `14. EXECUTIVE & BRAND LIGHTBOXES`. | **PASS** |
| **B-03** | [`README.md`](../README.md#L101-L180) | Completado el inventario de las 7 suites en `README.md` incorporando `test/auth-recovery.test.cjs` y `test/security.test.cjs`, además de alinear la documentación de `ADMIN_SESSION_SECRET` con `staging`/`preview`/`DATABASE_URL`. | **PASS** |
| **B-04** | [`test/load.test.cjs`](../test/load.test.cjs#L6-L22), [`test/auth-recovery.test.cjs`](../test/auth-recovery.test.cjs#L2080-L2843), [`test/behavior.test.cjs`](../test/behavior.test.cjs#L3-L10) | Incorporado `api/pricing.js` en `test/load.test.cjs` (`checked=26 fails=0`); cubierta petición `HEAD /admin/` y SPA routes con status `308` + cuerpo vacío en Test 33; alineado Case I (agregado test real de `403` IT RBAC y `logout` `Max-Age=0`); añadido **Test 37** validando `M-01` (`503` sin fallback en 9 entornos no-dev/staging/preview/cloud/prod/implícitos + `DATABASE_URL`, contraste con dev explícito sin DB, y login PostgreSQL simulado en `staging`/`preview` con secreto explícito); aisladas env vars de `.env.local` al inicio de `test/behavior.test.cjs`. | **PASS** |
| **M-03** | [`docs/ADMIN_SECURITY_REPORT.md`](../docs/ADMIN_SECURITY_REPORT.md), [`docs/PRODUCTION_READINESS_REPORT.md`](../docs/PRODUCTION_READINESS_REPORT.md), [`docs/FINAL_PRODUCTION_READINESS.md`](../docs/FINAL_PRODUCTION_READINESS.md), [`docs/SESSION_HANDOFF_2026-11-13.md`](../docs/SESSION_HANDOFF_2026-11-13.md), [`docs/VERCEL_STAGING_GUIDE.md`](../docs/VERCEL_STAGING_GUIDE.md), [`docs/VERCEL_NEON_DEPLOYMENT_GUIDE.md`](../docs/VERCEL_NEON_DEPLOYMENT_GUIDE.md) | Actualizadas las referencias históricas de P0.2 sobre `/api/health` (`200` liveness puro sin SQL) vs `/api/ready` (`200/503` probe `SELECT 1`), ampliadas las notas de suites y alineada la obligatoriedad `M-01` de `ADMIN_SESSION_SECRET` en las guías de despliegue Vercel/Neon. | **PASS** |

---

## 6. Estrategia Gradual CSP (`Content-Security-Policy-Report-Only`) y SRI (`M-02`)

No se activó una `Content-Security-Policy` restrictiva bloqueante en [`vercel.json`](../vercel.json) para no romper la SPA estática. La inspección directa de [`index.html`](../index.html), `css/styles.css` y `js/{data,api,app}.js` verificó los siguientes condicionantes técnicos:

1. **Inventario observado en frontend:**
   - **4 scripts CDN externos sin atributo `integrity` ni `crossorigin`:**
     - `https://cdn.tailwindcss.com`: CDN JIT dinámica sin versión fija en URL; **incompatible con SRI estático** porque recompila CSS según el User-Agent e inyecta `<style>` en runtime (exige `'unsafe-inline'` en `style-src` mientras se mantenga Tailwind CDN).
     - `https://cdnjs.cloudflare.com/ajax/libs/html2pdf.js/0.10.1/html2pdf.bundle.min.js`: versión fija (`0.10.1`), **SRI viable** tras cálculo/verificación online de digest SHA-384.
     - `https://cdn.jsdelivr.net/npm/@emailjs/browser@3/dist/email.min.js`: etiqueta mayor flotante (`@3`), **incompatible con SRI estable** hasta fijar versión exacta `patch` (ej. `@3.x.y`).
     - `https://cdn.jsdelivr.net/npm/docx@8.5.0/build/index.umd.js`: versión fija (`8.5.0`), **SRI viable** tras cálculo/verificación online.
   - **Scripts inline en `index.html`:** **2 bloques**: bloque #1 ejecutable (`tailwind.config`, `776` caracteres, líneas 36–63) y bloque #2 no ejecutable (`type="application/ld+json"`, `1884` caracteres).
   - **Handlers inline y estilos:** **93 atributos `on*=`** en `index.html`, **276 coincidencias `on*=`** en templates JS, **6 atributos `style="..."`** en `index.html`, **82 asignaciones `.style.`** y **7 `.style.cssText`** en JS; **0 ocurrencias de `eval` / `new Function`**.
   - **Orígenes externos usados / embebidos:** `https://cdn.tailwindcss.com`, `https://cdnjs.cloudflare.com`, `https://cdn.jsdelivr.net`, `https://fonts.googleapis.com` (`style-src`), `https://fonts.gstatic.com` (`font-src`), `https://images.unsplash.com` + `data:` SVG en `css/styles.css` (`img-src`), `https://www.youtube.com` (`frame-src`), además de tráfico XHR runtime del SDK `@emailjs/browser` hacia EmailJS (`connect-src`).

2. **Plan gradual de adopción recomendado (3 fases):**
   - **Fase 1 (No disruptiva — siguiente paso en Staging/Preview):**
     - Publicar `Content-Security-Policy-Report-Only` en `vercel.json` sobre `/(.*)` con inventario inicial (`default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data: blob: https://images.unsplash.com; frame-src 'self' https://www.youtube.com; connect-src 'self' https://api.emailjs.com; object-src 'none'; base-uri 'self'; frame-ancestors 'none'`) para recolectar telemetría en Vercel Preview sin bloquear UI.
     - En entorno con red, fijar versión exacta de `@emailjs/browser` y añadir `integrity="sha384-..." crossorigin="anonymous"` verificado a `html2pdf`, `@emailjs/browser` y `docx` (o hacer vendoring local).
   - **Fase 2 (Refactorización incremental):**
     - Externalizar `tailwind.config` a archivo local (`js/tailwind-config.js`) o reemplazar Tailwind CDN JIT por build CSS estático en CI/build (eliminando la necesidad permanente de `'unsafe-inline'` en `style-src` / script CDN sin SRI).
     - Migrar progresivamente los 93+ handlers `onclick=` / `onsubmit=` y plantillas JS a delegación con `addEventListener`.
   - **Fase 3 (Enforcement):**
     - Pasar de `Content-Security-Policy-Report-Only` a `Content-Security-Policy` estricta cuando el reporte en Preview marque cero falsos positivos.

---

## 7. Validación de Higiene de Secretos y Dependencias

- **Escaneo sobre diff P0.3.2 (`.env.example`, `.gitignore`, `README.md`, `api/`, `docs/`, `js/`, `scripts/`, `test/`):** `32107` bytes analizados, **0 hashes `scrypt$` añadidos** y únicamente 2 URIs sintéticas de prueba local (`postgres://mock:mock@localhost:5432/m01_db_dev` y `m01_staging_ok`) dentro del nuevo Test 37 en `test/auth-recovery.test.cjs` (más la confirmación de cero secretos/URIs en este documento nuevo `docs/P0_3_2_REMEDIATION_REPORT.md`).
- **`.gitignore` verificada (`git check-ignore -v`):** `.env`, `.env.local`, `.env.development`, `.env.staging`, `.env.preview`, `.env.production` ignorados correctamente; `.env.example` NO ignorado.
- **Dependencias (`npm ls --depth=0`):** árbol íntegro (`@neondatabase/serverless@0.10.4`, `serve@14.2.8`).
- **Auditoría de vulnerabilidades (`npm audit --omit=dev`):** **BLOCKED** en este entorno offline (`registry.npmjs.org` inaccesible sin salida a red).

---

## 8. Resultados de Pruebas y Comandos Ejecutados

Ejecución completa verificada tras las últimas ediciones de código, tests y guías (`2026-11-14`):

| Comando / Comprobación | Resultado Exacto Observado | Alcance y Naturaleza |
|---|---|---|
| `npm run check` | **PASS** (`exit 0`) | Sintaxis JS/CLI (`app.js`, `data.js`, `api.js`, `migrate.js`, `manage-admin-pins.js`, `dev-server.js`, `predeploy-check.js`). |
| `npm test` (`node --test "test/*.test.cjs"`) | **PASS** (`tests 31, suites 1, pass 31, fail 0, skipped 0`) | `api-client` (`[1]-[5] ALL PASS`), `auth-recovery` (escenarios `1-37` incluyendo `HEAD /admin/` en Test 33, Case I RBAC/logout y Test 37 `M-01`), `behavior` (`checks=16 failed=0`), `contract` (`checks=30 failed=0`), `load` (`checked=26 fails=0`, incluye `api/pricing.js`), `logic` (`checks=30 failed=0`), `security` (`checks=15 failed=0`). **DB simulada in-memory / mock SQL, no Neon real.** |
| `npm run predeploy:check` | **PASS** (`exit 0`) | Sintaxis + suite completa + invariantes estáticos RBAC/auth/`isStagingOrPreview`/`/api/health`/`/api/ready`/`vercel.json` + 3 migraciones SQL + snapshot seguro sin placeholder. |
| `npm ls --depth=0` | **PASS** (`exit 0`) | `@neondatabase/serverless@0.10.4`, `serve@14.2.8`. |
| `git diff --check` | **PASS** (`exit 0`) | Cero errores de espacios en blanco al final de línea ni conflictos de formato. |
| `npm audit --omit=dev` | **BLOCKED** | Sin acceso a red/registro npm en el sandbox. |
| Neon PostgreSQL live (`db:migrate`, `admin:verify`, concurrencia, PITR) | **BLOCKED** | Prohibido por alcance y sin `DATABASE_URL` remota en este sandbox. |
| Vercel Preview HTTPS (`__Host-session`, `RateLimit` multi-instancia, CSP Report-Only live) | **NOT VERIFIED** | Sin despliegue autorizado ni acceso externo en este entorno. |

---

## 9. Resultado del Peer Review Independiente

- **Ronda 1 (`p032_peer_reviewer`, solo lectura, con autoridad de rechazo) — FAIL (observación bloqueante previa a creación de informe):** Rechazado inicialmente exclusivamente porque 3 documentos actualizados enlazaban `./P0_3_2_REMEDIATION_REPORT.md` antes de su creación física en disco, confirmando cumplimiento estático de `M-01`, `B-01`–`B-04` y limpieza de PIN histórico. Emitió 4 advisories menores, todos resueltos inmediatamente:
  1. Distinción de `'dev-secret-change-me'` como `PLACEHOLDER` en `scripts/predeploy-check.js`.
  2. Aislamiento explícito de env vars de `.env.local` al inicio de `test/behavior.test.cjs`.
  3. Uso directo de `config.isExplicitLocalDev` en el banner de arranque de `scripts/dev-server.js`.
  4. Alineación de notas `ADMIN_SESSION_SECRET` en `docs/VERCEL_STAGING_GUIDE.md` y `docs/VERCEL_NEON_DEPLOYMENT_GUIDE.md`.
- **Ronda 2 (`p032_peer_reviewer`, verificación final sobre archivos en disco) — PASS (aprobado):** Confirmó la existencia e integridad de `docs/P0_3_2_REMEDIATION_REPORT.md` (11 secciones, enlace resuelto, cero secretos/URI reales, distinción explícita entre mocks SQL y Neon/Vercel reales) y verificó las 4 correcciones advisory. Señaló además actualizar el conteo del working tree (`22 entradas` tras incluir este archivo nuevo), ajustado en la Sección 2 antes del cierre. *(Nota: al ser subagente estrictamente de solo lectura `read_file`, la ejecución de `npm run check`, `npm test`, `npm run predeploy:check` y `git diff --check` se valida mediante la batería ejecutada directamente en el workspace principal.)*

---

## 10. Estado Consolidado por Control (`PASS | PARTIAL | FAIL | BLOCKED | NOT VERIFIED`)

| Control / Requisito P0.3.2 | Estado | Evidencia Respaldada |
|---|---|---|
| Diagnóstico Fase A de 5 items pendientes sin descarte ni secretos | **PASS** | Sección 3 + inspección `HEAD` y working tree sin impresión de PINs/hashes. |
| `M-01` Exigencia de `ADMIN_SESSION_SECRET` (`staging`, `preview`, cloud, prod, `DATABASE_URL`, implícito) | **PASS** | `api/_lib/config.js`, `scripts/predeploy-check.js`, Test 37 en `test/auth-recovery.test.cjs`. |
| `B-01` Higiene `.gitignore` y preservación `.env.example` | **PASS** | `.gitignore` + `git check-ignore -v`. |
| `B-02` Limpieza comentario huérfano `js/app.js` | **PASS** | `js/app.js#L11164-L11172` + `npm run check`. |
| `B-03` Inventario completo de suites en `README.md` | **PASS** | `README.md` lista las 7 suites y reglas de entorno actualizadas. |
| `B-04` `api/pricing.js` en `load.test.cjs` + Case I + `HEAD /admin/` | **PASS** | `load.test.cjs` (`checked=26`) + `auth-recovery.test.cjs` Test 33 & Test 35 Case I. |
| `M-03` Coherencia documental (`/api/health` vs `/api/ready`, guías) | **PASS** | Actualizados 6 documentos + presente reporte existente en disco. |
| `M-02` Endurecimiento CSP (`Report-Only`) y SRI | **PARTIAL** | Análisis de compatibilidad y roadmap de 3 fases listos (Sección 6); pendiente implementación en `vercel.json`/`index.html` y validación live en Preview. |
| Validación automatizada local (`check`, `test`, `predeploy:check`, `git diff --check`) | **PASS** | Todas las suites locales en 0 fallos; pruebas DB sobre mock SQL in-memory. |
| Limpieza de working tree hacia commit/push controlado | **PARTIAL** | Cambios listos y revisados localmente; commit/push detenidos esperando aprobación humana explícita. |
| Seguridad operativa ante historial heredado de `update_script.js` | **PARTIAL** | Archivo eliminado del árbol futuro, pero commits históricos permanecen en `origin/main`; requiere confirmar si algún PIN histórico antiguo debe rotarse. |
| Pruebas live Neon PostgreSQL (`db:migrate`, `admin:verify`, lock transaccional) | **BLOCKED** | Sin `DATABASE_URL` remota ni ejecución contra DB autorizada. |
| Despliegue y pruebas live Vercel Preview HTTPS / `npm audit --omit=dev` | **NOT VERIFIED / BLOCKED** | Sin despliegue autorizado y sin salida a internet en este sandbox. |

---

## 11. Decisión Pendiente para Aprobación Humana (Antes de Commit, Push o Despliegue)

1. **Aprobación de staging y commit de saneamiento + P0.3.2 en `main`:**
   - Decidir si consolidar en **1 commit** o **2 commits locales separados** (`chore(cleanup)` para los 5 elementos preexistentes + `fix/security/docs` para P0.3.2) antes de habilitar `git push origin main`:
     - Incluir `D sdd-init-results.json`, `M sdd/owner-dashboard-refactor/explore`, `D update_script.js`, `D update_script_2.js`, `D update_script_3.js` junto con `.env.example`, `.gitignore`, `README.md`, `api/_lib/config.js`, `scripts/dev-server.js`, `scripts/predeploy-check.js`, `js/app.js`, `test/{auth-recovery,behavior,load}.test.cjs`, `docs/*`.
2. **Confirmación de credenciales operativas heredadas (`update_script.js`):**
   - Confirmar que en **Neon Staging** y **Producción** no permanece activo ninguno de los dos códigos históricos heredados de 4 dígitos ni hashes ligados a `update_script.js`; de haber duda, rotar con `npm run admin:rotate`.
3. **Secuencia externa posterior (fuera de este sandbox offline):**
   - Ejecutar `npm audit --omit=dev` con acceso a red, autorizar `git push origin main`, provisionar **Neon Staging** (`db:migrate`, `admin:verify`), desplegar **Vercel Preview**, validar `__Host-session` HTTPS + `RateLimit` multi-instancia + `Content-Security-Policy-Report-Only`.
