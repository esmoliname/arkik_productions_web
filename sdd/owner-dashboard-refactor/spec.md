# Delta for Owner Dashboard Refactor

## Executive Summary

Modularize the monolithic `AdminModule.renderOwner()` method (lines 1358-1493 in `js/app.js`) into 5 focused sub-functions without changing HTML output or functionality. The refactor preserves exact outerHTML, all KPI calculations, sparkline data aggregation, status filtering logic, bookings list rendering, `STORAGE_KEYS`, `localStorage` persistence via `safeSet`/`safeParse`, and `StorageEngine.onDataChange()` dispatch patterns. No new dependencies introduced.

## Artifacts

| File | Path | Type | Change |
|------|------|------|--------|
| `js/app.js` | `js/app.js` | modified | Split `renderOwner()` into 5 sub-functions; lines 1358-1493 affected |

## Status

`proposed`

## Next Recommended Phase

`design`

## Risks

- **HTML structure breakage**: Inline template literals in each sub-function are fragile; even minor DOM structure changes break outerHTML preservation. Must use exact outerHTML diff comparison.
- **Data calculation drift**: KPI formulas (validated deposits, receivable, projected billing, occupancy %), sparkline data aggregation, status filtering counts, and bookings list mapping must produce identical results.
- **`StorageEngine.onDataChange()` cascade**: Indirect dispatch through `BookingStore` and `AvailabilityManager` must not be disrupted — each sub-function's dependencies must remain intact.
- **No test safety net**: Without a test framework, any regression in the owner dashboard would be hard to catch via manual outerHTML comparison only.

## Skill Resolution

- `sdd-spec` — Writing SDD delta specs with requirements and scenarios
- `sdd-init` — Initializing SDD context, testing capabilities, registry, and persistence
- `sdd-propose` — Creating SDD change proposal with intent, scope, and approach

## Spec Content

### 1. The Exact 5 Sub-Functions Extracted from `renderOwner()`

The following 5 methods already exist within `AdminModule` and will be extracted/composed from the monolithic `renderOwner()` at lines 1358-1493:

1. **`renderOwnerPeriodFilters()`** (lines 1366-1373)
   - Renders period filter buttons (`hoy`, `semana`, `mes`, `año`, `total`) into `#portal-period-filters`
   - Uses the `PERIOD_FILTERS` array and `this.periodFilter` to determine active state
   - Output: `<button>` elements with `data-period` attributes and `admin-tab-btn`/`admin-tab-btn--active` classes

2. **`renderOwnerMetrics()`** (lines 1375-1400)
   - Calculates KPI metrics from bookings within the period filter range
   - Computes: validated SINPE deposits (50%), receivable balances, projected billing, event occupancy percentage
   - Calls `bookingsInPeriod(this.periodFilter)` to filter bookings
   - Filters active (non-cancelada) bookings for calculations
   - Output: 4 `kpiCard()` HTML fragments rendered into `#admin-metrics`

3. **`renderOwnerSparkline()`** (lines 1402-1463)
   - Generates sparkline chart of cash flow by date using SVG `<g>`, `<rect>`, `<line>`, `<text>` elements
   - Aggregates booking data by date, separating validated (50% deposit) vs receivable amounts
   - Computes `maxVal` for bar scaling, calculates bar positions (`step`, `barW`)
   - Output: SVG chart with validated (purple) and receivable (pink) bars, date labels, and legend rendered into `#portal-sparkline`

4. **`renderOwnerFilters()`** (lines 1465-1481)
   - Renders status filter buttons (`todas`, `pendiente`, `confirmada`, `realizada`, `cancelada`) into `#admin-status-filters`
   - Uses `bookingsInPeriod(this.periodFilter)` to get period bookings, then counts per status
   - Highlights active filter with `admin-tab-btn--active` class
   - Output: `<button>` elements with `data-filter` attributes and status labels with counts

5. **`renderOwnerBookings()`** (lines 1483-1493)
   - Renders bookings list into `#admin-bookings-list` using `bookingCard()` helper
   - Filters by period and owner filter (`this.ownerFilter`)
   - Empty state: "No hay reservas registradas en esta categoría."
   - Output: `<div class="admin-booking-row">` cards joined together

### 2. Signatures and Exact Behavior of Each Sub-Function

All 5 sub-functions are methods of `AdminModule` and follow this signature:

```javascript
renderOwnerPeriodFilters() {
  // Renders period filter buttons
  // DOM: reads #portal-period-filters, sets innerHTML
}

renderOwnerMetrics() {
  // Renders KPI metrics
  // DOM: reads #admin-metrics, sets innerHTML via kpiCard()
  // Data: bookingsInPeriod(this.periodFilter), validatedDeposits, receivable, projected, occupancy
}

renderOwnerSparkline() {
  // Renders sparkline chart
  // DOM: reads #portal-sparkline, sets innerHTML via SVG
  // Data: bookingsInPeriod(this.periodFilter).filter(b => b.status !== "cancelada"), byDate aggregation
}

renderOwnerFilters() {
  // Renders status filter buttons
  // DOM: reads #admin-status-filters, sets innerHTML
  // Data: bookingsInPeriod(this.periodFilter), ownerFilter for active state and filtering
}

renderOwnerBookings() {
  // Renders bookings list
  // DOM: reads #admin-bookings-list, sets innerHTML via bookingCard()
  // Data: bookingsInPeriod(this.periodFilter).filter(b => this.ownerFilter === "todas" || b.status === this.ownerFilter)
}
```

Each function:
- Returns `undefined` (void — sets `innerHTML` on target element)
- Guards with `if (!element) return;` for missing DOM elements
- Uses `this.periodFilter` and `this.ownerFilter` from AdminModule state
- Uses `bookingsInPeriod()` and `kpiCard()` / `bookingCard()` as shared helpers
- Preserves exact HTML structure and TailwindCSS classes

### 3. Data Calculations Preservation

All data calculations are preserved exactly as they exist in the monolithic method:

**Period ranges** (`periodRange(key)` function, lines 1022-1043):
- `hoy`: `{start: iso(now), end: iso(now)}`
- `semana`: start = today - dow, end = start + 6 days
- `mes`: start = 1st of month, end = last day of month
- `anio`: `{start: year-01-01, end: year-12-31}`
- `total`: `{start: "0000-01-01", end: "9999-12-31"}`

**KPI computations** (in `renderOwnerMetrics()`, lines 1375-1400):
- `validatedDeposits`: `active.filter(b => b.status === "confirmada" || b.status === "realizada").reduce((s, b) => s + b.deposit50Amount, 0)`
- `receivable`: `active.reduce((s, b) => s + b.remainingBalance, 0)`
- `projected`: `active.reduce((s, b) => s + b.granTotal, 0)`
- `spanDays`: computed from period range dates (special handling for "total")
- `capacity`: `spanDays * DEFAULT_MAX_EVENTS_PER_DAY`
- `occupancy`: `Math.min(100, Math.round((active.length / capacity) * 100))`

**Sparkline data aggregation** (in `renderOwnerSparkline()`, lines 1402-1463):
- Filters non-cancelada bookings in period
- Aggregates by date: `{validated, receivable}` per date
- Computes `maxVal = Math.max(...data.map(x => x.validated + x.receivable), 1)`
- Calculates scaling: `step`, `barW`, bar heights `vH`, `rH`
- Generates SVG with validated (emerald) and receivable (pink) bars

**Status filtering** (in `renderOwnerFilters()`, lines 1465-1481):
- `bookingsInPeriod(this.periodFilter)` gets period bookings
- Per-status count: `key === "todas" ? periodList.length : periodList.filter(b => b.status === key).length`
- Active class: `this.ownerFilter === "todas" ? "admin-tab-btn--active" : ""` — wait, actually it checks `key === this.ownerFilter`

**Bookings list** (in `renderOwnerBookings()`, lines 1483-1493):
- `bookingsInPeriod(this.periodFilter)` gets period bookings
- Filter: `this.ownerFilter === "todas" || b.status === this.ownerFilter`
- Empty state when no bookings match
- Uses `bookingCard(b)` helper for each booking row

### 4. STORAGE_KEYS, localStorage Persistence, and StorageEngine.onDataChange() Unchanged

All persistence mechanisms remain completely unchanged:

- **STORAGE_KEYS**: All `STORAGE_KEYS` references remain as-is (e.g., `STORAGE_KEYS.bookings`, `STORAGE_KEYS.periodFilter`, `STORAGE_KEYS.ownerFilter`). No new storage keys introduced.
- **localStorage persistence**: `safeSet(key, value)` and `safeParse(key, fallback)` functions remain unchanged (lines 58-75). All sub-functions continue to use these through `BookingStore.persist()`, `CartState.persist()`, etc.
- **StorageEngine.onDataChange()**: The dispatch pattern in `StorageEngine.onDataChange(source)` (lines 354-368) continues to dispatch to `renderGalleryFilters()`, `renderMediaGallery()`, `renderCatalog()`, `updateSummaryPrices()`, `CalendarModule.render()`. The owner dashboard sub-functions do not call `onDataChange()` directly — they rely on the existing reactive flow through `BookingStore` and `AvailabilityManager` (e.g., `AvailabilityManager.set()` calls `StorageEngine.onDataChange("availability")` at line 469).
- **No changes to localStorage keys, values, or storage patterns**: All `safeSet`/`safeParse` calls, `STORAGE_KEYS` object references, and `localStorage` access patterns remain exactly as they are.

### 5. Exact Line Ranges in `js/app.js` Affected

| Function | Start Line | End Line | Description |
|----------|-----------|----------|-------------|
| `renderOwnerPeriodFilters()` | 1366 | 1373 | Period filter buttons rendering |
| `renderOwnerMetrics()` | 1375 | 1400 | KPI metrics rendering |
| `renderOwnerSparkline()` | 1402 | 1463 | Sparkline chart rendering |
| `renderOwnerFilters()` | 1465 | 1481 | Status filter buttons rendering |
| `renderOwnerBookings()` | 1483 | 1493 | Bookings list rendering |
| `renderOwner()` (original, to be simplified) | 1358 | 1364 | Calls 5 sub-functions; will be reduced to just the 5 calls or removed |

The refactor splits lines 1358-1493 (the monolithic `renderOwner()` and its 5 sub-functions) into 5 separate methods. After the refactor, `renderOwner()` at line 1358 will simply call the 5 sub-functions in order (preserving the same execution sequence), or may be simplified to just the 5 function calls.

### 6. Verification Approach: outerHTML Diff Comparison

To ensure exact HTML preservation with zero visual regression:

1. **Capture baseline outerHTML**: Before refactoring, capture the outerHTML of these containers at key points:
   - `#portal-period-filters` before/after `renderOwnerPeriodFilters()`
   - `#admin-metrics` before/after `renderOwnerMetrics()`
   - `#portal-sparkline` before/after `renderOwnerSparkline()`
   - `#admin-status-filters` before/after `renderOwnerFilters()`
   - `#admin-bookings-list` before/after `renderOwnerBookings()`

2. **Run refactored functions**: Execute each sub-function independently and capture new outerHTML.

3. **Diff comparison**: Use a simple script or manual comparison:
   ```javascript
   // Example diff approach
   const baseline = document.getElementById("admin-metrics").outerHTML;
   // ... run refactored renderOwnerMetrics()
   const newHTML = document.getElementById("admin-metrics").outerHTML;
   if (baseline === newHTML) { /* PASS */ }
   else { /* FAIL — log diff */ }
   ```

4. **Full render verification**: Run the complete `renderOwner()` (now calling 5 sub-functions) and compare the full outerHTML of the entire owner dashboard container against the baseline. Every HTML string must match exactly, including TailwindCSS classes, SVG attributes, and data bindings.

5. **Manual visual verification**: Since no test framework exists, a human should visually verify the owner dashboard renders identically in the browser, paying special attention to:
   - KPI values and order
   - Sparkline chart SVG rendering
   - Filter button labels and counts
   - Bookings list rows and actions

6. **Edge case verification**: Test with each period filter (`hoy`, `semana`, `mes`, `año`, `total`) and verify outerHTML matches for each. Test with no bookings, all bookings, mixed statuses.

### 7. No New Dependencies — Pure Refactor Within Existing Files

**Confirmed**: This refactor introduces zero new dependencies. All code remains within the existing `js/app.js` file. No npm packages, no import statements, no build step required. The refactor purely restructures existing monolithic code into smaller methods within the same file.

**Existing helpers used (already in `js/app.js`)**:
- `bookingsInPeriod(key)` — line 1045 (data layer, no new dep)
- `periodRange(key)` — line 1022 (data layer, no new dep)
- `kpiCard(icon, label, value, border)` — line 1916 (UI helper, no new dep)
- `bookingCard(b)` — line 1924 (UI helper, no new dep)
- `formatCRC(n)` — line 147 (formatting, no new dep)
- `sanitizeInput(str)` — line 11 (security, no new dep)
- `sanitizeUrl(url)` — line 26 (security, no new dep)
- `StorageEngine` — line 168 (persistence, no new dep)
- `localStorage` via `safeSet`/`safeParse` — lines 58-75 (persistence, no new dep)
- `AdminModule` methods referencing `this.periodFilter`, `this.ownerFilter` — existing state, no new dep
- `PERIOD_FILTERS` array — line 1014 (existing constant, no new dep)
- `BOOKING_STATUSES`, `DEFAULT_MAX_EVENTS_PER_DAY`, `LOGISTICS_CONFIG`, `CATALOG_SERVICES` — existing globals, no new dep

**No new imports, no new modules, no new file creation**. All changes are internal to `js/app.js` lines 1358-1493.

---
---
---
## Engram Persistence Reference

**Saved to Engram** with topic_key `sdd/owner-dashboard-refactor/spec`:
- Architecture decision: modularizing renderOwner() into 5 sub-functions
- Preservation of exact HTML output via outerHTML diff verification
- Zero new dependencies confirmed for static VanillaJS + TailwindCSS project
- Risk: HTML structure breakage — inline template literals are fragile
- Key data calculations preserved: KPI formulas, sparkline aggregation, status filtering, bookings list mapping