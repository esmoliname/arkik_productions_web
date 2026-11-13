# Arkik Productions — Catalog Audit

## Source

`js/data.js` → `CATALOG_SERVICES` (6 services). Prices defined here and
validated server-side via config/migrations (003_config_seed).

## Services

1. Banda Completa — ₡650,000 (popular)
2. Cuarteto Arkik — ₡480,000
3. Trío Acústico Premium — ₡380,000
4. Dúo Íntimo Arkik — ₡250,000
5. Solista Instrumental — ₡150,000
6. Alquiler Sonido e Iluminación Pro — ₡250,000

## Extras (DYNAMIC_EXTRAS_CONFIG)

- Extra hours (50% of base per hour, max 6)
- DJ service (₡75,000/h, max 6)
- Subwoofers 18" (₡80,000/unit, max 4)

## Pricing integrity

Frontend displays prices; server recalculates in `service.computePricing`
and rejects mismatches (`price_mismatch`). Travel surcharge 12% outside GAM
(with canton exceptions: Pérez Zeledón, Sarapiquí, Turrialba).

## Status

Catalog structure consistent between frontend and backend pricing logic.
Product images are remote Unsplash URLs; no missing-image audit performed
beyond static review. No invented items.