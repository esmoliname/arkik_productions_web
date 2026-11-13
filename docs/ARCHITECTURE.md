# Arkik Productions — Architecture

## Overview

Vanilla JavaScript SPA (`index.html` + `js/app.js` ~14k lines) served by Vercel,
with a serverless API under `api/` and Neon PostgreSQL as the single source of
truth for bookings. No framework migration; Vanilla JS is intentional.

## Components

- **Frontend**: `js/app.js` (BookingStore, CartState/PriceManager, AvailabilityManager,
  ArkikRAGEngine/RAGStudio, ModalController, ArkikAssets), `js/data.js` (catalog,
  geography, config), `js/api.js` (ArkikApi client).
- **Backend**: Vercel Serverless Functions `api/**/*.js`, shared libs `api/_lib/*`
  (db, repo, service, logic, auth, config, cors, respond, ratelimit, registry, log).
- **Database**: Neon PostgreSQL via `@neondatabase/serverless` (Pool max 1).

## Data flow (booking)

Customer → Frontend (ArkikApi.createBooking) → POST /api/bookings →
service.createBooking (rate limit, idempotency replay, validation, server pricing,
capacity lock + transaction, insert, audit) → Neon → {success, booking} →
Frontend confirmation (only after server success).

## Source of truth

- Bookings, statuses, availability, config, audit, admin credentials/sessions:
  Neon PostgreSQL.
- LocalStorage: cart state, drafts, read cache, offline queue (non-authoritative).

## Idempotency

`X-Idempotency-Key` header → `idempotency_keys` table (PK). Replay returns the
existing booking with HTTP 200. Frontend keeps the key in `sessionStorage`
(`arkik_idem_v1`) across retries and page reloads; cleared only after server
success.

## Admin auth

scrypt PIN hashes seeded from env; HMAC-hashed sliding sessions (15 min);
HttpOnly cookies, Secure in production, SameSite=Strict; role-based (owner/it).

## Environments

Development / Preview / Production isolated by `DATABASE_URL`, `APP_ENV`,
`SEED_MODE`. Production uses `SEED_MODE=false`.