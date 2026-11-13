# Arkik Productions — API Reference

Base path: `/api`. All responses use `{success, data}` / `{success, error:{code,message}}`.

## Public

- `GET /api/health` — service + database status.
- `GET /api/pricing` — catalog, overrides, rates.
- `GET /api/availability?date=ISO` or `?from=&to=` — capacity/blocked.
- `POST /api/bookings` (header `X-Idempotency-Key`) — create booking.

## Admin (cookie session required)

- `GET /api/bookings` — list with filters (status/date/from/to/q/limit).
- `GET /api/bookings/:code?include=voucher`
- `PATCH /api/bookings/:code` — update fields.
- `PATCH /api/bookings/:code/status` — {status}.
- `PATCH /api/bookings/:code/reschedule` — {selectedDate, selectedTime}.
- `GET/PUT /api/admin/pricing`
- `GET /api/admin/dashboard`, `GET /api/admin/stats`, `GET /api/admin/audit`
- `POST /api/admin/login`, `POST /api/admin/logout`, `GET /api/admin/session`.

## Availability admin

- `PUT /api/availability`, `DELETE /api/availability?date=ISO`.

## Auth

Session cookie HttpOnly, Secure (prod), SameSite=Strict. Unauthenticated admin
requests return 401.