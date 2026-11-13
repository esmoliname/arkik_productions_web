# Arkik Productions — QA Report

## Automated tests

`npm test` (2026-11-13): 5 suites, 0 failures.

- api-client.test.cjs — ArkikApi client contract.
- behavior.test.cjs — 13 checks (HTTP contracts, auth gating).
- contract.test.cjs — 30 checks (availability range, pricing, auth).
- load.test.cjs — 24 checks.
- logic.test.cjs — 30 checks (pricing, capacity, state machine, validation).

## Real integration (Neon)

BLOCKED — no credentials in this environment. Prepared scenario documented in
docs/PRODUCTION_READINESS_REPORT.md §8.

## Cross-device E2E

NOT VERIFIED (simulated only). Scenario: mobile creates booking → server
persists → desktop admin retrieves → status update → persists both sides.

## Regression

All five suites preserved; no tests removed.