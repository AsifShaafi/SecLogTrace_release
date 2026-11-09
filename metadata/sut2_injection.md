# SUT2 (TeaStore) — injection

> **Status: SCALED TO N=150, CLEAN (2026-09-17).** 152 attack / 152 normal,
> zero multi-label. Cross-system detection computed (see
> `docs/SUT2_ANALYSIS_DRAFT_20260917.md`). Pilot history retained below.

## Class definition
- CWE-89/943, injection attempt (no code change — malformed params on an
  existing endpoint).
- Shared target: `GET persistence/rest/products`.
  - Normal: `?start=0&max=10` — legitimate paged read → HTTP 200.
  - Attack: SQLi/NoSQLi/traversal/JNDI payloads in the `start` query param
    (int-typed JAX-RS `@QueryParam`) → HTTP 404 for all 7 payloads.

## The 2026-09-17 "404 blocker" was a misread
Prior handoff said both normal and attack 404. FALSE — normal returns 200;
only the attack 404s. The 404 is TeaStore's JAX-RS int-coercion rejection of
a non-integer `start` param, which **is the injection-rejection signature**,
not a broken generator (analogous to SUT1's injection class, where malformed
queries return empty results). Verified by direct curl on all 7 payloads.

## Collection
- Generator: `generate_sut2_traffic.py --class injection --mode pilot`
- 15 normal + 15 attack, 60s gap, separate export windows.

## Audit / noise (N=150 scale)
- Raw distinct traces: 1737
- Infra noise (bare-verb `GET`/`PUT`, no `http_url` tag): 1433 (82.5%)
- Real traces retained: 304 (152 normal + 152 attack). Zero multi-label.
- (Pilot: 445 distinct, 92.8% noise, 32 real.)

## Signal (trace-only)
- **DB-span ABSENCE + error-dispatch span — NOT status code.** Both classes:
  span_count 2 (identical), same `GET .../rest/products` root op.
  - Normal (200): `GET products` + `SELECT teadb` → **db_span_count 1**.
  - Attack (404): `GET products` + `ResponseFacade.sendError` → **db_span_count
    0** (rejected at the framework before the DB).
- **Critical methodology finding: SUT2 spans carry NO `http.status_code` (nor
  `http.method`) tag at all** — all NA, `is_error` all False. So the 404 is
  invisible to error-family features (http_4xx_count, error_span_rate); the
  only trace signal is the DB-span absence / operation composition. Error-based
  detection that works on SUT1 (which carries status codes) does NOT transfer.
- SUT1 comparison: SUT1 injection trace signal is the 0-results artifact
  (empty query result), plus log content (payloads appear in logs). SUT2 is
  request-rejected-before-DB. **Same "rejected input" essence, different trace
  manifestation.** SUT2 is trace-only, so no log-content arm here.
- Detection (trace-only RF F1, 5-fold, N=150): **SUT2 0.99** vs SUT1 1.00.

## Files
- Raw: `data/raw/jaeger/sut2_injection_sut2_injection_{normal,attack}/`
- Parsed: `data/processed/traces/sut2_injection/{spans,traces}.csv`
- Features: `data/processed/combined/sut2_injection_features.csv`

## Known limitations
- Like SUT1, this is rejected-input, not successful exploitation — frame
  honestly. The 0.99 F1 reflects "traces show the malformed request never
  reached the DB," not "traces detect SQL injection."
