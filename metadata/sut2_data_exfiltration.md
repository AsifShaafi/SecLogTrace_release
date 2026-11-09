# SUT2 (TeaStore) — data_exfiltration

> **Status: SCALED TO N=150, CLEAN (2026-09-17).** 152 attack / 152 normal,
> zero multi-label. Cross-system detection computed (see
> `docs/SUT2_ANALYSIS_DRAFT_20260917.md`). Pilot history retained below.

## Class definition
- Bulk PII enumeration (no code change — abuse of an existing endpoint).
- Attack target: `GET persistence/rest/users?start=0&max=-1` — bulk read of
  the entire user table (returns ~100 user records in one call).
- Normal target: `GET persistence/rest/users/{id}` — a single-record read
  (real seed id discovered at runtime, e.g. 507).
- Seed IDs are non-sequential (start at 507) — discovered at runtime, not
  hardcoded (see `discover_seed_data()`).

## Collection
- Generator: `generate_sut2_traffic.py --class data_exfiltration --mode pilot`
- 15 normal + 15 attack, 60s gap, separate export windows.

## Audit / noise (N=150 scale)
- Raw distinct traces: 1740
- Infra noise (bare-verb `GET`/`PUT`, no `http_url` tag): 1436 (82.5%)
- Real traces retained: 304 (152 normal + 152 attack). Zero multi-label.
- (Pilot: 452 distinct, 92.9% noise, 32 real.)

## Signal (trace-only)
- **Breadth / volume + DB touch.** Normal single-record read = 1 span
  (served without a DB-query span in the trace). Attack bulk read = 2 spans
  (`GET .../rest/users` + `SELECT teadb.PERSISTENCEUSER`): the bulk path hits
  the DB and returns the whole table. Features: span_count 1→2,
  db_span_count 0→1, span_dur_p95 ~4→15ms.
- SUT1 comparison: SUT1 data_exfiltration signal is breadth (3→5 endpoints
  touched), 0→74 PII field reads, ~36× request rate. SUT2 is single-endpoint
  single→bulk with a DB touch — **same essence (volume/breadth), generalizes.**
- Detection (trace-only RF F1, 5-fold, N=150): **SUT2 0.99** vs SUT1 0.85.

## Files
- Raw: `data/raw/jaeger/sut2_data_exfiltration_sut2_data_exfiltration_{normal,attack}/`
- Parsed: `data/processed/traces/sut2_data_exfiltration/{spans,traces}.csv`
- Features: `data/processed/combined/sut2_data_exfiltration_features.csv`

## Known limitations
- Normal and attack use different persistence endpoints (single-record vs
  collection), by design — the attack IS "call the bulk endpoint," so the
  root-operation difference is part of the attack signature, not a confound.
