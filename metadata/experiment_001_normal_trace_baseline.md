# experiment_001 — Normal Trace Baseline

> **Status: DEV DATA, not corpus data.** Corrected 2026-08-05 after a
> corpus audit. Three claims in the original version were wrong: the trace
> count, the noise-contamination statement, and the implication that the
> four export files cover one collection window. Corrections are marked
> inline. Do not cite any number from this experiment in a paper.

## Before collection
- Date/time window: 2026-07-28, 00:25:58 – 00:30:21 UTC (4m23s)
- Purpose: first real normal-behavior baseline for Train-Ticket, generated
  after resolving the trip-catalog blocker (see `research_master_log.md` /
  `phase_log_20260728.md` for the full root-cause story)
- Actions performed: 20 simulated sessions via
  `generate_baseline_traffic.py --sessions 20`, each doing: register/login
  (or reuse demo account, ~30% of sessions) → list stations → list routes
  → search trips across 6 station pairs with varied dates → book a ticket
  (if a trip was found) → query orders
- Services expected to be touched: ts-travel-service, ts-travel2-service,
  ts-preserve-service, ts-order-service, ts-station-service,
  ts-route-service, ts-user-service, ts-contacts-service,
  ts-seat-service, ts-price-service, ts-security-service, ts-config-service
- Collector: Shaafi (via `generate_baseline_traffic.py` +
  `export_jaeger_traces.sh`)
- Trip catalog state: 6 trips seeded prior to this run — G1307
  (nanjing→shanghai), G1308 (shanghai→taiyuan), D1309 (nanjing→beijing),
  Z1310 (shanghaihongqiao→hangzhou, travel2service), K1311
  (suzhou→shanghai, travel2service), G1312 (shanghai→seclogtrace_stationa)
- Storage backend at collection time: **Jaeger all-in-one, in-memory,
  `--memory.max-traces 8000`**. Measured retention 97.5 minutes. The
  original traces were evicted from Jaeger long before 2026-08-05; the
  files in `data/raw/jaeger/` are the only surviving copy

## During collection
- Start timestamp: 2026-07-28T00:25:58.766420
- End timestamp: 2026-07-28T00:30:21.852534
- Errors/anomalies observed: none during traffic generation — all 20
  sessions completed, every session that found a trip completed a booking
- Session log: `data/raw/traffic/traffic_session_log_20260728_002558.jsonl`

## After collection
Raw files in `data/raw/jaeger/`:

| File | Export mtime | Traces returned |
|---|---|---|
| `experiment_001_ts-travel-service_normal_20260728_003027.json` | 00:30 | 452 |
| `experiment_001_ts-travel2-service_normal_20260728_003029.json` | 00:30 | 423 |
| `experiment_001_ts-preserve-service_normal_20260728_003030.json` | 00:30 | 199 |
| `experiment_001_ts-order-service_normal_20260728_003031.json` | **02:06** | 300 |

**CORRECTION 1 — trace count.** The original "Total: 1,374 traces" summed
the four files. Jaeger returns a trace for every service participating in
it, so the files overlap. Deduplicated on `traceID`:

| Measure | Value |
|---|---|
| Sum of per-service counts | 1,374 (never cite) |
| **Distinct traces** | **1,253** |
| Duplicate entries | 121 |
| Infra-noise-only traces | 716 (57.1%) |
| **Real traces** | **537** |
| **Cleanly labelled real traces** | **483** |

Produced by `scripts/preprocessing/corpus_audit.py`.

**CORRECTION 2 — noise contamination.** The original text said "no
Nacos-noise contamination." That was wrong and contradicted the data-quality
note recorded in this same file on the same day. 716 of 1,253 distinct
traces are single-span `NacosWatch$$Lambda$.run` service-discovery polling.
The earlier 52.1% figure was computed against the summed count; against
distinct traces the fraction is 57.1%.

**CORRECTION 3 — the export was not one operation.** Three files carry
mtime 00:30. `ts-order-service` carries **02:06**, four minutes after
`attack_demo_001` ran at 02:02. That file swept up the attack window.
`corpus_audit.py` finds **58 trace IDs appearing in files labelled both
`normal` and `attack`**. Of 67 real attack traces, only 13 are cleanly
labelled. This is label leakage. It cannot be filtered out, because which
traces were genuinely normal cannot be reconstructed.

Operations confirmed present (real booking flow, not infra noise):
`OrderController.createNewOrder`, `PreserveController.preserve`,
`SeatController.create`, `SeatController.getLeftTicketOfInterval`,
`SecurityController.check`, `PriceController.query`, `INSERT ts.orders`,
`INSERT ts.trip`, `INSERT ts.trip2`, plus DB SELECT/repository chains for
Order/Route/Station/TrainType/User/Trip/PriceConfig/SecurityConfig.

Parsed 2026-07-28 →
`data/processed/traces/spans.csv` (41,990 rows) and
`data/processed/traces/traces.csv` (1,374 rows) via
`scripts/preprocessing/parse_jaeger_traces.py`. **The 1,374-row
`traces.csv` contains duplicate traces.** Regenerate through
`build_feature_table.py`, which deduplicates on `(trace_id, span_id)`
across export files in one pass.

## Label
- Label: normal — **unreliable for the `ts-order-service` file**
- Attack class: none intended; attack traffic present via leakage

## Fan-out observation
Only 1.8% of real traces appear in all four export files; 79.8% appear in
just one. This is expected, not a defect: only 4 of 42 services were
queried, so a trace through gateway → travel → seat → config → route lands
in `ts-travel-service`'s export alone. Context propagation is working — the
median real trace holds 42 spans, which requires it.

## Known limitation: no valid entry-point stratification
Root spans report operation `POST /*` and `http.route=/*`. Spring's
catch-all mapping collapses every endpoint into one bucket, so
attack-vs-normal comparisons cannot yet be stratified by entry point.
Until the tag holding the real request path is identified
(`corpus_audit.py --dump-root-tags`), any pooled comparison measures
workload mix rather than behaviour.

## Notes for Phase 1
- Safe to develop the parser and feature pipeline against this data. Not
  safe to draw any comparative conclusion from it.
- `ts-travel-service` and `ts-travel2-service` are separate because
  Train-Ticket splits high-speed (G/D) from other train types (Z/T/K)
  across two backends with separate query endpoints. Keep this split in
  mind during feature extraction — one "trip" concept spans two service
  implementations depending on train type.
- Re-collection requirements, all now satisfiable: Badger persistence is
  live (2026-08-05); the export script sweeps all services; explicit
  `--start`/`--end` prevent window overlap; `corpus_audit.py` must report
  zero multi-label traces before data is used.
