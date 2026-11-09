# experiment_004 — Scripted Normal Baseline (reliability-check re-run)

> **Status: reliability-check collection.** Second scripted, reproducible
> baseline run, on a different calendar day from `experiment_003`
> (2026-08-21), using the generalized `scripts/collection/run_reliability_check.sh`
> (a parameterized version of `docs/daily_logs/phase1_recollection_20260820_commands.sh`).
> Paired with `attack_demo_004` — see that file for the joint
> `corpus_audit.py --by-filename-label` result. Purpose: confirm the
> pipeline produces consistent results across days, per
> `PHASE_1_CHECKLIST.md` item 8's last open item.

## Before collection
- Date/time window: 2026-08-26, 21:52:15 – 21:56:11 UTC (3m56s, exported
  padded to 21:51:15–21:57:11, 6 min)
- Purpose: reliability check — repeat the `experiment_003` collection on a
  different day and compare distributions with `baseline_stats.py`, to
  confirm the scripted pipeline (not just one lucky run) produces a usable,
  reproducible baseline
- Actions performed: 15 simulated sessions via
  `generate_baseline_traffic.py --sessions 15 --demo-user-ratio 0.3`
  (invoked by `run_reliability_check.sh`), same flow shape as
  `experiment_003`: register/login (or reuse demo account) → list stations
  → list routes → search trips across 6 station pairs with varied dates →
  book a ticket (if found) → query orders → assurance/food/consign lookups
  → one randomly-weighted mutating action (none/pay+execute/rebook/cancel)
- Station pairs sampled this run: shanghaihongqiao–hangzhou, nanjing–
  shanghai, wuxi–suzhou, zhenjiang–wuxi, shijiazhuang–taiyuan, shanghai–
  suzhou (a different sample than `experiment_003`'s — expected, the
  generator draws a fresh sample per invocation)
- Collector: `scripts/collection/run_reliability_check.sh` (new,
  generalized re-run of the 2026-08-20 commands script), invoked as
  `./scripts/collection/run_reliability_check.sh 2>&1 | tee
  docs/daily_logs/reliability_check_20260826_log.md`
- Session log: `data/raw/traffic/traffic_session_log_20260826_215215.jsonl`

## During collection
- Start: 2026-08-26T21:52:15Z, End: 2026-08-26T21:56:11Z
- All 15 sessions completed; every session that found a trip booked one
- Two `rebookservice/rebook/difference` 500s (sessions 5 and 10) —
  `rebook()` itself (same body shape) succeeded immediately after both
  times. Same reproducible anomaly first seen 2026-08-20/21, now 6 total
  observations across three independent collections. Still not chased
  further.
- `list_foods()` returned 0 options for the shanghaihongqiao→hangzhou
  route on every call this run, while nanjing→shanghai (also sampled this
  run) returned 2 options every time. This confirms the theory raised in
  `experiment_003`'s notes: the 0-options result is **route-specific**
  (some seeded routes have no food-service data), not a client bug — two
  independent collections now, each showing a different route with zero
  options while a different route in the same run returns real data.

## After collection
### Trace export
- Command: `export_jaeger_traces.sh --label normal --experiment
  experiment_004 --start "2026-08-26T21:51:15Z" --end
  "2026-08-26T21:57:11Z" --limit 20000`
- 42 services swept, no truncation
- Sum of per-service counts: 2,052 (never cite)
- **Distinct traces: 769**
- Duplicate entries: 1,283 (avg 2.67 services touched per trace — close to
  `experiment_003`'s 2.97, both well above `experiment_002`'s 1.07,
  consistent with the extended flows chaining more cross-service calls)

### Joint corpus audit (with attack_demo_004)
`corpus_audit.py 'data/raw/jaeger/experiment_004_normal/*.json'
'data/raw/jaeger/attack_demo_004_attack/*.json' --by-filename-label`:
- Combined distinct: 881, infra-noise-only: 491 (55.7%), real: 390
- **Traces carrying more than one label: 0** — the mandatory gate,
  confirmed clean again (third consecutive clean collection after
  `experiment_003`/`attack_demo_003`)
- This experiment's share: 363 real (noise: 406/769 = 52.8%)
- Root operations: attack=3, normal=28, shared=2

### Parsing
`parse_jaeger_traces.py`: 2,052 traces / 119,495 spans from 42 files, 406
(19.8%) pure infra noise.
`build_feature_table.py`: 769 in → **363 retained**, 29 features/trace.
Top root operations: `travelservice`/`travel2service` trips/left (90 each),
then `routeservice/routes` (16), assurance/login/preserve/consign/
contacts/order-query/station endpoints at 15 each — same shape as
`experiment_003`.
Output: `data/processed/combined/experiment_004_features.csv` (363 rows).

### Log capture and join
- `data/raw/logs/experiment_004/`: 46 files, 2 empty (news/voucher — one
  fewer empty file than `experiment_003`'s 4; ticket-office and admin-basic
  had traffic this run)
- `parse_service_logs.py --traces-csv`: **348/363 (95.9%)** real traces
  have ≥1 log line — identical join rate to `experiment_003`'s 355/370
  (95.9%). **100%** of logged trace_ids resolve to a real trace.
- Output: `data/processed/logs/experiment_004/logs.csv` (7,157 rows),
  `logs_by_trace.csv` (348 rows)

## Reliability comparison against experiment_003
Ran after fixing a broken dependency (see below):
```
python3 scripts/visualization/baseline_stats.py \
  --features data/processed/combined/experiment_003_features.csv \
             data/processed/combined/experiment_004_features.csv \
  --group-col experiment_id --compare --outdir results/reliability_check_experiment_004
```
- Entry-point coverage: 26 (experiment_003) vs 28 (experiment_004), 20
  shared.
- **Structural features (span_count, service_count, edge_count, max_depth,
  operation_count, max_fanout, unique_edge_count) reproduce well across
  days**: of 91 (entry-point × structural-feature) stratified comparisons,
  72 (79%) are negligible (Cliff's |δ| < 0.147, project threshold). The
  remainder are small, topping out at |δ|=0.333 on the two highest-volume
  entry points (`travel2service/trips/left`, n=90/90, and
  `preserveservice/preserve`, n=15/15) — right at the small/medium
  boundary, plausibly from real trip-availability differing by calendar
  date rather than a pipeline defect.
- **Timing features (durations) do not reproduce across days** — stratified
  |δ| up to 0.95 within the *same* entry point. Expected: wall-clock
  latency reflects live server/network load at collection time, not
  pipeline behavior. This is exactly why the project's stratification rule
  treats timing cautiously; do not use raw duration deltas across
  collections as a signal.
- Tables: `results/reliability_check_experiment_004/tables/{baseline_summary,baseline_by_root_operation,pooled_comparison,stratified_comparison}.csv`.
  Figures: `results/reliability_check_experiment_004/figures/`.

**Dependency bug found and fixed during this run**: `build_feature_table.py`
and `baseline_stats.py` both crashed with `ModuleNotFoundError: No module
named 'pandas'` (Steps 9–11) on the machine this reliability re-run was
executed from — `pandas`/`numpy`/`matplotlib` were never installed there,
and no `requirements.txt` in the repo covered `scripts/feature_extraction/`
or `scripts/visualization/` (only `scripts/collection/requirements.txt`
existed, `requests` only). By the time this surfaced, Steps 1–8 had
already run for real against the live gateway/Jaeger — a wasted round-trip
against shared infrastructure if the same run needed to be redone. Fixed
two ways: added `scripts/feature_extraction/requirements.txt` and
`scripts/visualization/requirements.txt` (`pandas>=2.3`, `numpy>=2.0`,
`matplotlib>=3.9` where applicable), and added a preflight import check to
`run_reliability_check.sh` so a missing dependency now fails before any
live traffic is generated, not after. The already-collected raw data for
this run did not need to be recollected — Steps 9–11 were re-run
standalone against the existing `data/raw/jaeger/experiment_004_normal/`
and `attack_demo_004_attack/` once the dependencies were installed.

## Also new this run: `baseline_stats.py`'s `--compare` generalized
Previously `--compare` only ever split on the `label` column (normal vs.
attack), which can't compare two same-label collections from different
days. Added `--group-col` (default `label`; pass `experiment_id` for a
reliability check) and made `--features` accept multiple CSVs (they're
concatenated) so a baseline and its reliability re-run can be compared in
one invocation without hand-merging CSVs first.

## Label
- Label: normal
- Attack class: none

## Notes for Phase 1
- **Closes `PHASE_1_CHECKLIST.md` item 8's last open item** (the
  reliability-check re-run) and, with it, Phase 1's exit criteria.
- Structural-feature reproducibility across days supports treating
  `experiment_003`/`attack_demo_003` (or a similar future scripted run) as
  a defensible frozen-corpus candidate on the structural feature families
  Phase 3 will actually model on; timing features should not be pooled
  across collections.
- Full commands + output transcript:
  `docs/daily_logs/reliability_check_20260826_log.md`.
