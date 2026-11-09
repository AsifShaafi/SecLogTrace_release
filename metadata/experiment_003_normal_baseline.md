# experiment_003 — Scripted Normal Baseline (re-collection)

> **Status: first scripted baseline corpus candidate.** Collected with the
> extended `generate_baseline_traffic.py` (assurance/food/consign/cancel/
> rebook/execute/inside-payment flows added 2026-08-20) and the shared
> `stratification.py` helper. Paired with `attack_demo_003` — see that
> file for the joint `corpus_audit.py --by-filename-label` result. Not yet
> declared the frozen Phase 2 corpus; still needs the reliability-check
> re-run (a second collection on a different day) before that decision.

## Before collection
- Date/time window: 2026-08-21, 04:56:45 – 05:00:55 UTC (4m10s, exported
  padded to 04:55:45–05:01:55, 6 min)
- Purpose: replace `experiment_001` (dev data, label-leaked) and
  `experiment_002` (hand-clicked coverage/dev data, not reproducible) with
  a clean, scripted, re-runnable normal-traffic baseline — the last open
  item under PHASE_1_CHECKLIST.md item 8
- Actions performed: 15 simulated sessions via
  `generate_baseline_traffic.py --sessions 15 --demo-user-ratio 0.3`, each
  doing register/login (or reuse demo account, ~30%) → list stations →
  list routes → search trips across 6 station pairs with varied dates →
  book a ticket (if found) → query orders → **new extended flows**: list
  assurance types → list food options → list consigns by account → get
  consign by order → one randomly-weighted mutating action (none/pay+
  execute/rebook/cancel, weights 40/20/20/20)
- Collector: ran via `docs/daily_logs/phase1_recollection_20260820_commands.sh`
  on the server (kubectl + Jaeger + gateway all reachable there)
- Session log: `data/raw/traffic/traffic_session_log_20260821_045646.jsonl`

## During collection
- Start: 2026-08-21T04:56:45Z, End: 2026-08-21T05:00:55Z
- All 15 sessions completed; every session that found a trip booked one
- Two real `rebookservice/rebook/difference` 500s (sessions 9 and 13) —
  `rebook()` itself (same body shape) succeeded immediately after both
  times. Third and fourth observation of this exact anomaly (first two
  were during live verification of the extended flows, 2026-08-20) —
  reproducible, not a fluke. Not chased further; noted in `ts_client.py`.
- `list_foods()` returned 0 options on every call (15/15) for the
  nanjing→beijing route exercised this run — plausibly this route/date
  combination has no food service registered on this deployment, not a
  client bug (the endpoint itself returned 200 with an empty/null `data`
  each time, which `list_foods()` already handles correctly). Worth
  re-checking against a different route before concluding it's route-
  specific.

## After collection
### Trace export
- Command: `export_jaeger_traces.sh --label normal --experiment
  experiment_003 --start "2026-08-21T04:55:45Z" --end
  "2026-08-21T05:01:55Z" --limit 20000`
- 42 services swept, no truncation
- Sum of per-service counts: 2,398 (never cite)
- **Distinct traces: 808** (per `export_jaeger_traces.sh` on this
  experiment alone; combined with `attack_demo_003` in the same
  `corpus_audit.py` run below, distinct = 975 across both)
- Duplicate entries: 1,590 (avg 2.97 services touched per trace — notably
  higher fan-out than `experiment_002`'s 1.07 average, consistent with the
  new extended flows chaining more cross-service calls per booking)

### Joint corpus audit (with attack_demo_003)
`corpus_audit.py 'data/raw/jaeger/experiment_003_normal/*.json'
'data/raw/jaeger/attack_demo_003_attack/*.json' --by-filename-label`:
- Combined distinct: 975, infra-noise-only: 525 (53.8%), real: 450
- **Traces carrying more than one label: 0** — the mandatory gate before
  using this data. Confirmed clean, unlike `experiment_001`'s postmortem.
- This experiment's share: 370 real (noise: 438/808 = 54.2%)
- Root operations: attack=4, normal=26, shared=3. Within-shared-entry-point
  comparison available (see `attack_demo_003`'s metadata for the numbers) —
  this is the only valid attack-vs-normal comparison per the project's
  standing stratification rule.

### Parsing
`parse_jaeger_traces.py`: 2,398 traces / 154,709 spans from 42 files, 438
(18.3%) pure infra noise.
`build_feature_table.py`: 808 in → **370 retained**, 29 features/trace.
Top root operations: `travelservice`/`travel2service` trips/left (90
each — 15 sessions × 6 searches), then assurance/consign/contacts/station/
login/order-query endpoints at ~15-16 each (one call per session, as
expected from the new extended flows).
Output: `data/processed/combined/experiment_003_features.csv` (370 rows).

### Log capture and join
- `data/raw/logs/experiment_003/`: 46 files, 4 empty
  (avatar/news/ticket-office/voucher — same 4 services with zero traffic
  as `experiment_002`, consistent finding across two independent
  collections now)
- **Bug found and fixed during this run**: the collection script redirected
  `kubectl logs ... 2>&1`, which merged kubectl's own one-per-invocation
  stderr banner ("Defaulted container ... out of: ..., agent-container
  (init)") into every raw log file — 44 of 44 populated files, one line
  each. `parse_service_logs.py` correctly caught all 44 as `UNPARSED`
  rather than silently misparsing them, which is exactly what that
  fallback exists for. Fixed two ways: the collection script now uses
  `2>/dev/null` (won't recur), and `parse_service_logs.py` explicitly
  recognizes and classifies this line (so this run's already-captured
  data, which can't be hand-edited, still parses to 0 unparsed).
- `parse_service_logs.py --traces-csv`: **355/370 (95.9%)** real traces
  have ≥1 log line, **100%** of logged trace_ids resolve to a real trace.
- Output: `data/processed/logs/experiment_003/logs.csv` (8,813 rows),
  `logs_by_trace.csv` (355 rows)

## Label
- Label: normal
- Attack class: none

## Notes for Phase 1
- This is the first baseline collection to exercise the assurance/food/
  consign/cancel/rebook/execute/inside-payment flows added 2026-08-20 —
  confirms they work end-to-end in a real scripted (not just live-tested)
  collection run, not only the earlier manual verification.
- Still open: the reliability-check re-run (PHASE_1_CHECKLIST.md, "a
  second run on a different day, compare distributions") — cannot be done
  same-day by the checklist's own requirement.
- Full commands + output transcript:
  `docs/daily_logs/phase1_recollection_20260820_log.md`.
