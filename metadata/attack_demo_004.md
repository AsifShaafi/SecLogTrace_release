# attack_demo_004 — Preliminary Attack Traffic (reliability-check re-run)

> **Status: PRELIMINARY/DEMO data, not the frozen Phase 2 corpus.** Same 3
> non-SSRF demo classes as `attack_demo_003` (auth_abuse,
> resource_exhaustion, injection_attempt), re-collected on a different
> calendar day as the attack-side half of the Phase 1 reliability check.
> Paired with `experiment_004`.

## Before collection
- Date/time window: 2026-08-26, 22:01:36 – 22:01:41 UTC (**5 seconds** —
  expected, same reasoning as `attack_demo_003`: none of the 3 demo classes
  pace requests, since unpaced timing is itself part of the
  resource_exhaustion/auth_abuse signature)
- Purpose: repeat the attack-demo half of the corpus alongside
  `experiment_004`, ≥5 min after the normal-window export ended, preserving
  the export-window discipline that fixed `attack_demo_001`'s 81% label
  leakage
- Actions performed: `generate_attack_traffic.py --class all --count 20`
  (invoked by `run_reliability_check.sh`):
  - `auth_abuse`: 20 failed logins against `fdse_microservice`, all HTTP
    200 / `response_status=0`
  - `resource_exhaustion`: 20 unpaced identical searches, 0.74s total,
    27.0 req/s (close to `attack_demo_003`'s 26.4 req/s)
  - `injection_attempt`: 20 requests cycling 8 SQLi/NoSQLi/XSS/path-
    traversal/JNDI payloads through the station-search field, all HTTP 200
- Collector: same run as `experiment_004`, via
  `scripts/collection/run_reliability_check.sh`
- Session log: `data/raw/attack_demo/attack_demo_session_log_20260826_220136.jsonl`

## During collection
- Gap since the normal-window export ended: 5 min (script-enforced,
  `--gap-seconds 300` default)
- No errors during generation itself; all 60 requests completed

## After collection
### Trace export
- Command: `export_jaeger_traces.sh --label attack --experiment
  attack_demo_004 --start "2026-08-26T22:00:36Z" --end
  "2026-08-26T22:02:41Z" --limit 20000`
- 42 services swept, no truncation
- Sum of per-service counts: 118 (never cite)
- **Distinct traces: 112**
- Duplicate entries: 6 (avg 1.05 services touched per trace — close to
  `attack_demo_003`'s 1.38)

### Joint corpus audit (with experiment_004) — see that file for the full
combined numbers. This experiment's share:
- Real (non-noise): **27** (noise: 85/112 = 75.9%)
- **Zero multi-label traces** confirmed in the same combined run
- Root operations seen: 3 (`travel2service/trips/left`, `users/login`,
  and a third minor path)
- **Within-shared-entry-point comparison** (the only valid attack-vs-
  normal comparison, per the project's stratification rule):

  | root_operation | attack (n, median spans) | normal (n, median spans) |
  |---|---|---|
  | `POST /* .../travel2service/trips/left` | n=20, med=9 | n=90, med=42 |
  | `POST /* .../users/login` | n=6, med=8 | n=15, med=12 |

  Same direction as `attack_demo_003`'s comparison (attack traces run
  fewer spans than normal at the same entry point) — consistent across two
  independent collections now. Still an observation, not a claim: n is
  small and this is demo data, not the frozen Phase 2 corpus.

### Parsing
`parse_jaeger_traces.py`: 118 traces / 364 spans, 85 (72.0%) infra noise.
`build_feature_table.py`: 112 in → **27 retained**, 29 features/trace.
Output: `data/processed/combined/attack_demo_004_features.csv` (27 rows).

### Log capture and join
- `data/raw/logs/attack_demo_004/`: 46 files, 3 empty (news/ticket-office/
  voucher)
- `parse_service_logs.py --traces-csv`: **27/27 (100%)** real traces have
  ≥1 log line, same as `attack_demo_003`'s 80/80 (100%). 27/80 (33.8%) of
  logged trace_ids resolve to a real trace in this direction (lower than
  `attack_demo_003`'s 100% — expected, since more distinct trace_ids appear
  in the logs than survived the infra-noise filter into `traces.csv`; every
  real trace is still covered).
- Output: `data/processed/logs/attack_demo_004/logs.csv` (386 rows),
  `logs_by_trace.csv` (80 rows)

## Label
- Label: attack
- Attack classes: `auth_abuse`, `resource_exhaustion`, `injection_attempt`
  — **not** SSRF, data-exfiltration, or DoS (all deferred to the frozen
  Phase 2 corpus)

## Notes for Phase 1/2
- Demo/preliminary data, same caveats as `attack_demo_003`: useful for
  pipeline validation and the within-entry-point comparison above, not a
  substitute for the frozen multi-class Phase 2 corpus.
- Paired with `experiment_004` to close `PHASE_1_CHECKLIST.md` item 8's
  reliability-check item — see that file for the structural-vs-timing
  reproducibility comparison against `experiment_003`.
- Full commands + output transcript:
  `docs/daily_logs/reliability_check_20260826_log.md`.
