# attack_demo_003 — Preliminary Attack Traffic (re-collection)

> **Status: PRELIMINARY/DEMO data, not the frozen Phase 2 corpus.** Covers
> the 3 non-SSRF demo classes already in `generate_attack_traffic.py`
> (auth_abuse, resource_exhaustion, injection_attempt). SSRF is the primary
> attack class for Phase 2 and is being handled separately (forked-service
> endpoint injection, not yet complete as of this collection). Replaces
> `attack_demo_001`, which had 81% label leakage from an export-window
> overlap — see `PHASE_STATUS.md`'s corpus-numbers table.

## Before collection
- Date/time window: 2026-08-21, 05:06:24 – 05:06:29 UTC (**5 seconds** —
  expected, not a bug: none of the 3 demo classes use `human_pause()`
  between requests by design, since unpaced request timing is itself part
  of the resource_exhaustion/auth_abuse signature. 60 total requests at
  effectively network-latency-bound speed. Confirmed in-run:
  `resource_exhaustion`'s own burst measured 26.4 req/s)
- Purpose: re-collect the attack-demo dataset cleanly, ≥5 min after the
  paired `experiment_003` baseline run ended, to avoid the exact
  export-window-overlap defect that contaminated `attack_demo_001`
- Actions performed: `generate_attack_traffic.py --class all --count 20`:
  - `auth_abuse`: 20 failed logins against `fdse_microservice` with wrong
    passwords, all HTTP 200 / `response_status=0` (login rejected but the
    endpoint itself didn't error)
  - `resource_exhaustion`: 20 unpaced identical searches
    (nanjing→shanghai), 0.76s total, 26.4 req/s
  - `injection_attempt`: 20 requests cycling 8 SQLi/NoSQLi/XSS/path-
    traversal/JNDI payloads through the station-search field, all HTTP 200
    (the field accepted the payload as a literal string; no client-visible
    breakage, as expected — this classes on request pattern, not outcome)
- Collector: same run as `experiment_003`, via
  `docs/daily_logs/phase1_recollection_20260820_commands.sh`
- Session log: `data/raw/attack_demo/attack_demo_session_log_20260821_050624.jsonl`

## During collection
- Gap since the normal-window export ended: 5 min (script-enforced,
  `GAP_SECONDS=300`) — the exact discipline `experiment_001`'s postmortem
  said was missing
- No errors during generation itself; all 60 requests completed

## After collection
### Trace export
- Command: `export_jaeger_traces.sh --label attack --experiment
  attack_demo_003 --start "2026-08-21T05:05:24Z" --end
  "2026-08-21T05:07:29Z" --limit 20000`
- 42 services swept, no truncation
- Sum of per-service counts: 230 (never cite)
- **Distinct traces: 167**
- Duplicate entries: 63 (avg 1.38 services touched per trace)

### Joint corpus audit (with experiment_003) — see that file for the full
combined numbers. This experiment's share:
- Real (non-noise): **80** (noise: 87/167 = 52.1%)
- **Zero multi-label traces** confirmed in the same combined run — this
  and `experiment_003` do not overlap
- Root operations seen: 4 total (`travelservice`/`travel2service`
  trips/left, `users/login`, and one path where the raw span
  `operationName` was already a full path rather than Spring's `POST /*`
  wildcard — `root_operation` then shows the operation name and the
  normalized URL concatenated, e.g. "POST /api/v1/travelservice/trips/left
  /api/v1/travelservice/trips/left" (n=17). Cosmetic duplication in the
  label, not a stratification bug — confirmed present in the pre-refactor
  logic too (this is the same `root_operation_from_parts()` combination
  rule extracted to `stratification.py` on 2026-08-20, unchanged
  behavior). Worth trimming in a future pass if it fragments Phase 3
  feature groups, not blocking now.
- **Within-shared-entry-point comparison** (the only valid attack-vs-
  normal comparison, per the project's stratification rule):

  | root_operation | attack (n, median spans) | normal (n, median spans) |
  |---|---|---|
  | `POST /* .../travel2service/trips/left` | n=20, med=9 | n=90, med=78 |
  | `POST /* .../travelservice/trips/left` | n=23, med=3 | n=90, med=82 |
  | `POST /* .../users/login` | n=20, med=8 | n=15, med=12 |

  Attack traces at the same entry point run consistently *fewer* spans
  than normal traces — plausible given `auth_abuse`/`injection_attempt`
  requests fail fast (rejected login, no matching trips) rather than
  fanning out through the full booking chain. Interesting early signal,
  **not a claim** — n is small and this is demo data, not the frozen
  corpus.

### Parsing
`parse_jaeger_traces.py`: 230 traces / 1,145 spans, 87 (37.8%) infra noise.
`build_feature_table.py`: 167 in → **80 retained**, 29 features/trace.
Output: `data/processed/combined/attack_demo_003_features.csv` (80 rows).

### Log capture and join
- `data/raw/logs/attack_demo_003/`: 46 files, same 4 empty
  (avatar/news/ticket-office/voucher)
- Same kubectl-banner artifact as `experiment_003` (see that file) — found
  and fixed the same way; this experiment's `logs.csv` also regenerated to
  0 unparsed.
- `parse_service_logs.py --traces-csv`: **80/80 (100%)** real traces have
  ≥1 log line, **100%** of logged trace_ids resolve to a real trace.
- Output: `data/processed/logs/attack_demo_003/logs.csv` (430 rows),
  `logs_by_trace.csv` (80 rows)

## Label
- Label: attack
- Attack classes: `auth_abuse`, `resource_exhaustion`, `injection_attempt`
  — **not** SSRF, data-exfiltration, or DoS (all deferred to the frozen
  Phase 2 corpus)

## Notes for Phase 1/2
- This is demo/preliminary data (per `generate_attack_traffic.py`'s own
  framing) — useful for pipeline validation and the within-entry-point
  comparison above, but not a substitute for the frozen multi-class Phase 2
  corpus, which still needs the SSRF endpoint (in progress separately) and
  the data-exfiltration/DoS classes (not yet built).
- Full commands + output transcript:
  `docs/daily_logs/phase1_recollection_20260820_log.md`.
