# resource_exhaustion_pilot — Resource Exhaustion (CWE-400), pilot

> **Status: clean pilot (N=15+15), method-validating, not corpus scale.**
> Collected with `scripts/collection/generate_abuse_traffic.py` following the
> SSRF template. Zero multi-label traces. Third of the five Phase 2 attack
> classes to reach a clean pilot (after SSRF and credential_abuse).

> **IMPORTANT — a first collection was discarded.** The first run rotated the
> normal-class station pair while the attack used one fixed pair, which
> produced a span-count gap (172 vs 82) driven purely by query selectivity —
> the exact workload confound behind the withdrawn 82-vs-46 finding. The
> generator was fixed (2026-09-04) so BOTH classes now fire the SAME fixed
> query (`nanjing->shanghai`), isolating request RATE as the only variable.
> This file describes the corrected re-collection.

## Before collection
- Date/time windows (UTC), from the session logs:
  - normal: 2026-09-04T01:11:25 – 01:11:55 (15 requests, ~2s human pace)
  - 60s gap (script-enforced)
  - attack: 2026-09-04T01:12:47 – 01:12:50 (15 requests, unpaced burst)
- Endpoint (both classes, controlled): `POST /api/v1/travelservice/trips/left`,
  the SAME query `nanjing->shanghai` on both sides.
- Purpose: pilot the resource-exhaustion class — a request flood vs. the same
  search at human pace — isolating request RATE (and any load-induced latency)
  with per-trace structure held constant.
- Actions: `generate_abuse_traffic.py --class resource_exhaustion --mode pilot`
  - normal: 15 human-paced searches, all HTTP 200 / resp_status=1
  - attack: 15 unpaced burst searches (sub-type `resource_flood`), all HTTP
    200 / resp_status=1 — measured 5.69 req/s vs normal 0.50 req/s
- Session logs: `data/raw/traffic/resource_exhaustion_pilot_{normal,attack}_20260904_011125.jsonl`

## After collection
### Trace export
- `export_jaeger_traces.sh --label {normal,attack} --experiment
  resource_exhaustion_pilot`, windows padded ~10s.
  - normal export window 01:11:15–01:12:05 UTC → **85 distinct**
  - attack export window 01:12:47–01:13:09 UTC → **50 distinct**

### Joint corpus audit (the mandatory gate)
- Combined distinct: 135, real: 30 (15+15).
- **Traces carrying more than one label: 0** — passes.
- Root operations: attack=1, normal=1, shared=1 — both hit
  `POST /* /api/v1/travelservice/trips/left` only.

### Signal characterization (within the shared endpoint)
Request rate (window-level, the primary signature):
- normal **0.50 req/s** vs attack **5.69 req/s** (~11×).

Per-trace features, normal (n=15) vs attack (n=15):

| feature | normal | attack | reading |
|---|---|---|---|
| span_count | 172 | 172 | **identical** — structure held constant (same query) |
| service_count | 10 | 10 | identical |
| db_span_count | 37 | 37 | identical |
| trace_duration_us | 102,562 | **188,016** | ~1.8× slower under load |
| span_dur_p95 | 11,272 | **44,478** | ~4× — queuing/contention in the burst |
| span_dur_mean | 5,575 | 10,261 | ~1.8× |
| error_span_count / http_5xx | 0 | 0 | no errors — the flood degrades latency, doesn't fail |

**One-paragraph signature:** Resource exhaustion is a **rate** signal, not a
per-trace-structure one. With the query held constant, span/service/DB counts
are identical between classes (172 / 10 / 37); the attack differs by request
rate (~11×) and by **latency degradation under load** — the same query runs
~1.8–4× slower in the burst (queuing/contention), with no errors. Detection
needs temporal/volumetric features (request rate, inter-arrival time) and/or
the duration inflation; a per-trace *structural* detector will not see this
class. Durations are timing features (project rule: treat cautiously), but
here the comparison is controlled — identical query and structure — so the
latency delta is legitimately load-induced, not a workload artifact. Contrast
with SSRF (*adds spans*) and credential abuse (*aborts early / fewer spans*):
resource exhaustion changes neither span count nor status, only rate+latency.

### Parsing & logs
- `build_feature_table.py`: 15 retained each (normal 70 / attack 35 infra
  noise dropped), 29 features/trace.
  `data/processed/combined/resource_exhaustion_pilot_{normal,attack}_features.csv`.
- `parse_service_logs.py`: **15/15 (100%)** real traces with ≥1 log line,
  both classes; 100% reverse.

## Label
- Label: attack (paired with the normal window)
- Attack class: `resource_exhaustion` (CWE-400); sub-type `resource_flood`

## Notes for Phase 2
- Corpus-ready to scale (~150+/class). Do NOT cite N=15 numbers as detection
  results.
- The rate signature lives at the window/session level; when scaling,
  preserve request timestamps so inter-arrival-time features can be built.
- Generator fix (same-query design) documented in
  `docs/design/ABUSE_CLASSES_COLLECTION_DESIGN.md` and the generator
  docstring. Pipeline overview: `docs/DATA_COLLECTION_PIPELINE.md`.
- Session: `docs/phase_logs/phase_log_20260903.md`.
