# injection_pilot — SQL/NoSQL Injection (CWE-89/943), pilot

> **Status: clean pilot (N=15+15), method-validating, not corpus scale.**
> Collected with `scripts/collection/generate_abuse_traffic.py` following the
> SSRF template. Zero multi-label traces. Fourth of the five Phase 2 attack
> classes to reach a clean pilot (after SSRF, credential_abuse,
> resource_exhaustion).

## Before collection
- Date/time windows (UTC), from the session logs:
  - normal: 2026-09-04T01:14:34 – 01:15:04 (15 requests, ~2s pace)
  - 60s gap (script-enforced)
  - attack: 2026-09-04T01:15:46 – 01:16:16 (15 requests, **same ~2s pace**)
- Endpoint (both classes, controlled): `POST /api/v1/travelservice/trips/left`.
- Purpose: pilot the injection class — malformed payloads in the station
  field vs. a legitimate search — isolating the INPUT (both sides use the
  same endpoint, same pacing, same `endPlace`; only `startPlace` differs).
  Injection is deliberately paced like normal (NOT bursted) so it is not
  confounded with the resource_exhaustion rate signal.
- Actions: `generate_abuse_traffic.py --class injection --mode pilot`
  - normal: 15 valid searches (`nanjing`->`shanghai`), HTTP 200 / resp_status=1
  - attack: 15 searches with SQLi/NoSQLi/path-traversal/JNDI/XSS payloads in
    `startPlace` (sub-typed by family: `inj_sqli`, `inj_nosqli`,
    `inj_pathtrav`, `inj_jndi`, `inj_xss`), **all HTTP 200 / resp_status=1
    "Success"** — the queries are parameterized; the payload is treated as a
    literal station name that matches nothing (0 trips), no error raised.
- Session logs: `data/raw/traffic/injection_pilot_{normal,attack}_20260904_011434.jsonl`

## After collection
### Trace export
- normal export window 01:14:24–01:15:14 UTC → **82 distinct**
- attack export window 01:15:56–01:16:45 UTC → **79 distinct**

### Joint corpus audit (the mandatory gate)
- Combined distinct: 161, real: 30 (15+15).
- **Traces carrying more than one label: 0** — passes.
- Root operations: attack=1, normal=1, shared=1 — both hit
  `POST /* /api/v1/travelservice/trips/left` only.

### Signal characterization (within the shared endpoint)
Per-trace features, normal (n=15) vs attack (n=15):

| feature | normal | attack | reading |
|---|---|---|---|
| span_count | 172 | 18 | attack much shorter — payload matches no station → 0 trips → no per-trip fan-out |
| service_count | 10 | 4 | fewer services touched |
| db_span_count | 37 | 2 | no per-trip DB lookups |
| http_span_count | 61 | 7 | no downstream trip/seat/price calls |
| error_span_count / http_5xx | 0 | 0 | **no error** — HTTP 200 / "Success" both |

**Key nuance — the structural gap is NOT a robust injection signal.** The
18-vs-172 span difference comes entirely from the attack returning **0
results** (the payload isn't a real station), and a *benign* search that
happens to return 0 results would look structurally identical. So trace
structure alone cannot tell an injection attempt from a legitimate empty
search.

**The robust, injection-specific signal is in the LOG CONTENT.** The payload
strings appear verbatim in `ts-basic-service` logs (e.g. `startPlace={"$ne
...`, `DROP TABLE`, `UNION SELECT`, `jndi:ldap`, `../../../../etc/passwd`,
`<script>`) — 10+ payload-bearing lines in the attack window, none in a
normal search. A benign empty search contains no such markers. **This makes
injection the strongest case in the corpus for the combined (trace+log)
detection arm:** the trace side is blind to it (looks like any empty query),
the log side sees it plainly. Characterize honestly — no injection actually
succeeded (parameterized queries); we are detecting the *attempt* pattern,
not an exploit.

### Parsing & logs
- `build_feature_table.py`: 15 retained each (normal 67 / attack 64 infra
  noise dropped), 29 features/trace.
  `data/processed/combined/injection_pilot_{normal,attack}_features.csv`.
- `parse_service_logs.py`: **15/15 (100%)** real traces with ≥1 log line,
  both classes; 100% reverse.
- NOTE: the raw `..._normal/` log dir over-captures (kubectl `--since-time`
  has no upper bound, so it includes attack-window lines); the trace_id join
  filters these out, and the trace-level audit confirms zero multi-label.

## Label
- Label: attack (paired with the normal window)
- Attack class: `injection` (CWE-89/943); sub-types `inj_sqli`, `inj_nosqli`,
  `inj_pathtrav`, `inj_jndi`, `inj_xss`

## Notes for Phase 2
- Corpus-ready to scale (~150+/class). Do NOT cite N=15 numbers as detection
  results.
- When scaling, the log-content feature (payload markers) is the one to
  engineer for this class — the per-trace structural features will not
  separate it from benign empty searches.
- Generator design (paced attack, fixed valid normal query) documented in
  `docs/design/ABUSE_CLASSES_COLLECTION_DESIGN.md`. Pipeline overview:
  `docs/DATA_COLLECTION_PIPELINE.md`. Session:
  `docs/phase_logs/phase_log_20260903.md`.
