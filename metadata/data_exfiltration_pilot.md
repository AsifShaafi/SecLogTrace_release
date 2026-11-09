# data_exfiltration_pilot — Data Exfiltration (CWE-200), pilot

> **Status: clean pilot (N=15+15), method-validating, not corpus scale.**
> Fifth and final Phase 2 attack class to reach a clean pilot (after SSRF,
> credential_abuse, resource_exhaustion, injection). Newly designed and built
> this session (no prior tooling). Collected with
> `scripts/collection/generate_abuse_traffic.py --class data_exfiltration`.
> Zero multi-label traces.

## Design (threat model)
Bulk read of sensitive tables via the admin API. The admin bulk-read
endpoints return WHOLE tables (verified 2026-09-04: `adminuserservice/users`
→ 69 user records incl. PII; `adminorderservice/adminorder` → 65 orders;
`adminbasicservice/adminbasic/contacts` → 66 contacts incl. names/doc-nums/
phones; `admintravelservice/admintravel` → 16). All require an admin bearer
token (403 without one).

- **normal:** a legitimate admin reading routine OPERATIONAL dashboards
  (orders, travels) at human pace — never the PII tables.
- **attack:** an admin-credentialed session sweeping ALL sensitive tables —
  crucially the PII ones (users, contacts) that routine ops never touch — in
  a burst, harvesting the dataset. Sub-typed per table (`exfil_orders`,
  `exfil_travels`, `exfil_users`, `exfil_contacts`).
- Uses `DEMO_ADMIN` (admin/222222) — SAFE; never admin/admin (that trips the
  injected `INVALID_PASSWORD_LENGTH_FAULT`).
- The shared endpoints (orders, travels) appear in both classes for a
  within-endpoint comparison; the PII endpoints are attack-only, like SSRF's
  targets.

## Before collection
- Date/time windows (UTC), from the session logs:
  - normal: 2026-09-04T03:55:56 – 03:56:26 (15 reads, ~2s pace, 0.50 req/s)
  - 60s gap (script-enforced)
  - attack: 2026-09-04T03:57:28 – 03:57:29 (15 reads, burst, 13.39 req/s)
- Endpoint family: `GET /api/v1/admin*service/*` (bulk reads).
- Actions: `generate_abuse_traffic.py --class data_exfiltration --mode pilot`
  - normal: 15 reads rotating orders/travels, all HTTP 200 / resp_status=1
  - attack: 15 reads rotating orders/travels/**users/contacts**, all HTTP
    200 / resp_status=1; per-read `resp_bytes`/`record_count` logged
- Session logs: `data/raw/traffic/data_exfiltration_pilot_{normal,attack}_20260904_035556.jsonl`

## After collection
### Trace export
- normal export window 03:55:46–03:56:36 UTC → **86 distinct** (sum 146)
- attack export window 03:57:18–03:57:39 UTC → **47 distinct** (sum 93)

### Joint corpus audit (the mandatory gate)
- Combined distinct: 133, real: 31 (normal 16, attack 15).
- **Traces carrying more than one label: 0** — passes.
- normal 16 includes one admin-login trace (`POST /users/login`) at session
  start — a legitimate part of the admin session, correctly labelled normal
  (no leakage).
- Root operations: attack=4, normal=3, shared=2.
- **Attack-only root operations = the two PII tables:**
  `GET /adminuserservice/users`, `GET /adminbasicservice/adminbasic/contacts`.

### Signal characterization
Session/window level (the primary signal):

| measure | normal | attack |
|---|---|---|
| distinct sensitive endpoints (breadth) | 2 | **4** |
| PII-table reads | **0** | **7** (users + contacts) |
| request rate | 0.50 req/s | **13.39 req/s** (~27×) |
| records read | 632 | 798 |
| response bytes | 312,602 | 259,997 |

Per-trace, within the SHARED endpoints (structurally identical):

| endpoint | normal (span/db) | attack (span/db) |
|---|---|---|
| `adminorderservice/adminorder` | 19 / 2 | 19 / 2 |
| `admintravelservice/admintravel` | 259 / 66 | 259 / 66 |

**One-paragraph signature:** Data exfiltration is primarily an **access-
pattern / breadth** signal, not a per-trace-structure one. A bulk read is
structurally identical whether a legit admin or an exfiltrator issues it
(adminorder 19 spans, admintravel 259 spans — the coverage-sweep outlier —
in both classes). What separates the attack is (1) **which endpoints are
hit** — the attack reads the PII tables (`users`, `contacts`) that routine
ops never touch, so those are attack-only root operations (the clearest,
per-trace-detectable signal); (2) **breadth** — 4 vs 2 distinct sensitive
tables in the window; and (3) **rate** — a ~27× burst. Notably, raw response
bytes did NOT separate the classes at N=15 (normal repeatedly read the large
order table), so volume alone is a weak discriminator — the endpoint set and
breadth are the strong ones. Contrast the five classes: SSRF *adds spans*,
credential abuse *aborts early*, resource exhaustion *is rate+latency only*,
injection *is log-content only*, data exfiltration *accesses sensitive tables
it shouldn't, broadly and fast* — five distinct signal shapes.

### Parsing & logs
- `build_feature_table.py`: normal 16 retained (70 infra noise dropped),
  attack 15 (32 dropped), 29 features/trace.
  `data/processed/combined/data_exfiltration_pilot_{normal,attack}_features.csv`.
- `parse_service_logs.py`: **16/16 and 15/15 (100%)** real traces with ≥1
  log line; 100% reverse.

## Label
- Label: attack (paired with the normal window)
- Attack class: `data_exfiltration` (CWE-200); sub-types `exfil_orders`,
  `exfil_travels`, `exfil_users`, `exfil_contacts`

## Notes for Phase 2
- Corpus-ready to scale (~150+/class). Do NOT cite N=15 numbers as detection
  results.
- Engineer for this class the ACCESS-BREADTH features: distinct sensitive
  endpoints per session, whether PII endpoints are touched, and read rate —
  session-level, not per-trace structural.
- Design + generator: `docs/design/ABUSE_CLASSES_COLLECTION_DESIGN.md`;
  pipeline overview: `docs/DATA_COLLECTION_PIPELINE.md`; session:
  `docs/phase_logs/phase_log_20260903.md`.
