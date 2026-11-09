# data_exfiltration — Data Exfiltration (CWE-200), corpus (N=150+150)

> **Status: corpus-scale, clean (zero label leakage).** Scaled from
> `data_exfiltration_pilot` via `collect_abuse_corpus.sh data_exfiltration
> 150` on 2026-09-04. See `metadata/data_exfiltration_pilot.md` for
> method/design.

## Collection
- Windows (UTC, 2026-09-04): normal 07:32:53–07:38:04 (150 reqs, 0.48 req/s);
  60s gap; attack 07:39:06–07:39:15 (150 reqs, **17.47 req/s** burst).
- Endpoint family: `GET /api/v1/admin*service/*` (bulk reads, admin token).
  normal = operational dashboards (orders, travels); attack = sweep of ALL
  sensitive tables incl. PII (users, contacts). DEMO_ADMIN (222222).
- Export: normal 602 distinct → **151 real**; attack 229 distinct → **151 real**
  (the +1 per window is the admin-login trace at session start — legit).
- **Audit gate: zero multi-label traces.** Log join 100% both labels.

## Signal at scale
| measure | normal | attack |
|---|---|---|
| distinct sensitive endpoints (breadth) | 3 | **5** |
| PII-table reads (users + contacts) | **0** | **74** |
| request rate | 0.48/s | **17.47/s** |

Per-trace, the shared endpoints are structurally identical (a bulk read is a
bulk read regardless of who issues it). Confirms the pilot: exfiltration is an
**access-pattern** signal — which endpoints are hit (the PII tables are
attack-only root operations), breadth, and rate — **not** per-trace structure
and **not** raw bytes. Engineer session-level access-breadth features for
this class.

## Label
attack (paired normal window). Sub-types `exfil_orders`, `exfil_travels`,
`exfil_users`, `exfil_contacts`.

## Note
Jaeger-query export-tool traces filtered as infra noise (fix 2026-09-04).
Transcript: `docs/daily_logs/corpus_data_exfiltration_20260904.md`.

## Prior work (peer-reviewed)
Our method is conventional: scripting attacks into a benchmark for a labelled
corpus follows Zhou et al. (*IEEE TSE* 2021) and CIC-IDS2017 (labelled attack
generation, incl. infiltration/exfiltration); trace/log detection follows
DeepTraLog (*ICSE* 2022), TraceAnomaly (*ISSRE* 2020), Eadro (*ICSE* 2023),
Nezha (*ESEC/FSE* 2023). Full DOIs: `docs/DATA_STATEMENT.md` §12.
