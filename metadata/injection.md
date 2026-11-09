# injection — SQL/NoSQL Injection (CWE-89/943), corpus (N=150+150)

> **Status: corpus-scale, clean (zero label leakage).** Scaled from
> `injection_pilot` via `collect_abuse_corpus.sh injection 150` on
> 2026-09-04. See `metadata/injection_pilot.md` for method/design.

## Collection
- Windows (UTC, 2026-09-04): normal 07:03:09–07:08:21 (150 reqs, 0.48 req/s);
  60s gap; attack 07:09:24–07:14:26 (150 reqs, 0.50 req/s — **paced like
  normal**, so rate is held constant and only the input differs).
- Endpoint (both): `POST /api/v1/travelservice/trips/left`; normal = valid
  station, attack = SQLi/NoSQLi/path-traversal/JNDI/XSS payloads in startPlace.
- Export: normal 603 distinct → **150 real**; attack 612 distinct → **150 real**.
- **Audit gate: zero multi-label traces.** Log join 100% both labels.

## Signal at scale (within the shared endpoint)
| feature | normal | attack |
|---|---|---|
| span_count | 172 | 18 |
| db_span_count | 37 | 2 |
| trace_duration_us | 76,718 | 12,844 |
| error_span_count / http_5xx | 0 | 0 |

Confirms the pilot. All payloads return HTTP 200 (queries are parameterized;
no injection succeeds). The span/DB gap (18 vs 172) is the **0-results
effect** — a benign empty search would look the same — so it is **not** a
robust injection signal. The robust, injection-specific signal is
**log content**: payload strings (`$ne`, `DROP TABLE`, `UNION SELECT`,
`jndi:ldap`, `etc/passwd`, `<script>`) appear in `ts-basic-service` logs,
absent from normal. **Strongest case in the corpus for the combined trace+log
arm** — traces blind, logs plain.

## Label
attack (paired normal window). Sub-types `inj_sqli`, `inj_nosqli`,
`inj_pathtrav`, `inj_jndi`, `inj_xss`.

## Note
Jaeger-query export-tool traces filtered as infra noise (fix 2026-09-04).
Transcript: `docs/daily_logs/corpus_injection_20260904.md`.

## Prior work (peer-reviewed)
Our method is conventional: scripting attacks into a benchmark for a labelled
corpus follows Zhou et al. (*IEEE TSE* 2021) and CIC-IDS2017 (labelled attack
generation, incl. web attacks); trace/log detection follows DeepTraLog
(*ICSE* 2022), TraceAnomaly (*ISSRE* 2020), Eadro (*ICSE* 2023), Nezha
(*ESEC/FSE* 2023). Full DOIs: `docs/DATA_STATEMENT.md` §12.
