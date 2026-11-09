# credential_abuse — Credential Abuse (CWE-307), corpus (N=150+150)

> **Status: corpus-scale, clean (zero label leakage).** Scaled from
> `credential_abuse_pilot` via `scripts/collection/collect_abuse_corpus.sh
> credential_abuse 150` on 2026-09-04. See `metadata/credential_abuse_pilot.md`
> for full method/design; this file records the scaled collection.

## Collection
- Windows (UTC, 2026-09-04): normal 06:12:57–06:18:12 (150 reqs, 0.48 req/s);
  60s gap; attack 06:19:15–06:19:41 (150 reqs, 5.76 req/s burst).
- Endpoint (both classes): `POST /api/v1/users/login`.
- normal = successful demo-user logins; attack = auth failures
  (`cred_bruteforce` wrong-pw vs the real user, `cred_userenum` non-existent
  users). Never admin/admin.
- Export: normal 612 distinct → **150 real**; attack 255 distinct → **150 real**.
- **Audit gate: zero multi-label traces.** Log join 100% both labels.

## Signal at scale (within `POST /api/v1/users/login`)
| feature | normal | attack |
|---|---|---|
| span_count | 12 | **8** |
| db_span_count | 3 | **1** |
| trace_duration_us | 89,093 | 172,148 |
| error_span_count / http_5xx | 0 | 0 |
| request rate | 0.48/s | 5.76/s |

Confirms the pilot: *aborts early* — fewer spans and DB calls, **no status/
error signal** (bad login is HTTP 200). Detection = structure + log content +
rate.

## Label
attack (paired normal window). Sub-types `cred_bruteforce`, `cred_userenum`.

## Note
Jaeger-query traces (export-tool artifact) were filtered as infra noise
(fix 2026-09-04, `parse_jaeger_traces.py` INFRA_SERVICES) — see
`docs/phase_logs/phase_log_20260904.md`. Transcript:
`docs/daily_logs/corpus_credential_abuse_20260904.md`.

## Prior work (peer-reviewed)
Our method is conventional: scripting attacks into a benchmark for a labelled
corpus follows Zhou et al. (*IEEE TSE* 2021, Train-Ticket + injected faults)
and CIC-IDS2017 (controlled labelled attack generation, incl. brute-force);
trace/log detection follows DeepTraLog (*ICSE* 2022), TraceAnomaly (*ISSRE*
2020), Eadro (*ICSE* 2023), Nezha (*ESEC/FSE* 2023). Full DOIs:
`docs/DATA_STATEMENT.md` §12.
