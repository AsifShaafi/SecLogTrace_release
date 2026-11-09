# SUT2 (TeaStore) — injection — v2 (traces + logs)

> **Status: v2 corpus, N=500/label, CLEAN (2026-10-28).** 500 attack / 500
> normal traces, zero multi-label. First SUT2 run with per-request application
> logs (request-boundary instrumentation; see TeaStore
> `LOGGING_INSTRUMENTATION.md`). Supersedes the v1 trace-only
> `sut2_injection.md` (N=150).

## Class definition
- CWE-89/943, injection attempt (no code change — malformed params on an
  existing endpoint).
- Shared target: `GET persistence/rest/products`.
  - Normal: `?start=0&max=10` — legitimate paged read → HTTP 200.
  - Attack: SQLi/NoSQLi/traversal/JNDI payloads in the int-typed `start`
    `@QueryParam` → HTTP 404 (JAX-RS int-coercion rejection = the
    injection-rejection signature).

## Collection
- `collect_sut2_corpus.sh injection 500 0.5` (pace safe to lower — signal is
  per-trace, not rate-based). Generator: `generate_sut2_traffic.py`.
- normal window → 60s gap → attack window → windowed Jaeger export + per-service
  `docker compose logs` capture → zero-leakage audit gate → parse → features.

## Modalities (v2)
- **Trace:** 29-feature schema (as v1).
- **Log:** attack requests are rejected at the framework **before the servlet
  method runs**, so they emit **no request-boundary log line**. Normal requests
  do. Log join: **500/1000** traces (all 500 normal, 0 attack) — the absence is
  the signal, not a gap.

## Signal
- **Trace:** DB-span absence + `sendError` span. span_count 2 for both; normal
  → `db_span_count 1` (SELECT), attack → `db_span_count 0` (rejected pre-DB).
  SUT2 spans carry no `http.status_code`, so the 404 is invisible to error
  features — only DB-span composition carries it.
- **Log:** presence/absence. `log_line_count` 0 (attack) vs >0 (normal)
  separates the classes perfectly on its own.

## Detection (RF F1, 5-fold, N=500)
| arm | precision | recall | F1 |
|---|---|---|---|
| trace | — | — | **1.00** |
| log | — | — | **1.00** |
| combined | — | — | **1.00** |

Both modalities independently separate this class. SUT1 v2 injection: trace
1.00 / log 1.00 / combined 1.00 — same two-modality separability.

## Files
- Features: `data/processed/combined/sut2v2_injection_features.csv`
- Per-trace logs: `data/processed/logs/sut2v2_injection/logs_by_trace.csv`
- Traces: `data/processed/traces/sut2v2_injection/{spans,traces}.csv`
- Traffic: `data/raw/traffic/sut2v2_injection_{normal,attack}_*.jsonl`
- Transcript: `docs/daily_logs/corpus_sut2v2_injection_20261028.md`
- Raw Jaeger/logs: `data/raw/{jaeger,logs}/sut2v2_injection_*` (gitignored)

## Known limitations
- Rejected-input, not successful exploitation — frame honestly. The F1 reflects
  "the malformed request never reached the DB / emitted no app log," not "SQL
  injection detected."
