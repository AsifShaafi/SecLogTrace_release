# SUT2 (TeaStore) — data_exfiltration — v2 (traces + logs)

> **Status: v2 corpus, N=500/label, CLEAN (2026-10-28).** 500 attack / 500
> normal traces, zero multi-label, log join 1000/1000. First SUT2 run with
> per-request application logs. Supersedes v1 `sut2_data_exfiltration.md`.

## Class definition
- CWE-200, bulk PII enumeration (no code change — abuse of an existing endpoint).
- Attack: `GET persistence/rest/users?start=0&max=-1` — bulk read of the whole
  user table (one call returns every record).
- Normal: `GET persistence/rest/users/{id}` — single-record read (real seed id
  discovered at runtime, e.g. 507).

## Collection
- `collect_sut2_corpus.sh data_exfiltration 500 0.5`.

## Modalities (v2)
- **Trace:** 29-feature schema. Normal single-record read = 1 span; attack bulk
  read = 2 spans (`GET .../rest/users` + `SELECT teadb.PERSISTENCEUSER`):
  span_count 1→2, db_span_count 0→1.
- **Log:** both paths log a request-boundary ENTRY; the discriminating detail
  is in the **arguments** — attack `[listAll] args=[0,-1]` (bulk) vs normal
  `[findById] args=[507]` (single). This is **content**, not a count: the
  current per-trace log features are counts (line/error/warn/service), so the
  log-only arm sees little here. Log-content features are future work.

## Signal / detection (RF F1, 5-fold, N=500)
| arm | F1 | note |
|---|---|---|
| trace | **1.00** | span/db-count breadth separates cleanly |
| log | 0.40 | count-based log features miss the args-content signal |
| combined | **1.00** | trace dominates |

SUT1 v2 data_exfiltration: trace 0.94 / log 0.67 / combined 0.94 (best:
combined). Same essence (single→bulk breadth); on SUT2 the trace arm alone is
saturating.

## Files
- Features: `data/processed/combined/sut2v2_data_exfiltration_features.csv`
- Per-trace logs: `data/processed/logs/sut2v2_data_exfiltration/logs_by_trace.csv`
- Traces: `data/processed/traces/sut2v2_data_exfiltration/{spans,traces}.csv`
- Traffic: `data/raw/traffic/sut2v2_data_exfiltration_{normal,attack}_*.jsonl`
- Transcript: `docs/daily_logs/corpus_sut2v2_data_exfiltration_20261028.md`

## Known limitations
- Normal and attack use different persistence endpoints (single-record vs
  collection) by design — the attack IS "call the bulk endpoint," so the
  root-operation difference is part of the signature, not a confound.
- The rich log signal (bulk `args=[0,-1]`) exists in the raw log stream but is
  not yet a feature — content-aware log features would move the log arm up.
