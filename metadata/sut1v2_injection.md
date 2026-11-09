# SUT1 (Train-Ticket) — injection — SQL/NoSQL Injection (CWE-89 / CWE-943) — v2 (traces + logs)

> **Status: v2 corpus, N=500/label, CLEAN.** 500 / 500 (normal / attack) real
> traces, zero multi-label (`corpus_audit.py --by-filename-label` GATE PASSED),
> 100% trace→log coverage. Collected on branch `corpus-v2`
> (2026-10-28/29). Supersedes v1 `metadata/injection.md` (which stays as the frozen
> N=150 record).

## Class definition (CWE-89 / CWE-943)
- Shared endpoint: `POST /api/v1/travelservice/trips/left`.
  - Normal: legitimate-station searches (return real trips).
  - Attack: malformed-station payloads (SQLi/NoSQLi/path/JNDI/XSS families).

## Collection
- `collect_abuse_corpus.sh injection 500` (SSRF: `collect_ssrf_corpus.sh 500 external/pic.jpg`),
  exported via `JAEGER_API=http://<node-ip>:30005/jaeger/ui/api` (node IP;
  the host port-forward was stale). normal window → 60s gap → attack window →
  windowed export → log capture → zero-multi-label audit → parse → feature table.
- Exact windows + per-request transcript: `docs/daily_logs/corpus_injection_v2_20261029.md`.

## Signal (within the shared endpoint)
| feature | normal | attack |
|---|---|---|
| span_count (median) | 172 | **18** |

Malformed queries return empty → short traces. **Characterize honestly:** the trace signal is "a query returned nothing" (the 0-results artifact), NOT robust SQLi detection; the robust signal is **log content** (payloads appear in logs).

## Detection (RF F1, 5-fold)
trace **1.00** / log **1.00** / combined **1.00** (RF, 5-fold, n=1000).

## Files
- Features: `data/processed/combined/injection_{normal,attack}_features.csv` (`experiment_id = sut1v2_injection`)
- Per-trace logs: `data/processed/logs/injection_{normal,attack}/logs_by_trace.csv`
- Traces (bulk, gitignored): `data/processed/traces/injection_{normal,attack}/{spans,traces}.csv`
- Traffic: `data/raw/traffic/injection_*_*.jsonl`
- Raw Jaeger (bulk, gitignored → Zenodo): `data/raw/jaeger/injection_{normal,attack}/`

## Known limitations
- Trace-only separability is the empty-result artifact, not injection semantics.
