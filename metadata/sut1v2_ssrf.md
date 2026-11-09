# SUT1 (Train-Ticket) — ssrf — Server-Side Request Forgery (CWE-918) — v2 (traces + logs)

> **Status: v2 corpus, N=500/label, CLEAN.** 503 / 500 (normal / attack) real
> traces, zero multi-label (`corpus_audit.py --by-filename-label` GATE PASSED),
> 100% trace→log coverage. Collected on branch `corpus-v2`
> (2026-10-28/29). Supersedes v1 `metadata/ssrf.md` (which stays as the frozen
> N=150 record).

## Class definition (CWE-918)
- Target: `ts-avatar-service` (Python/Flask, port 17001, reached **directly** — not gateway-routable; internal/direct-access threat model). Injected `src_url` field triggers a naive server-side `urllib` fetch (no validation).
  - Normal: base64 upload of a real image (`external/pic.jpg`) — no outbound call.
  - Attack: `src_url` SSRF, three sub-types (db_reach, internal_svc, closed_port).

## Collection
- `collect_abuse_corpus.sh ssrf 500` (SSRF: `collect_ssrf_corpus.sh 500 external/pic.jpg`),
  exported via `JAEGER_API=http://<node-ip>:30005/jaeger/ui/api` (node IP;
  the host port-forward was stale). normal window → 60s gap → attack window →
  windowed export → log capture → zero-multi-label audit → parse → feature table.
- Exact windows + per-request transcript: `docs/daily_logs/corpus_ssrf_v2_20261029.md`.

## Signal (within the shared endpoint)
| feature | normal | attack |
|---|---|---|
| span_count (median) | 1 | **5** |

Normal = 1 span (no outbound call); SSRF **adds an outbound call** (2–8 spans). Sub-types: `ssrf_db_reach` (8-span chain to a DB SELECT), `ssrf_internal_svc` (2-span 404), `ssrf_closed_port` (2-span ~10s timeout).

## Detection (RF F1, 5-fold)
trace **1.00** / log 0.666 / combined **1.00** (RF, 5-fold, n=1003).

## Files
- Features: `data/processed/combined/ssrf_{normal,attack}_features.csv` (`experiment_id = sut1v2_ssrf`)
- Per-trace logs: `data/processed/logs/ssrf_{normal,attack}/logs_by_trace.csv`
- Traces (bulk, gitignored): `data/processed/traces/ssrf_{normal,attack}/{spans,traces}.csv`
- Traffic: `data/raw/traffic/ssrf_*_*.jsonl`
- Raw Jaeger (bulk, gitignored → Zenodo): `data/raw/jaeger/ssrf_{normal,attack}/`

## Known limitations
- Threat model is internal/direct-access (service not gateway-routable), state this in the paper. Attack window is slow (closed-port timeouts).
