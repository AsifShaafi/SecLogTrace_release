# SUT2 (TeaStore) — resource_exhaustion — v2 (traces + logs)

> **Status: v2 corpus, N=500/label, CLEAN (2026-10-28).** 500 attack / 500
> normal traces, zero multi-label, log join 1000/1000. First SUT2 run with
> per-request application logs. Supersedes v1 `sut2_resource_exhaustion.md`.

## Class definition
- CWE-400, resource exhaustion.
- Shared target: `GET persistence/rest/products` (controlled within-endpoint
  comparison).
  - Attack: unpaced burst (pace 0).
  - Normal: `--pace 2.0` (2s between requests).

## Collection
- `collect_sut2_corpus.sh resource_exhaustion 500 2.0`. **Pace must stay 2.0:**
  the pace IS this class's rate contrast — normal ~0.50 req/s vs attack ~83
  req/s (~167×). Do not lower it for this class.

## Modalities (v2)
- **Trace:** structure **identical** for both (span_count median 2/2, db_span
  1/1) — no per-trace structural signal.
- **Log:** structure identical too — both emit the same request-boundary ENTRY.
  The signal is **rate** (a session-level property), present in neither the
  per-trace trace features nor the per-trace log features.

## Detection (RF F1, 5-fold, N=500)
| arm | F1 | note |
|---|---|---|
| trace | 0.57 | residual, load-correlated timing jitter; 2-span traces are high-variance |
| log | 0.13 | per-trace log counts are identical across classes |
| combined | 0.57 | neither per-trace modality carries a rate signal |

SUT1 v2 resource_exhaustion: trace 0.96 / log 0.22 / combined 0.96. SUT1's
long (100+ span) traces give a stable timing aggregate; SUT2's 2-span traces do
not. This is one of the two cross-system divergences — the rate signal needs a
session/window-level feature, not a per-trace one. See
`docs/CROSS_SYSTEM_ANALYSIS.md` §5b.

## Files
- Features: `data/processed/combined/sut2v2_resource_exhaustion_features.csv`
- Per-trace logs: `data/processed/logs/sut2v2_resource_exhaustion/logs_by_trace.csv`
- Traces: `data/processed/traces/sut2v2_resource_exhaustion/{spans,traces}.csv`
- Traffic: `data/raw/traffic/sut2v2_resource_exhaustion_{normal,attack}_*.jsonl`
- Transcript: `docs/daily_logs/corpus_sut2v2_resource_exhaustion_20261028.md`

## Known limitations
- Timing comparison to SUT1 is qualitative (rate ratio), not a literal
  cross-machine latency comparison (SUT2 = local laptop, SUT1 = research
  server).
- Detectability of this class needs a window-level rate feature; per-trace
  arms (trace, log, combined) are all near chance by construction.
