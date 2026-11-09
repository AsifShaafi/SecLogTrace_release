# SUT2 (TeaStore) — resource_exhaustion

> **Status: SCALED TO N=150, CLEAN (2026-09-17).** 152 attack / 152 normal,
> zero multi-label. Cross-system detection computed (see
> `docs/SUT2_ANALYSIS_DRAFT_20260917.md`). Pilot history retained below.

## Class definition
- CWE-400, resource exhaustion.
- Target: `GET persistence/rest/products` (unpaced burst vs. paced normal
  traffic at the same endpoint — controlled within-endpoint comparison).
- Attack: same request, no delay between calls.
- Normal: same request, `--pace 2.0` (2s between requests).

## Collection
- Generator: `generate_sut2_traffic.py --class resource_exhaustion --mode pilot`
- 15 normal + 15 attack, 60s gap between windows, separate export windows.
- Jaeger backend: local, in-memory (SUT2 standard — see
  `docs/setup_notes/system_setup_teastore_jaeger.md`).

## Audit / noise (N=150 scale)
- Raw distinct traces: 1764
- Infra noise (registry heartbeat, bare-verb `GET`/`PUT`, no `http_url` tag):
  1460 (82.8%)
- **Real traces retained: 304 — 152 normal + 152 attack.** Zero multi-label
  (`corpus_audit.py --by-filename-label`).
- (Pilot: 290 distinct, 89.7% noise, 30 real (15/15).)

## Signal (within the single shared root endpoint)
- **Structure IDENTICAL** for both classes (span_count median 2/2, db_span 1/1)
  — confirmed at N=150, same as SUT1 (172/172). No per-trace structural signal.
- Root operation: single shared endpoint for both classes
  (`GET /tools.descartes.teastore.persistence/rest/products`) — the
  controlled within-endpoint comparison the class design called for.
- The real signal is **request RATE** (a session-level property), NOT captured
  in per-trace features — same as SUT1 (0.49 vs 13.33 req/s there).
- Detection (trace-only RF F1, 5-fold, N=150): **SUT2 0.57** vs SUT1 0.84.
  The residual score is an incidental, load-correlated timing shift; on SUT2 the
  2-span trace makes per-trace timing statistics high-variance and non-separable,
  whereas SUT1's 172-span traces give a stable timing aggregate. This is one of
  the two cross-system divergences — full reasoning:
  `docs/SUT2_ANALYSIS_DRAFT_20260917.md` §5b.

## Files
- Raw: `data/raw/jaeger/sut2_resource_exhaustion_sut2_resource_exhaustion_{normal,attack}/`
- Parsed: `data/processed/traces/sut2_resource_exhaustion/{spans,traces}.csv`
- Features: `data/processed/combined/sut2_resource_exhaustion_features.csv`

## Known limitations
- Timing-based comparison to SUT1 should be qualitative (rate ratio), not a
  literal cross-machine latency comparison — SUT2 runs on a local Windows
  laptop, SUT1 on the shared research server; absolute timings aren't
  comparable across that hardware/environment difference even if the
  request-rate *pattern* is.
- This class's noise-filtering fix (2026-09-17) is confirmed correct here,
  but was NOT yet re-verified in `corpus_audit.py` (only in
  `parse_jaeger_traces.py`) — see
  `docs/phase_logs/phase_log_20260917.md` §5.
