# SUT1 (Train-Ticket) — resource_exhaustion — Resource Exhaustion (CWE-400) — v2 (traces + logs)

> **Status: v2 corpus, N=500/label, CLEAN (re-collected same-session 2026-10-29).**
> 500 / 500 (normal / attack), zero multi-label (`corpus_audit.py
> --by-filename-label` GATE PASSED), 100% trace→log coverage.
> `experiment_id = sut1v2_resource_exhaustion`. Supersedes v1
> `metadata/resource_exhaustion.md` (frozen N=150 record).

## Class definition (CWE-400)
- Shared endpoint (both labels, SAME fixed query nanjing→shanghai):
  `POST /api/v1/travelservice/trips/left`.
  - Normal: human-paced searches (~0.5 req/s).
  - Attack: unpaced burst flood (rate IS the signal).

## Collection
- **Re-collected 2026-10-29 in ONE same-day session** (normal 07:08–07:26Z →
  60 s gap → attack burst 07:26–07:28Z), replacing the original split-day
  collection — see "Day-confound" below. Exported via
  `JAEGER_API=http://<node-ip>:30005/jaeger/ui/api` (node IP; host
  port-forward was stale).
- **Attack over-provisioned (1,500 fired → 1,044 gateway-rooted → 920 clean
  172-span)**, then sampled to exactly **500** (fixed seed 42); normal uses its
  full 500. Restricting to gateway-rooted, exactly-172-span traces makes the
  attack structurally identical to normal, so only the rate signal differs.
  Transcript / windows: the 2026-10-29 session-3 entry in
  `docs/phase_logs/phase_log_20261028.md`.

## Signal (within the shared endpoint)
Structure is **identical** (span_count 172/172); the signal is **request RATE**
(a session-level property), not per-trace structure or latency.

## Detection (RF F1, 5-fold, n=1000, clean same-day set)
trace **0.955** / log **0.70** / combined **0.96**. The trace/combined arms are
timing-driven (load-correlated, collection-sensitive); the log arm is weak. A
session/window-level rate feature lifts trace to ~1.00 in prototyping
(`scripts/detection/prototype_features.py`) — but that is a session-level
signal, not per-trace detection; frame accordingly.

## Day-confound found and fixed (threat-to-validity, resolved)
The ORIGINAL rex collection had normal (Wed 2026-10-28) and attack (Thu
2026-10-29) windows a day apart (the attack was re-collected during the Jaeger
recovery / over-provisioning). The HTTP `Date:` header weekday ("Wed"/"Thu") and
day number ("28"/"29") in the trace-correlated logs then **trivially separated
normal vs attack** — a de-leaked log-content TF-IDF scored a spurious 1.00. This
same-session re-collection removes it: naive log-content drops 1.00 → 0.70 (see
`scripts/detection/prototype_logcontent_deleaked.py`). The trace/combined F1 are
essentially unchanged (0.96), confirming the trace signal was the genuine timing
signal, not the day artifact.

## Files
- Features: `data/processed/combined/resource_exhaustion_{normal,attack}_features.csv`
- Per-trace logs: `data/processed/logs/resource_exhaustion_{normal,attack}/logs_by_trace.csv`
- Traces (bulk, gitignored): `data/processed/traces/resource_exhaustion_{normal,attack}/{spans,traces}.csv`
- Traffic: `data/raw/traffic/resource_exhaustion_*_*.jsonl`
- Raw Jaeger (bulk, gitignored → Zenodo): `data/raw/jaeger/resource_exhaustion_{normal,attack}/`

## Known limitations
- Detectability needs a window/session-level rate feature; per-trace arms are
  timing-driven and collection-sensitive.
- Log arm is weak (0.70) — see the corpus-wide log-content finding in
  `docs/DATA_STATEMENT.md` §10 (logs alone are a limited signal for these
  security anomalies).
