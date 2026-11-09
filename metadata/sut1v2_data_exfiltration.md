# SUT1 (Train-Ticket) — data_exfiltration — Sensitive Data Exposure (CWE-200) — v2 (traces + logs)

> **Status: v2 corpus, N=500/label, CLEAN.** 501 / 501 (normal / attack) real
> traces, zero multi-label (`corpus_audit.py --by-filename-label` GATE PASSED),
> 100% trace→log coverage. Collected on branch `corpus-v2`
> (2026-10-28/29). Supersedes v1 `metadata/data_exfiltration.md` (which stays as the frozen
> N=150 record).

## Class definition (CWE-200)
- Admin bulk-read endpoints (need admin token `admin`/`222222`; NEVER `admin/admin`):
  `adminorderservice/adminorder` (65), `admintravelservice/admintravel` (16),
  `adminuserservice/users` (69 incl. PII), `adminbasicservice/adminbasic/contacts` (66 incl. PII).
  - Normal: a legitimate admin reading routine operational dashboards.
  - Attack: admin-credentialed sweep of ALL sensitive tables (burst).

## Collection
- `collect_abuse_corpus.sh data_exfiltration 500` (SSRF: `collect_ssrf_corpus.sh 500 external/pic.jpg`),
  exported via `JAEGER_API=http://<node-ip>:30005/jaeger/ui/api` (node IP;
  the host port-forward was stale). normal window → 60s gap → attack window →
  windowed export → log capture → zero-multi-label audit → parse → feature table.
- Exact windows + per-request transcript: `docs/daily_logs/corpus_data_exfiltration_v2_20261029.md`.

## Signal (within the shared endpoint)
Signal is **breadth / volume**: endpoints touched 3→5, PII field reads 0→74, ~36× request rate. Per-trace span counts vary by endpoint (attack median 12, normal 19). Burst attack did **not** truncate (admin-read traces are small).

## Detection (RF F1, 5-fold)
trace **0.941** / log 0.666 / combined 0.942 (RF, 5-fold, n=1002).

## Files
- Features: `data/processed/combined/data_exfiltration_{normal,attack}_features.csv` (`experiment_id = sut1v2_data_exfiltration`)
- Per-trace logs: `data/processed/logs/data_exfiltration_{normal,attack}/logs_by_trace.csv`
- Traces (bulk, gitignored): `data/processed/traces/data_exfiltration_{normal,attack}/{spans,traces}.csv`
- Traffic: `data/raw/traffic/data_exfiltration_*_*.jsonl`
- Raw Jaeger (bulk, gitignored → Zenodo): `data/raw/jaeger/data_exfiltration_{normal,attack}/`

## Known limitations
- +1 incidental extra per label (501/501), matching the v1 convention.
