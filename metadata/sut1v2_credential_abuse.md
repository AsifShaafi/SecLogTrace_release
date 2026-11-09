# SUT1 (Train-Ticket) — credential_abuse — Credential Abuse (CWE-307) — v2 (traces + logs)

> **Status: v2 corpus, N=500/label, CLEAN.** 500 / 500 (normal / attack) real
> traces, zero multi-label (`corpus_audit.py --by-filename-label` GATE PASSED),
> 100% trace→log coverage. Collected on branch `corpus-v2`
> (2026-10-28/29). Supersedes v1 `metadata/credential_abuse.md` (which stays as the frozen
> N=150 record).

## Class definition (CWE-307)
- Shared endpoint (both labels): `POST /api/v1/users/login`.
  - Normal: successful, human-paced logins of the demo user (`fdse_microservice`).
  - Attack: credential stuffing — `cred_bruteforce` (375) + `cred_userenum` (125).
  - Both return HTTP 200 (Train-Ticket returns 200 on bad login; `resp_status=0`).

## Collection
- `collect_abuse_corpus.sh credential_abuse 500` (SSRF: `collect_ssrf_corpus.sh 500 external/pic.jpg`),
  exported via `JAEGER_API=http://<node-ip>:30005/jaeger/ui/api` (node IP;
  the host port-forward was stale). normal window → 60s gap → attack window →
  windowed export → log capture → zero-multi-label audit → parse → feature table.
- Exact windows + per-request transcript: `docs/daily_logs/corpus_credential_abuse_v2_20261028.md`.

## Signal (within the shared endpoint)
| feature | normal | attack |
|---|---|---|
| span_count (median) | 12 | **8** |

Attack **aborts early** (fewer DB touches) — there is **no status-code signal** (200 either way); the signal is the span-count drop plus log content.

## Detection (RF F1, 5-fold)
trace **1.00** / log **1.00** / combined **1.00** (RF, 5-fold, n=1000).

## Files
- Features: `data/processed/combined/credential_abuse_{normal,attack}_features.csv` (`experiment_id = sut1v2_credential_abuse`)
- Per-trace logs: `data/processed/logs/credential_abuse_{normal,attack}/logs_by_trace.csv`
- Traces (bulk, gitignored): `data/processed/traces/credential_abuse_{normal,attack}/{spans,traces}.csv`
- Traffic: `data/raw/traffic/credential_abuse_*_*.jsonl`
- Raw Jaeger (bulk, gitignored → Zenodo): `data/raw/jaeger/credential_abuse_{normal,attack}/`

## Known limitations
- No HTTP error signal by construction; detection leans on span-count + log content.
