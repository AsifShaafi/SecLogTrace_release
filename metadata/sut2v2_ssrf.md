# SUT2 (TeaStore) — ssrf — v2 (traces + logs)

> **Status: v2 corpus, N=500/label, CLEAN (2026-10-28).** 500 attack / 500
> normal traces, zero multi-label, log join 1000/1000. First SUT2 run with
> per-request application logs. Supersedes v1 `sut2_ssrf.md`.

## Class definition
- CWE-918, server-side request forgery (the one INJECTED vulnerability).
- Attack: `POST image/rest/image/fetchFromUrl` — the injected naive sink
  (`ImageProviderEndpoint.java`); fetches an attacker-supplied URL server-side
  with no validation.
- Normal: `POST image/rest/image/getProductImages` — benign image lookup.
- Attack sub-types (weighted, mirroring SUT1): `ssrf_persistence` (3, reaches
  the persistence users table → DB), `ssrf_registry` (2), `ssrf_closed_port`
  (1, timeout).

## Collection
- `collect_sut2_corpus.sh ssrf 500 0.5`.

## Modalities (v2)
- **Trace:** attack ADDS spans. Normal (`getProductImages`) = 1 span; attack
  (`fetchFromUrl`) = 2–4 (the `ssrf_persistence` chain image→persistence→DB is
  4). Median attack span_count ~3 vs normal 1.
- **Log:** the `fetchFromUrl` request-boundary ENTRY records the **target URL**
  in its arguments — direct evidence of the outbound destination. As with
  data_exfiltration, this is content, only partly reflected in count-based log
  features.

## Detection (RF F1, 5-fold, N=500)
| arm | F1 | note |
|---|---|---|
| trace | **1.00** | added outbound span chain separates cleanly |
| log | 0.67 | partial — count features catch the extra log volume, not the URL |
| combined | **1.00** | trace dominates |

SUT1 v2 ssrf: trace 1.00 / log 0.67 / combined 1.00 — identical arm profile.
Same signal locus (an added outbound call); generalizes cleanly.

## Files
- Features: `data/processed/combined/sut2v2_ssrf_features.csv`
- Per-trace logs: `data/processed/logs/sut2v2_ssrf/logs_by_trace.csv`
- Traces: `data/processed/traces/sut2v2_ssrf/{spans,traces}.csv`
- Traffic: `data/raw/traffic/sut2v2_ssrf_{normal,attack}_*.jsonl`
- Transcript: `docs/daily_logs/corpus_sut2v2_ssrf_20261028.md`

## Known limitations
- Cross-endpoint (not within-endpoint) comparison: `fetchFromUrl` is a distinct
  injected endpoint from `getProductImages`, so the structural signal partly
  conflates "new endpoint" with SSRF behaviour. The image→persistence→DB
  outbound chain is the genuine SSRF signature regardless.
