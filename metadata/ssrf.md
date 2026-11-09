# ssrf — Server-Side Request Forgery (CWE-918), corpus (N=150+150)

> **Status: corpus-scale, clean (zero label leakage).** Scaled from the SSRF
> pilot (2026-08-27) via `scripts/collection/collect_ssrf_corpus.sh 150` on
> 2026-09-04, using `external/pic.jpg` as the normal-class face image. SSRF is
> the injected class (a `src_url` sink in the forked `ts-avatar-service`) — see
> `docs/design/SSRF_INJECTION_DESIGN.md` and `SSRF_PILOT_FINDINGS.md`.

## Collection
- Windows (UTC, 2026-09-04): normal 07:41:09–08:00:41 (150 reqs, 0.13 req/s —
  slow because dlib face-detection on the image takes seconds per request);
  60s gap; attack 08:01:49–08:11:00 (150 reqs; the closed-port sub-target adds
  ~10s timeouts, so the window is minutes long).
- Endpoint (both, DIRECT on :17001, not gateway-routed):
  `POST /api/v1/avatar`. normal = base64 image upload (`external/pic.jpg`);
  attack = `src_url` at internal targets (`ssrf_db_reach`,
  `ssrf_internal_svc`, `ssrf_closed_port`).
- **normal returned HTTP 200 on all 150** (pic.jpg verified to pass dlib) —
  resolves the pilot's placeholder-500 confound.
- Export: normal 1796 distinct → **151 real**; attack 985 distinct → **150 real**.
  (normal +1 = a single benign avatar GET from the script's preflight, same
  endpoint — harmless.)
- **Audit gate: zero multi-label traces.** ts-avatar-service is Python/Flask,
  so its logs are UNPARSED (known parser gap); the trace side is SSRF's signal.

## Signal at scale (within `POST /api/v1/avatar`)
| feature | normal | attack |
|---|---|---|
| span_count | 1 | **5** |
| service_count | 1 | **2** |
| error_span_count | 0 | 2 |
| trace_duration_us | 5,849,546 (image processing) | 5,926 |

Confirms the injected-SSRF signature: normal is a single-span local operation
with **no outbound call**; attack **adds an outbound span** (2–8 depending on
sub-target) reaching across the mesh. The benign path's multi-second duration
is dlib image processing, not part of the SSRF signal — span structure is the
discriminator.

## Label
attack (paired normal window). Sub-types `ssrf_db_reach`, `ssrf_internal_svc`,
`ssrf_closed_port`.

## Note
Jaeger-query export-tool traces filtered as infra noise (fix 2026-09-04).
Transcript: `docs/daily_logs/corpus_ssrf_20260904.md`.

## Prior work (peer-reviewed)
SSRF is a studied attack, and the **inject-then-exercise** pattern we use is
conventional: Jabiyev et al. (*ACM SAC* 2021) study SSRF and evaluate a
defense by deploying deliberately vulnerable applications. Injecting a
vulnerability to build a ground-truth corpus follows Dolan-Gavitt et al.,
LAVA (*IEEE S&P* 2016) and Zhou et al. (*IEEE TSE* 2021, Train-Ticket +
injected faults). Trace/log detection follows DeepTraLog (*ICSE* 2022),
TraceAnomaly (*ISSRE* 2020), Eadro (*ICSE* 2023), Nezha (*ESEC/FSE* 2023).
Full DOIs: `docs/DATA_STATEMENT.md` §12.
