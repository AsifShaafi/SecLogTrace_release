# resource_exhaustion — Resource Exhaustion (CWE-400), corpus (N=150+150)

> **Status: corpus-scale, clean (zero label leakage).** Scaled from
> `resource_exhaustion_pilot` via `collect_abuse_corpus.sh
> resource_exhaustion 150` on 2026-09-04. See
> `metadata/resource_exhaustion_pilot.md` for method/design.

## Collection
- Windows (UTC, 2026-09-04): normal 06:29:16–06:34:30 (150 reqs, 0.48 req/s);
  60s gap; attack 06:35:32–06:35:51 (150 reqs, **8.01 req/s** burst).
- Endpoint (both, SAME fixed query nanjing→shanghai): `POST /api/v1/travelservice/trips/left`.
- Export: normal 609 distinct → **150 real**; attack 229 distinct → **150 real**.
- **Audit gate: zero multi-label traces.** Log join 100% both labels.

## Signal at scale (within the shared endpoint)
| feature | normal | attack |
|---|---|---|
| span_count | 172 | 172 |
| service_count | 10 | 10 |
| db_span_count | 37 | 37 |
| trace_duration_us | 91,984 | 90,084 |
| request rate | 0.48/s | **8.01/s** (~17×) |

**Correction vs the pilot:** structure is identical (172/10/37 — confirmed),
and the signal is **request RATE only**. The pilot's apparent "latency
degrades under load" (durations 2–4× higher) **did NOT reproduce at N=150** —
median trace_duration is essentially equal (92k vs 90k µs). That pilot effect
was a small-N artifact; at scale resource exhaustion changes neither
per-trace structure nor latency, only rate. Detection needs temporal/
volumetric (request-rate / inter-arrival) features; a per-trace detector is
blind to this class.

## Label
attack (paired normal window). Sub-type `resource_flood`.

## Note
Jaeger-query export-tool traces filtered as infra noise (fix 2026-09-04).
Transcript: `docs/daily_logs/corpus_resource_exhaustion_20260904.md`.

## Prior work (peer-reviewed)
Our method is conventional: scripting attacks into a benchmark for a labelled
corpus follows Zhou et al. (*IEEE TSE* 2021) and CIC-IDS2017 (labelled attack
generation, incl. DoS/resource-exhaustion); trace/log detection follows
DeepTraLog (*ICSE* 2022), TraceAnomaly (*ISSRE* 2020), Eadro (*ICSE* 2023),
Nezha (*ESEC/FSE* 2023). Full DOIs: `docs/DATA_STATEMENT.md` §12.
