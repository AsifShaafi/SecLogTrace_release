# SUT2 (TeaStore) — ssrf

> **Status: SCALED TO N=150, CLEAN (2026-09-17).** 152 attack / 152 normal,
> zero multi-label. Cross-system detection computed (see
> `docs/SUT2_ANALYSIS_DRAFT_20260917.md`). Pilot history retained below.

## Class definition
- CWE-918, server-side request forgery (INJECTED vulnerability).
- Attack target: `POST image/rest/image/fetchFromUrl` — the injected naive-sink
  endpoint (added to `ImageProviderEndpoint.java`, see
  `docs/design/SUT2_SSRF_INJECTION_DESIGN.md`). Fetches an attacker-supplied
  URL server-side with no validation.
- Normal target: `POST image/rest/image/getProductImages` — the benign image
  lookup. `ImageSize` payload is `"WIDTHxHEIGHT"` (e.g. `"400x400"`), NOT a
  named size (verified live 2026-09-17).
- Attack sub-types (weighted, mirroring SUT1): `ssrf_persistence` (3) reaches
  the persistence users table → DB; `ssrf_registry` (2); `ssrf_closed_port`
  (1) timeout.

## Collection
- Generator: `generate_sut2_traffic.py --class ssrf --mode pilot`
- 15 normal + 15 attack, 60s gap, separate export windows.
- Jaeger backend: local, in-memory (SUT2 standard).

## Audit / noise (N=150 scale)
- Raw distinct traces: 1795
- Infra noise (registry heartbeat, bare-verb `GET`/`PUT`, no `http_url` tag):
  1491 (83.1%)
- Real traces retained: 304 (152 normal + 152 attack). Zero multi-label.
- (Pilot: 467 distinct, 93.1% noise, 32 real.)

## Signal (trace-only)
- **Structural — attack ADDS spans**, the same locus as SUT1's SSRF.
  Normal (`getProductImages`) = 1 span. Attack (`fetchFromUrl`) = 2–4 spans:
  the `ssrf_persistence` sub-type chains image→persistence→DB (4 spans), the
  registry/closed-port sub-types are 2 spans. Median attack span_count 4 vs
  normal 1 (feature table and `corpus_audit.py` agree).
- SUT1 comparison: SUT1 SSRF span count 1→5 (adds an outbound call). SUT2 is
  1→4 — **same signal locus, generalizes cleanly.**
- Detection (trace-only RF F1, 5-fold, N=150): **SUT2 0.99** vs SUT1 1.00.
- Methodology note: unlike SUT1 (avatar service, same endpoint for normal and
  attack — a within-endpoint controlled comparison), SUT2's `fetchFromUrl` is
  a distinct injected endpoint from `getProductImages`, so the structural
  signal partly conflates "new endpoint" with SSRF behavior. The 4-span
  image→persistence→DB outbound chain is the genuine SSRF signature regardless.

## Files
- Raw: `data/raw/jaeger/sut2_ssrf_sut2_ssrf_{normal,attack}/`
- Parsed: `data/processed/traces/sut2_ssrf/{spans,traces}.csv`
- Features: `data/processed/combined/sut2_ssrf_features.csv`

## Known limitations
- Cross-endpoint (not within-endpoint) comparison — see methodology note above.
