# Cross-System Detection Analysis (SUT1 + SUT2, traces + logs)

Analysis of the corpus (both systems at N=500/label, traces **and** logs): the
cross-system generalization and modality-comparison result.

Companion artifacts:
- Feature tables: `data/processed/combined/sut1v2_<class>_*.csv`,
  `data/processed/combined/sut2v2_<class>_features.csv`
- Detection results: `results/tables/detection_results.csv` (SUT1),
  `results/tables/detection_results_sut2_v2.csv` (SUT2)
- Cross-system comparison: `results/tables/cross_system_comparison.csv`
- Per-class metadata: `metadata/sut1v2_<class>.md`, `metadata/sut2v2_<class>.md`
- Log-arm probes: `scripts/detection/prototype_features.py`,
  `scripts/detection/prototype_logcontent_deleaked.py`
- Figures (`scripts/visualization/make_paper_figures.py`, PDF + PNG):
  `fig1_detection_heatmap` (SUT1 class×arm), `fig5_detection_heatmap_sut2`
  (SUT2 class×arm), `fig3_cross_system` (SUT1 vs SUT2), `fig4_detector_comparison`
  (rf≈hgb), `fig2_trace_signatures`

All F1 is the **attack class**, 5-fold stratified (seed 42), one feature row per
trace. Four detectors: `rule` (depth-3 tree), `iforest` (unsupervised, fit on
normal), `rf` (random forest), `hgb` (HistGradientBoosting). Headline numbers
are `rf`; the `rf`/`hgb` agreement is itself a finding (§4).

---

## 1. Question and setup

SUT1 (Train-Ticket) establishes that each class's discriminative signal lives in
a different feature family, and that some high scores rest on collection
artifacts rather than the attack mechanism. The cross-system question is whether
those *signal loci* are properties of the attack class or of the system. We
replicate all five CWE-mapped classes on **TeaStore** (SUT2) — Java,
service-registry discovery, a separate persistence tier — architecturally
distinct from Train-Ticket.

TeaStore was instrumented with per-request request-boundary
logging (AspectJ load-time weave; see TeaStore `LOGGING_INSTRUMENTATION.md`).
Both systems run the **same three arms**
(trace / log / combined), so the modality comparison (RQ2) is cross-system,
not SUT1-only.

## 2. Corpus (N=500/label)

| System | classes | real traces | per-class | multi-label |
|---|---|---|---|---|
| SUT1 (Train-Ticket) | 5 | 5,005 | ~500/500 (rex pooled to 500/500) | 0 |
| SUT2 (TeaStore) | 5 | 6,000 | 500/500 (cred_abuse 1000/1000, ~2 traces/login) | 0 |

Log↔trace join is ~100% on both systems with two exceptions: **injection on
SUT2** (500/1000: attack requests are rejected before the servlet method runs
and emit no log line — the absence is the signal, §6.3), and **request-forgery
on SUT1**, whose benign class reaches only the uninstrumented Python sink (0%
normal / 50% attack correlated-log rate; stratum `source_not_instrumented`, its
log-only and combined arms withdrawn).

## 3. Detection (RF F1 per class × arm, SUT1 / SUT2)

| Class | trace | log | combined | best arm |
|---|---|---|---|---|
| ssrf | 1.00 / 1.00 | n/a / 0.67 | n/a / 1.00 | trace |
| injection | 1.00 / 1.00 | **1.00 / 1.00** | 1.00 / 1.00 | trace or log |
| data_exfiltration | 0.94 / 1.00 | 0.67 / 0.40 | 0.94 / 1.00 | trace |
| credential_abuse | 1.00 / 0.78 | 1.00 / 0.55 | 1.00 / 0.77 | trace (SUT1) |
| resource_exhaustion | 0.96 / 0.57 | 0.70 / 0.13 | 0.96 / 0.57 | trace (SUT1) |

**Three classes transfer** (ssrf, injection, data_exfiltration — the last
actually higher on SUT2). **Two diverge** (credential_abuse, resource_exhaustion)
— both drops are explained by signal locus (§5), not detector weakness or corpus
quality (every class is 0-leakage, balanced, N=500).

**The combined arm never beats the better single arm** on either system: where
logs carry signal it is the same signal the trace already carries (or less), so
fusion adds nothing here. That is a result about *this corpus's* feature
representation, not a claim that trace+log fusion is useless in general (§7).

## 4. The gaps are representation limits, not classifier limits

Adding `hgb` (HistGradientBoosting, a stronger tabular model, no new dependency)
as a fourth detector **ties `rf` across every class and arm** on both systems
(e.g. SUT2 resource_exhaustion trace rf 0.955 / hgb 0.945; combined rf 0.96 /
hgb 0.948). A gradient-boosted model does not recover the two divergent classes.
So the credential_abuse and resource_exhaustion gaps are **not** "the classifier
is too weak" — the discriminating information is **absent from the per-trace
feature representation** on SUT2. This is the precise, defensible form of the
cross-system claim.

Confirmation from the feature side (`prototype_features.py`): adding a single
**session-level rate feature** (local request density over the pooled timeline)
recovers resource_exhaustion to ≈1.0. The signal exists — it is just
session-level, not per-trace (§5b).

## 5. Why the two classes diverge

Both reduce to one mechanism: **on SUT2 the security-relevant condition does not
change the trace's structure**, so the only residual per-trace signal is
incidental timing — noisy and workload-dependent. Every top RF importance on the
two divergent SUT2 classes is a span-duration statistic; the structural features
are flat. *Why* the structure is flat differs by class.

### 5a. Credential abuse — the signal locus moves out of the trace
- **SUT1:** login is a multi-service orchestration whose control flow *branches*
  on the auth result. Success issues a token and loads context; failure
  short-circuits. The decision is imprinted on the **trace structure** (span 12→8,
  DB 3→1) — one trace suffices, F1 1.00 (and the failure is logged distinctly, so
  the SUT1 **log** arm is also 1.00).
- **SUT2:** login is a single-service predicate — the auth service compares the
  password hash and returns a boolean, **the same work either way**. Success and
  failure produce an **identical 5-span, 1-DB trace**; the only difference is the
  302 redirect target (home vs login) and the response body. Our numeric feature
  set deliberately excludes categorical routing identifiers, so the signal is
  largely invisible to the detector (trace 0.78). The log arm sees both outcomes
  log similarly (0.55) — the redirect route, not a log field, is the
  discriminator.

**Claim:** an attack is trace-structurally detectable when the system's control
flow *branches* on the security-relevant condition. When the condition affects
only the response routing/payload — as TeaStore's auth does — the trace is blind
to it. `hgb` tying `rf` shows the fix is a *feature* (capture routing), not a
better model.

### 5b. Resource exhaustion — no per-trace signal on any system; rate is session-level
The attack replays an identical expensive query at high rate, so per-request
structure is *identical* to normal on both systems (SUT1 172/172 spans; SUT2 2/2).
The defining property is request **rate**, a session-level quantity the per-trace
features do not encode.

- **SUT1** traces are span-rich (172 spans): a per-trace timing aggregate is an
  average over many spans — stable, low-variance — so the modest load-correlated
  latency shift is exploitable (trace 0.96).
- **SUT2** traces are 2 spans: a per-trace timing statistic is the max/std of two
  numbers — high variance — so individual traces overlap (trace 0.57).

So SUT1's trace score is an incidental timing artifact that scales with span
richness, **not** a portable signal. The `prototype_features.py` session-rate
feature recovers both systems to ≈1.0, confirming the robust signal is rate —
which belongs in a session-/window-level feature a *streaming* detector would
compute, not in the per-trace arm.

## 6. Modality findings (RQ2) and the log-arm honesty check

### 6.1 Logs alone are a weak stand-alone detector for these anomalies — tested, not assumed
A content-aware (TF-IDF over log messages) probe
(`prototype_logcontent_deleaked.py`) gives **no** improvement over the
count-based log features for data_exfiltration, where logs looked most
promising: it stays ≈0.67 even with the bulk-read `args=[0,-1]` present in the
text — the content that reads as diagnostic to a human is not linearly separable
in the captured SUT1 logs. (Request-forgery is not part of this probe: its SUT1
benign class is uninstrumented, so its log-only and combined arms are withdrawn,
not content-limited.)

### 6.2 The one apparent log win was a collection-day leak (found and fixed)
Naive log-content scored resource_exhaustion a spurious **1.00** despite its
normal/attack logs being token-for-token identical. Two leak channels:
(1) collection-window tokens — the HTTP `Date:` header ("Wed 28" vs "Thu 29")
when the normal and attack windows fell on different days, plus trace/span ids
and timestamps; (2) per-trace line **count** proxying request volume via term
frequency. De-leaking (strip date/time/id tokens; `binary=True` presence;
de-duplicate identical lines) drops rex to chance. **Re-collecting rex in a
single same-day session** dropped its honest log-content to 0.70 and left
trace/combined unchanged at 0.96 — confirming the "signal" had been the artifact.
This is the methodological value of the dual-modality corpus: the trace arm was
the control that exposed the log leak.

### 6.3 Where logs genuinely contribute: presence/absence (injection)
Injection is the one class where the log arm independently reaches 1.00 on both
systems — because the attack is rejected before the handler runs and emits **no
log line**, so `log_line_count` 0 vs >0 separates perfectly. This is real
presence/absence evidence, not content, and it is orthogonal to (and redundant
with) the trace's `db_span` 1→0 + `sendError` signal.

## 7. Cross-system methodology findings

1. **Instrumentation carries different tags across systems.** TeaStore's OTel
   server spans carry **no `http.status_code`/`http.method`** tag, so the whole
   trace error-family is inert on SUT2; the 404 injection-rejection is visible
   only via `db_span` composition. Feature design must be re-validated per
   system, not assumed to transfer.
2. **Infra-noise signatures differ and must be re-derived.** Train-Ticket's
   discovery noise has a name (`NacosWatch…`); TeaStore's registry heartbeat is
   named with a bare HTTP verb and carries no URL tag, so it is identified by the
   *absence* of a URL. ~83% of raw SUT2 capture is this noise; a filter tuned to
   one system silently failed on the other, and the corpus audit caught it.
3. **Injection is rejected input, not exploitation, on both systems** — the
   detectable thing is "the request short-circuited," an honest negative.
4. **The combined arm's null result is informative** (§3): on this corpus logs
   carry no signal the trace lacks, so fusion is flat. Content-aware log features
   and session-level features (§4, §5b) are the directions that would change that
   — tested as prototypes, not yet in the frozen pipeline.

## 8. Caveats / limitations
- SUT2 runs on a local single-host Docker deployment; SUT1 on a shared research
  server. Absolute timings are not comparable; the timing *pattern* (and its
  instability at low span counts, §5b) is the portable observation.
- SSRF on SUT2 uses a distinct injected endpoint (`fetchFromUrl`) from the benign
  one (`getProductImages`) — a cross-endpoint comparison; the image→persistence→DB
  outbound chain is the genuine signature regardless.
- credential_abuse detection sets are per-trace (1000/1000), not per-login.
- The session-rate and de-leaked-content features are **prototypes**
  (exploratory), not part of the frozen feature pipeline; they bound what the
  current representation misses, and define the future-feature work.

## 9. Suggested manuscript edits
- Evaluation: add "Cross-system generalization" with the §3 table and the §5
  mechanism explanations; state the result as three-transfer / two-locus-shift.
- Add the §4 representation-not-classifier point (`rf`≈`hgb`) — it is what makes
  the signal-locus claim defensible.
- Methods/Threats: report the §6.2 log leak and its fix as a validity control;
  it strengthens, not weakens, the corpus.
- RQ2: logs are a weak stand-alone arm here (presence/absence for injection; no
  content gain for data_exfil; SUT1 request-forgery log/combined withdrawn as
  uninstrumented); traces carry the detectable structure.
