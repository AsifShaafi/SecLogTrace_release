# Data Statement — SecLogTrace Attack Corpus (two SUTs, traces + logs)

A labelled corpus of OpenTelemetry distributed traces fused with application
logs, for evaluating security-anomaly detection in microservice systems.

> **Summary.** Two architecturally distinct systems under test, N=500/label.
> **SUT1 (Train-Ticket):** 5-class corpus, **5,000 retained traces** (2,500
> normal + 2,500 attack), traces + logs, zero multi-label. Five traces were
> excluded as out-of-scope observations and are no longer in the released
> tables; the pre-exclusion count was 5,005 (see §5.1).
> **SUT2 (TeaStore):** the same 5 classes at N=500/label, traces + logs —
> TeaStore was instrumented with per-request request-boundary logging (§3).
> 6,000 real traces (3,000 normal + 3,000 attack), zero multi-label, log↔trace
> join ~100% (SUT2 injection attack excepted — see §5.2). Three modality arms
> (trace / log / combined) exist on both SUTs.

## 1. Purpose
Enable an empirical comparison of **trace-based vs. log-based vs. combined**
detection of security attacks in a microservice system, with per-attack-class
signature analysis. Every request is labelled `normal` or `attack` (and by
attack class/sub-type) and captured as a trace. Where a log record carries a
matching `trace_id`, the logs join to the trace; each trace carries a
`log_observation_status` recording whether that join was possible, so an
unjoined trace is distinguishable from an uninstrumented source (§5.2).

## 2. Source systems
- **SUT1 — Train-Ticket** — an open-source microservice benchmark (41 services;
  Fudan SELab, https://github.com/FudanSELab/train-ticket), the fork
  `AsifShaafi/train-ticket-injection`, on Kubernetes on a single research
  server (`<research-host>`).
  - Only **one** service is modified from upstream: `ts-avatar-service` carries
    an injected SSRF sink (see §6). All other attacks exercise unmodified
    behaviour.
- **SUT2 — TeaStore** — an architecturally distinct open-source Java
  microservice benchmark (von Kistowski et al., MASCOTS 2018;
  https://github.com/DescartesResearch/TeaStore), a e-commerce store with a
  service registry, a persistence tier over a relational DB, and an image
  service. Deployed locally via Docker Compose with the OTel Java agent and
  Jaeger. Used to test **cross-system generalization** of the five classes.
  - Only **one** service is modified: the image service carries an injected
    SSRF sink (`fetchFromUrl`, CWE-918, same naive-sink pattern as SUT1's
    avatar). All other attacks exercise unmodified behaviour.

## 3. Instrumentation & modalities
- **Traces:** OpenTelemetry via the Java agent (and Flask/urllib
  auto-instrumentation for the avatar service), stored in Jaeger (Badger,
  720h TTL). Exported per service, deduplicated on distinct `trace_id`
  (and `(trace_id, span_id)` at span level).
- **Logs:** each service's stdout; application lines carry `trace_id`/`span_id`
  (`LOGGING_PATTERN_LEVEL`), so logs join to traces by `trace_id`. The log
  capture command received **no time bound**, so a capture named for one
  session may also hold records from the session that followed it (§4).
  Association is by `trace_id`, so no trace received another trace's log lines,
  but completeness of event capture within a window is not established.
- **Features:** one trace-level feature row per trace, **29 columns** in
  structural/timing/error/interaction/identity families, of which **22 are
  numeric modellable features** — the remaining seven (`trace_id`, `label`,
  `experiment_id`, `infra_noise`, `path_signature`, `root_service`,
  `root_operation`) are identity and provenance columns and must be dropped
  before fitting (§10). Plus per-trace log features (`logs_by_trace.csv`).
- **SUT2 modality — traces + logs.** TeaStore was instrumented with
  **request-boundary logging**: an AspectJ load-time weave emits one structured
  application log line per request at the servlet/REST handler, carrying
  `trace_id`/`span_id` (MDC) and the method arguments, with credential
  arguments redacted at the boundary (`***`). SUT2 therefore has the same three
  modality arms as SUT1. See TeaStore `LOGGING_INSTRUMENTATION.md`. SUT2 carries
  no `http.status_code`/`http.method` span tags, so the trace error feature
  family is inert there (documented in `docs/CROSS_SYSTEM_ANALYSIS.md`); that
  signal appears, where it exists, on the log side instead.

## 4. Collection method (per class)
`normal` and `attack` are generated as **separate, explicitly-windowed
sessions** with a ≥60s gap, then audited. Trace export used explicit
`--start`/`--end`. **Log capture did not:** the capture command received no
time bound, so in the four SUT1 classes with gateway coverage each
normal-named capture also holds records from the subsequent attack session.
For those four, the gateway access log's in-window counts agree with the
transcripts to within eleven records per stratum. **The non-negotiable gate:**
`corpus_audit.py --by-filename-label` must report **zero multi-label traces**
before any class is trusted. Where possible normal and attack hit the **same
endpoint**, differing only in the attack variable — a controlled
within-endpoint comparison. Scripts: `scripts/collection/collect_abuse_corpus.sh`,
`collect_ssrf_corpus.sh`, `generate_abuse_traffic.py`, `generate_ssrf_traffic.py`.

## 5. Composition

### 5.1 SUT1 (Train-Ticket) — traces + logs (N=500/label)
~500 normal + ~500 attack traces per class; every class audited zero
multi-label (`corpus_audit.py --by-filename-label`).

| Class | CWE | normal | attack | Endpoint(s) | Signature (mechanism) |
|---|---|---|---|---|---|
| credential_abuse | 307 | 500 | 500 | `POST /users/login` | aborts early (12→8 spans, 3→1 DB; no status signal) |
| resource_exhaustion | 400 | 500 | 500 | `POST /travelservice/trips/left` | pure request rate (structure identical 172/172; same-day re-collection — see metadata) |
| injection | 89/943 | 500 | 500 | `POST /travelservice/trips/left` | log-content only (payload in logs; traces blind) |
| data_exfiltration | 200 | 500 | 500 | `GET /admin*service/*` | access pattern: PII-endpoint access + breadth + rate |
| ssrf | 918 | 500 | 500 | `POST /avatar` | adds an outbound span (1→2–8) |

Totals: **2,500 normal + 2,500 attack = 5,000 retained traces.** The capture
held 5,005; five traces were excluded as out-of-scope observations — two setup
logins issued by the generator but outside its scenario-request transcript, and
three unrelated error-carrying traces in an otherwise 500-request normal
window. The exclusion is applied to the released tables, and every decision is
published with a stable record identifier and its reason in
`results/audit/excluded_traces.csv`. Removal leaves exactly 500 per label per
class **on SUT1**.

resource_exhaustion was re-collected in a single same-day session to remove a
split-day collection confound (see §10). The attack side was over-provisioned:
1,500 requests fired, **920 recorded as clean 172-span at collection time**,
then sampled to 500 under fixed seed 42 (the flood truncates a large fraction of
traces, ≈38% clean yield). **The 920 is a figure from the collection log, not
from the released artifact: the pre-selection export did not survive, so the
intermediate population cannot be reconstructed and the sampling step cannot be
re-run.** The count is recorded; the reproducibility is not.

A corpus-wide audit over all classes confirms **zero multi-label**.
`experiment_id` is stamped `sut1v2_<class>` / `sut2v2_<class>` on every
**feature** table. It is **not** reliable on the SUT1 **log** tables, where it
takes the form `<class>_<label>` and is stamped from the capture filename —
which, given the unbounded capture window (§4), mislabels attack-session traces
that landed in a normal-named capture. Drop `experiment_id` from the log
tables; use the feature table's value. Sub-type labels:
`cred_bruteforce`/`cred_userenum`; `resource_flood`;
`inj_{sqli,nosqli,pathtrav,jndi,xss}`; `exfil_{orders,travels,users,contacts}`;
`ssrf_{db_reach,internal_svc,closed_port}`. Per-class detail:
`metadata/sut1v2_<class>.md`.

### 5.2 SUT2 (TeaStore) — traces + logs (N=500/label)
500 normal + 500 attack **requests** per label per class; every class **zero
multi-label**. ~83% of raw capture is registry-heartbeat infra noise (filtered;
see §10). credential_abuse yields ~2 traces per login (the login POST + the
client's followed redirect), hence 1000/1000.

| Class | CWE | normal | attack | Endpoint(s) | trace / log signal |
|---|---|---|---|---|---|
| credential_abuse | 307 | 1000 | 1000 | `POST /webui/loginAction` | trace: login identical (5/5 spans, 1/1 DB); signal is the redirect route. log: ENTRY both ways, password redacted `***` |
| resource_exhaustion | 400 | 500 | 500 | `GET /persistence/rest/products` | rate only; trace AND log structure identical (2/2 spans) — signal is session rate |
| injection | 89/943 | 500 | 500 | `GET /persistence/rest/products` | trace: `db_span` 1→0 + `sendError`. log: no attack-side log record carries a matching `trace_id` → 0 joined lines (presence/absence) |
| data_exfiltration | 200 | 500 | 500 | `GET /persistence/rest/users{,?max=-1}` | trace: span 1→2, `db_span` 0→1. log: `[listAll] args=[0,-1]` bulk vs `[findById]` single (content) |
| ssrf | 918 | 500 | 500 | `POST /image/rest/image/fetchFromUrl` | trace: outbound chain 1→4 (image→persistence→DB). log: `fetchFromUrl` ENTRY records the target URL (content) |

Log↔trace join is ~100% on captured strata except two cases, and the two cases
are **not** equivalent.

**Injection (SUT2)** — `verified_no_match`. No attack-side log record carries a
matching `trace_id` (500/1000 joined, all normal). The services did produce log
output in that window; what is absent is a log record joinable to the trace. We
do not assert a single rejection mechanism, because the handling path was not
established for each sub-type. The absence is an observation, not a gap.

**SUT1 request-forgery** — `source_not_instrumented` on the normal side. Its
benign class reaches only the injected Python sink, which logs without trace
context and bypasses the gateway access log, so no line in that window carries
a trace identifier at all. Per-trace absence therefore **cannot be verified**
and the rate is undefined rather than 0%; the attack side joins at 50%
(250/500). The log-only and combined arms for this stratum are withdrawn.

Detection (supervised RF F1, 5-fold, three arms; SUT2 / SUT1):

| Class | trace | log | combined |
|---|---|---|---|
| ssrf | 1.00 / 1.00 | 0.67 / n/a | 1.00 / n/a |
| injection | 1.00 / 1.00 | **1.00 / 1.00** | 1.00 / 1.00 |
| data_exfiltration | 1.00 / 0.94 | 0.40 / 0.67 | 1.00 / 0.94 |
| credential_abuse | 0.78 / 1.00 | 0.55 / 1.00 | 0.77 / 1.00 |
| resource_exhaustion | 0.57 / 0.96 | 0.13 / 0.70 | 0.57 / 0.96 |

The trace arm dominates on SUT2; the **log arm independently separates
injection** (presence/absence) on both SUTs. For data_exfiltration the
discriminating log evidence is in the line *content* (bulk args), which the
current count-based per-trace log features do not encode — a known, documented
ceiling, not a null result (see §10). **SUT1 request-forgery (ssrf) log-only and
combined analyses are withdrawn** (`n/a` above): its benign class reaches only
the injected Python sink, which is uninstrumented for trace-correlated logging,
so no normal-side logs exist to separate (`source_not_instrumented`); the trace
arm alone separates it at 1.00. SUT2 request-forgery keeps a genuine log signal. Two classes
(credential_abuse, resource_exhaustion) diverge from SUT1 for signal-locus
reasons analyzed in `docs/CROSS_SYSTEM_ANALYSIS.md`. Results:
`results/tables/detection_results_sut2_v2.csv`; per-class detail:
`metadata/sut2v2_<class>.md`. The SUT1 resource_exhaustion F1 is on the clean,
same-day re-collected 500/500 set (n=1000; see §10); `detection_results.csv` and
`cross_system_comparison.csv` were regenerated after that re-collection. A
stronger tabular classifier (`HistGradientBoosting`, added as a 4th detector)
matches RF on every class — the gaps are feature-representation limits, not
classifier limits.

## 6. Provenance of labels
Labels are ground truth by construction: each trace's class is determined by
which generated, windowed session produced it. SSRF is the one **injected**
vulnerability (a `src_url` sink in `ts-avatar-service`, CWE-918) — needed
because Train-Ticket has no natural SSRF sink; the detector learns the
resulting telemetry, which matches a real SSRF. The other four classes abuse
**existing, unmodified** endpoints (no login lockout, no rate limiting,
bulk-dumping admin endpoints, unvalidated search input).

## 7. Normal / legitimate traffic & declared scope
The `normal` class for each attack is a **matched control at the attacked
endpoint** (successful logins, valid searches, routine admin dashboard reads,
real base64 image uploads). A complementary general booking-workload baseline
exists (`experiment_003`/`experiment_004`).
**Declared workload scope (Option A):** the corpus covers the **auth + booking +
admin-read + avatar** workload the five attack classes target, NOT the full
203-endpoint / 44-service API surface. This is stated as an explicit scope,
with full-API coverage noted as future work (§10).

## 8. Ethics & safety
- No real personal data. The system is a benchmark; the "PII" the
  data_exfiltration class reads (user/contact tables) is **synthetic seed +
  test-account data** (68 of 69 user records are our own `seclog_`/`fdse_`/
  `admin` accounts, with randomly generated document numbers).
- All traffic ran against a private research deployment on the Baylor network
  (VPN-gated), never a third party. Attacks are contained to that system.
- Credentials used are the benchmark's documented test accounts; `admin/admin`
  is deliberately never sent (it triggers a built-in fault).

## 9. Reproducibility
Every trace traces back to a generator script + windowed export. Collection
transcripts: `docs/daily_logs/`; per-class metadata: `metadata/<class>.md`;
method: `docs/DATA_COLLECTION_PIPELINE.md`. The reproducible core (feature
tables, per-trace log features, traffic session logs, scripts) is in git; the
1.5 GB raw Jaeger/log bulk is archived separately (Zenodo, for the DOI release)
— see `.gitignore`.

## 10. Known limitations
- **Declared workload scope** (§7) — normal does not span all 203 endpoints.
- **Cross-system generalization evidenced on all three arms:** the five
  classes were replicated on a second SUT (TeaStore, N=500), and TeaStore
  carries logs (§3), so trace / log / combined all run on both SUTs. Three
  classes show consistent observable characteristics across the two systems;
  two (credential_abuse, resource_exhaustion) reveal that their signal locus is
  system-specific — a result, analyzed in
  `docs/CROSS_SYSTEM_ANALYSIS.md`. Two systems cannot establish transfer,
  so we report cross-system consistency rather than generalization. A third SUT and
  cross-day/cross-deployment replication remain future work. (A reliability
  check confirmed SUT1 structural features reproduce across days.)
- **Log features are count-based (`log_line_count`/`error`/`warn`/
  `service_count`).** On SUT2 the discriminating log evidence for
  data_exfiltration (bulk `args=[0,-1]`) is in line
  *content*, which the current features do not encode — so the log arm
  underperforms its potential there. (SUT1 request-forgery is a different case:
  its benign class is uninstrumented, so its log-only and combined arms are
  *withdrawn*, not content-limited.) Content-aware log features are future
  work; the raw log stream retains the evidence.
- **Logs alone are a limited signal for these security anomalies — tested, not
  assumed.** A prototype content-aware (TF-IDF) log feature on SUT1
  (`scripts/detection/prototype_logcontent_deleaked.py`) gave **no** improvement
  over the count features for data_exfiltration (it stays ≈0.67; the bulk-read
  args are not separable in the captured SUT1 logs), while trace/combined reach
  ≈1.0. (Request-forgery is excluded here: its SUT1 benign class is
  uninstrumented, so there are no normal-side logs for a content probe to use.) The log arm's one *apparent* win
  was instructive: resource_exhaustion scored a spurious **1.00** on log-content
  until we traced it to a **collection-day leak** — its normal and attack
  windows were a day apart, so the HTTP `Date:` header in
  the logs trivially separated them. Re-collecting rex in a single same-day
  session dropped log-content to 0.70 (and left trace/combined unchanged at
  0.96), confirming the "signal" was the artifact. Net: for this corpus the
  **log modality is a weak stand-alone detector** — it mainly contributes
  presence/absence evidence (e.g. injection) and content the current features
  don't yet exploit; traces carry the detectable structure.
- **N = 500 per class.** Sufficient for signature characterization and a
  detection split; not a large-scale ML dataset.
- **SSRF is injected**; **injection attempts do not succeed** — we capture the
  attempt pattern, an honest negative. We do not assert why each sub-type was
  rejected, because the handling path was not established per sub-type.
- **No class demonstrates a compromise.** Request forgery performed the
  outbound call but all 500 attack requests returned 5xx, so no fetched content
  reached the caller. Bulk extraction returned the requested records, but the
  intended authorization boundary is not established, so it is bulk retrieval
  rather than verified unauthorized exfiltration. Resource stressing generated
  sustained load with no resource-pressure measurement captured, so it is not
  exhaustion. Credential abuse failed authentication by design. The corpus is
  **attack-attempt telemetry**: a label identifies the scenario that generated
  the request, not that the request succeeded.
- **Pilot correction:** resource_exhaustion's apparent latency-under-load did
  not reproduce at the pilot scale (rate-only).
- **Filtered artifact:** `jaeger-query` traces (the export tool's own API
  calls) are filtered as infra noise; the raw exports still contain them.

## 10a. Leakage hazards for reusers

Four columns and one raw stream separate the label without any mechanism. Our
own pipeline avoids all of them; a reuser who does not will get an inflated
result.

- **Raw SUT2 log lines contain the request arguments, which for SSRF,
  injection and bulk extraction are the attack payload.** The AspectJ weave
  logs the method name and its arguments, so in the SSRF class
  `fetchFromUrl` appears 1,000 times on the attack side and zero times on the
  normal side, with `getProductImages` the exact inverse — perfect separation
  on the method name alone, before the payload is even read. Content-based
  models over `data/raw/logs/` are label-leaking by construction. The
  count-based per-trace log features are the intended interface.
- **`root_operation`, `path_signature` and `root_service`** are identity and
  provenance columns, not features. On SUT2 request forgery and SUT2 bulk
  extraction the normal and attack endpoint sets do not overlap at all, so
  one-hot encoding any of the three gives a perfect classifier. On SUT1
  credential abuse, 23 attack traces carry `nosuchuser<N>` in
  `root_operation` and no normal trace does.
- **`experiment_id`** on the SUT1 log tables encodes the label and is
  unreliable (§5.1).
- **SUT2 injection**: `log_line_count = 0` is perfectly collinear with the
  attack label. Exclude that stratum from log and combined arms, or treat
  presence as a known collection artifact.
- **Required drop set before fitting:** `trace_id`, `label`, `experiment_id`,
  `infra_noise`, `path_signature`, `root_service`, `root_operation`.

## 10b. Session confound and recommended evaluation protocol

Each class was collected as one normal session followed by one attack session,
so **collection time is confounded with the label**. On SUT2, two strata that
share label, endpoint and call-graph shape but were collected in different
sessions separate at **0.937–0.957 balanced accuracy on every timing feature**,
with structural features identical; on SUT1 the same comparison reaches only
0.542.

Six of the 29 columns are duration-derived and carry this confound:
`trace_duration_us`, `span_dur_mean`, `span_dur_median`, `span_dur_p95`,
`span_dur_max`, `span_dur_std`. The remaining 16 modellable columns are
structural and unaffected. There is no absolute-timestamp column in the
feature table.

- **Recommended default — structure only.** Fit on the 16 structural columns.
  Results under this protocol are the comparable ones.
- **Timing included — exploratory.** Any reported gain should be accompanied by
  the same-label session control (`scripts/preprocessing/check_session_effect.py`);
  on SUT2 that control reaches 0.957.
- Durations remain in the release because they are genuine observations and
  because characterizing the confound requires them. They are not dropped.

See Kapoor & Narayanan on leakage in ML-based science
([doi:10.1016/j.patter.2023.100804](https://doi.org/10.1016/j.patter.2023.100804)).

## 11. Intended use / not-for
For research on trace/log security-anomaly detection in microservices. NOT a
production IDS dataset, NOT representative of real-world attack prevalence, and
NOT to be used to claim detector generalization beyond the declared scope.

## 12. Methodological grounding (peer-reviewed prior work)
Every method this corpus uses is established in the peer-reviewed literature.

**Injecting/scripting attacks into a benchmark to build a labelled corpus**
- X. Zhou et al., "Fault Analysis and Debugging of Microservice Systems:
  Industrial Survey, Benchmark System, and Empirical Study," *IEEE TSE* 2021
  — defines Train-Ticket and replicates 22 fault cases by **injection**.
  [doi:10.1109/TSE.2018.2887384](https://doi.org/10.1109/TSE.2018.2887384)
- B. Dolan-Gavitt et al., "LAVA: Large-Scale Automated Vulnerability
  Addition," *IEEE S&P* 2016 — the canonical case that **injecting
  vulnerabilities to produce ground-truth corpora** is standard practice.
  [doi:10.1109/SP.2016.15](https://doi.org/10.1109/SP.2016.15)
- I. Sharafaldin et al., **CIC-IDS2017** — controlled generation of
  *labelled* benign+attack traffic (brute-force, DoS, web attacks, infiltration)
  for detection evaluation.
  [unb.ca/cic/datasets/ids-2017](https://www.unb.ca/cic/datasets/ids-2017.html)

**Trace + log (multi-source) anomaly detection in microservices — the study's method**
- C. Zhang et al., "DeepTraLog: Trace-Log Combined Microservice Anomaly
  Detection through Graph-based Deep Learning," *ICSE* 2022 — closest prior
  work (trace+log fusion; evaluated on a Train-Ticket-based benchmark with
  injected anomalies).
  [doi:10.1145/3510003.3510180](https://doi.org/10.1145/3510003.3510180)
- P. Liu et al., "Unsupervised Detection of Microservice Trace Anomalies
  through Service-Level Deep Bayesian Networks" (**TraceAnomaly**), *ISSRE*
  2020.
  [doi:10.1109/ISSRE5003.2020.00014](https://doi.org/10.1109/ISSRE5003.2020.00014)
- C. Lee et al., "Eadro: An End-to-End Troubleshooting Framework for
  Microservices on Multi-source Data," *ICSE* 2023 — traces + logs + KPIs.
  [doi:10.1109/ICSE48619.2023.00150](https://doi.org/10.1109/ICSE48619.2023.00150)
- G. Yu et al., "Nezha: Interpretable Fine-Grained Root Causes Analysis for
  Microservices on Multi-modal Observability Data," *ESEC/FSE* 2023.
  [doi:10.1145/3611643.3616249](https://doi.org/10.1145/3611643.3616249)

**SSRF (our one injected class) as a studied attack**
- B. Jabiyev, O. Mirzaei, A. Kharraz, E. Kirda, "Preventing Server-Side
  Request Forgery Attacks," *ACM SAC* 2021 — cited for SSRF as a studied
  attack and for its defenses. **Not** the source of our construction: their
  evaluation deploys six *existing* deliberately vulnerable applications taken
  from the OWASP Vulnerable Web Applications Directory, rather than injecting
  sinks into otherwise sound applications. Our sink is our own implementation.
  [doi:10.1145/3412841.3442036](https://doi.org/10.1145/3412841.3442036)

The other four classes exercise unmodified behaviour and map to standard
weakness taxonomies (see the CWE / OWASP-API references in the per-class
metadata).
