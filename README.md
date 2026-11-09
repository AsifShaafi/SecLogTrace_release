# SecLogTrace — artifact guide

A labelled corpus of OpenTelemetry **distributed traces joined to application
logs** for evaluating **security-anomaly detection** in microservice systems.
Five CWE-referenced scenarios — server-side request forgery, credential abuse,
injection, data exfiltration, resource exhaustion — are collected on two
architecturally distinct benchmarks: **Train-Ticket (SUT1)** under Kubernetes
and **TeaStore (SUT2)** under Docker Compose. Every request-level trace carries
a `normal` or `attack` label and a four-state log observation status.

- **Scale:** 11,000 labelled trace records — **SUT1 = 5,000**, **SUT2 = 6,000**.
- **Schema:** [`docs/DATA_SCHEMA.md`](docs/DATA_SCHEMA.md)
- **Data statement:** [`docs/DATA_STATEMENT.md`](docs/DATA_STATEMENT.md)

## Read this before counting rows

Five SUT1 traces are not attributable to a generated request and are excluded
from the corpus.
They are removed from the shipped tables, so a row count of the CSVs gives
11,000 and matches every reported number.

| Stratum | Before | Excluded | Retained |
|---|---|---|---|
| `ssrf_normal` | 503 | 3 | 500 |
| `data_exfiltration_normal` | 501 | 1 | 500 |
| `data_exfiltration_attack` | 501 | 1 | 500 |
| all other SUT1 strata | 500 | 0 | 500 |

The rule drops SSRF normal-window traces carrying an error span or a 5xx, and
data-exfiltration traces rooted at the login operation. It is stated in two
places that must agree: `exclusion_keep()` in
`scripts/detection/build_results_registry.py`, which still runs and is now a
no-op, and `scripts/preprocessing/materialise_corpus.py`, which applied it to
the files.

**Nothing was lost.** All five excluded rows are preserved verbatim, with their
source file and the matching predicate, in
`results/audit/excluded_traces.csv`. The exclusion is reversible from that
ledger. Retained rows were filtered as text rather than through a DataFrame
round-trip, so every retained line is byte-identical to the pre-exclusion file.

Materialising the exclusion changed no result: all 120 registry cells matched
to zero delta on F1, precision, recall, balanced accuracy, every
confusion-matrix count and every `n`.

**One script is superseded.** `scripts/detection/run_detection.py` predates the
exclusion and never applied it. It is retained for provenance only. Compute
from `build_results_registry.py`.

### Scenario names in the paper vs keys in the tables

The paper uses display names for two scenarios that differ from the table keys,
to avoid asserting an outcome the corpus does not establish ("bulk extraction"
rather than exfiltration, "resource stressing" rather than exhaustion). The
released tables, filenames and metadata use the keys.

| Paper display name | Key in tables / filenames |
|---|---|
| server-side request forgery | `ssrf` |
| credential abuse | `credential_abuse` |
| injection | `injection` |
| bulk extraction | `data_exfiltration` |
| resource stressing | `resource_exhaustion` |

### Composition, per scenario and label

The corpus is exactly balanced: 5,500 normal and 5,500 attack.

| Scenario | SUT1 normal | SUT1 attack | SUT2 normal | SUT2 attack | Total |
|---|---|---|---|---|---|
| Server-side request forgery | 500 | 500 | 500 | 500 | 2,000 |
| Credential abuse | 500 | 500 | 1,000 | 1,000 | 3,000 |
| Injection | 500 | 500 | 500 | 500 | 2,000 |
| Data exfiltration | 500 | 500 | 500 | 500 | 2,000 |
| Resource exhaustion | 500 | 500 | 500 | 500 | 2,000 |
| **Total** | **2,500** | **2,500** | **3,000** | **3,000** | **11,000** |

**SUT2 `credential_abuse` holds 2,000 rows, not 1,000.** Each generated request
produced about two traces there, so that stratum is double-size while SUT2
still totals 6,000. Its rows are therefore not independent observations, which
the registry records as the `dependent_traces` flag.

## Log coverage, stated conditionally

| System | Traces with a correlated log | Denominator | Rate |
|---|---|---|---|
| SUT1 | 4,250 | 4,500 | 94.44% |
| SUT2 | 5,500 | 6,000 | 91.67% |

The SUT1 denominator excludes the 500-trace SSRF stratum. Its sink is a Flask
service that logs without trace context, so an absent join there cannot be read
as an absent log record. `TraceId` and `SpanId` are optional fields in the
OpenTelemetry logs data model, which is why the corpus records a four-state
`log_observation_status` — `matched`, `verified_no_match`,
`source_not_instrumented`, `capture_unavailable` — instead of a boolean.

## What is included

**In git — the citable core:**

- `data/processed/combined/*_features.csv` — one row per trace, 29 trace features.
- `data/processed/logs/*/logs_by_trace.csv` — four per-trace log features.
- `data/raw/traffic/*.jsonl` — the traffic session record for every window.
- `scripts/` — collection, parsing, feature extraction, detection, audit.
- `results/audit/` — the registry, fold manifest and audit tables (below).
- `results/tables/`, `results/figures/` — detector outputs and paper figures.
- `metadata/` — per-scenario definitions and signatures.

**In the dataset archive (DOI):** the raw Jaeger trace exports and raw service
logs for both systems.

## The audit tables

These carry the provenance that the feature tables alone cannot.

| File | What it records |
|---|---|
| `results_registry_canonical.csv` | 120 cells: 2 systems x 5 scenarios x 3 arms x 4 models, one row each, with input hashes, seed, fold rule and four independent status fields |
| `fold_manifest.csv` | the fold id of all 11,000 records, so a split is checkable rather than described |
| `quality_audit_20_strata.csv` | per-stratum composition and telemetry availability |
| `feature_degeneracy_audit.csv` | which arms have class-conditional feature distributions that are identical |
| `separating_features.csv` | which features are range-disjoint by label, and over what ranges |
| `order_sensitivity.csv` | how far each cell moves under input permutation |
| `sanitisation_findings.csv` | the identifier scan, with a decision recorded per finding |

### Reading the registry

Status is four independent fields, not one label:

- `data_quality_status` — `complete`, `source_not_instrumented`, or
  `log_capture_not_interpretable`.
- `balanced_acc_above_0p52_screen` — a named heuristic, nothing more: pooled
  balanced accuracy above 0.52. Not a significance test, no interval.
  Constant-classifier baselines sit alongside on the same metrics.
- `interpretation_flags` — `session_confounded_possible`, `selection_bias`,
  `dependent_traces`, `log_absence_not_interpretable`, `presence_only`.
- `suitable_for_showcase_figure` — a recorded decision from the rule stated in
  the file. Excluded rows stay in the file.

Of the 120 cells, **75 are figure-eligible**, **21 sit at or below balanced
accuracy 0.52**, and **12 have no discriminative signal at all**. Eight SUT1
SSRF cells are withdrawn as `log_capture_not_interpretable`.

Precision, recall and F1 appear twice. `*_foldmean` averages each metric across
folds; `*_pooled` computes it once from concatenated out-of-fold predictions. A
fold-averaged F1 is not the harmonic mean of fold-averaged precision and
recall, so both are kept.

### Why some cells report F1 = 0.000

Three SUT2 log arms have **identical class-conditional feature distributions**.
In `resource_exhaustion` and `data_exfiltration` every row is the single vector
`(2,0,0,1)` at 500/500. No classifier can separate them. F1 then varies across
models only because each defaults to a different class, which is why the tree
models report 0.000 and isolation forest reports 0.667. Balanced accuracy
0.500 is the result in all four cases. Read balanced accuracy there, not F1.

## Row order is part of the protocol

`StratifiedKFold(shuffle=True, random_state=42)` permutes by row *position*, so
the input file's row order would otherwise change every score. The registry
builder therefore assigns each record an immutable `record_id`, sorts by
`(label, record_id)`, and writes the resulting fold assignment to
`fold_manifest.csv`. Random forest's bootstrap also draws indices in training
row order, so the canonical ordering is a requirement, not a convenience.

Measured effect: under permutation, reported cells move by at most **0.0075**
F1. Two excluded cells move by up to **0.5333** — both are no-discrimination
log arms where the prediction is arbitrary.

## Requirements

Python 3.9 or newer, then `pip install -r requirements.txt`
(pandas, numpy, scikit-learn, matplotlib).

`requirements.txt` pins minimums. `requirements-clean-env.txt` records the exact
resolved set under which the verification below was last run, for anyone who
needs to reproduce it exactly.

## Running example

No system bring-up. Runs on the shipped tables in about two minutes.

```bash
pip install -r requirements.txt

# 1. Rebuild the canonical 120-cell registry and the fold manifest.
python scripts/detection/build_results_registry.py \
    --processed-dir data/processed --out-dir results/audit

# 2. Add the degeneracy columns the registry depends on.
python scripts/detection/build_degeneracy_audit.py \
    --processed-dir data/processed \
    --registry results/audit/results_registry_canonical.csv \
    --out-dir results/audit

# 3. Per-stratum composition and telemetry availability.
python scripts/preprocessing/build_quality_audit.py \
    --processed-dir data/processed --traffic-dir data/raw/traffic \
    --sut1-results results/tables/detection_results.csv \
    --sut2-results results/tables/detection_results_sut2_v2.csv \
    --out-dir results/audit

# 4. Check every quantitative claim in the paper against those tables.
python scripts/detection/verify_manuscript_numbers.py \
    --audit-dir results/audit \
    --tex paper/msr2027/seclogtrace_msr2027.tex
```

Step 4 prints one line per claim and ends with a pass count. **The expected
result is 19 of 19 checks passing.** If a number in the paper and a number in
the released tables ever diverge, this is the step that says so.

Optional further checks: `verify_separating_features.py`,
`verify_registry_arithmetic.py`, `check_order_sensitivity.py`, and
`scripts/preprocessing/scrub_scan.py` for the identifier scan.

### Verified reproduction

The chain above was last executed in a clean virtual environment, installing
only from `requirements.txt`, against the shipped tables and nothing else.

- **All 120 registry cells matched the committed values exactly** — zero drift
  on F1, precision, recall, balanced accuracy and every confusion-matrix count.
- That held under **pandas 3.1.0, numpy 2.5.4, scikit-learn 1.9.1**, against a
  corpus developed on pandas 1.5.3 and scikit-learn 1.6.1.
- 19 of 19 manuscript checks passed.
- Registry build 109 s; the remaining steps under 30 s.

The canonical ordering is what makes that hold across library versions.

## Full reproduction from the systems

Standing up each benchmark and re-collecting a scenario end to end — traffic,
windowed trace export, log capture, zero-multi-label audit, feature table — is
documented in [`docs/DATA_COLLECTION_PIPELINE.md`](docs/DATA_COLLECTION_PIPELINE.md)
and the per-system protocols under `docs/experiment_protocols/`. SUT2 is
orchestrated by `scripts/collection/collect_sut2_corpus.sh <scenario> 500 <pace>`.

One stratum is not re-collectable. The SUT1 SSRF sink does not emit trace
context, so its per-trace log join cannot be recovered by repeating the
collection. It is marked `source_not_instrumented` rather than described as
missing data.

## Availability, licence, citation

- **Dataset archive:** [`10.5281/zenodo.24093117`](https://doi.org/10.5281/zenodo.24093117)
  (version DOI). The record is deposited with files restricted, which registers a
  resolvable DOI while the corpus stays closed until the paper appears. Cite the
  **version** DOI above, not the concept DOI; the concept DOI follows the newest
  version and would unpin these numbers from the archive they were computed against.
- **Reviewer access:** a private share link on the record (sent with the paper
  submission) opens the restricted files without a Zenodo account.
- **Code licence:** Apache License 2.0 — [`LICENSE`](LICENSE)
- **Data licence:** CC BY 4.0 — [`LICENSE-DATA`](LICENSE-DATA)
- **Third-party components and change notices:** [`NOTICE`](NOTICE)
- **Citation:** [`CITATION.cff`](CITATION.cff)

Both benchmark systems are Apache-2.0. Train-Ticket's `ts-avatar-service` is
included here in modified form, carrying a deliberately vulnerable request
forgery sink; the change notice required by Apache-2.0 section 4(b) is in
`NOTICE`. **Do not deploy that service on a network you do not control.**
