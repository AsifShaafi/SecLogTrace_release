# Data Collection Pipeline — how and why (SecLogTrace)

A plain-language overview of how a labelled dataset is produced in this
project, and *why* each step exists. Read this to understand the end-to-end
flow before running any single script; the per-task detail lives in
`docs/design/ABUSE_CLASSES_COLLECTION_DESIGN.md` (attack classes) and
`docs/design/SSRF_INJECTION_DESIGN.md` (the SSRF reference class).

**Keep this file current.** Whenever the collection process changes (a new
step, a new script, a changed gate, a new attack class's quirk), update the
relevant stage below and bump the "Last updated" date.

Last updated: 2026-09-03.

---

## The goal

The detection study compares three signals — **traces only**,
**logs only**, and **traces+logs combined** — at spotting security attacks
in a microservice system (Train-Ticket). To do that we need a dataset where
every request is labelled `normal` or `attack`, captured as *both* a
distributed trace and the application logs it produced, with the two
joinable by `trace_id`. This pipeline is how that dataset is built, one
attack class at a time, so it is clean enough to make honest detection
claims on.

## Why BOTH traces and logs

They are complementary and the whole point of the paper is measuring that.

- **Traces** (from Jaeger/OpenTelemetry) capture *structure and timing*: how
  many spans, which services a request crossed, call depth/fan-out, DB
  calls, durations. Attacks often distort structure (SSRF *adds* an outbound
  span; a failed login *aborts early* with fewer spans).
- **Logs** (from each service's stdout) capture *content*: error messages,
  auth-failure text, stack traces — things a trace's structure alone does
  not say. Some attacks are invisible structurally but obvious in a log line.
- **Combined** is the hypothesis: joined on `trace_id`, the two together
  should beat either alone. We cannot show that without collecting both for
  the same requests, in the same time window.

## Why the discipline is so strict

One early dataset (`experiment_001`) was **81% contaminated** — attack
traffic leaked into the `normal` label because the export time windows
overlapped. Every rule below (separate windows, a gap between classes,
explicit start/end, the audit gate, dedup) exists to prevent a repeat. A
contaminated corpus produces detection numbers that are worse than useless
because they look fine.

---

## The stages

Each attack class goes through the same sequence. `<class>` below is e.g.
`credential_abuse_pilot`.

### 1. Generate labelled traffic (two separate windows)
`scripts/collection/generate_abuse_traffic.py` (or `generate_ssrf_traffic.py`,
or `generate_baseline_traffic.py`) drives real requests at the live gateway.
- A **normal** window and an **attack** window are run **separately**, with a
  **≥60s gap** between them, so their traces never share a time window.
- Both classes hit the **same endpoint** where possible, differing only in
  input/timing — a *controlled within-endpoint comparison*, so a measured
  difference is the attack, not a different workload.
- Each request is logged to a `.jsonl` session log with a UTC `ts`; those
  timestamps define the export windows in stage 2.
- *Why:* labels come from *which window* a trace falls in, so the windows
  must be clean and separable.

### 2. Export the traces (Jaeger → raw JSON)
`scripts/collection/export_jaeger_traces.sh --label {normal,attack}
--experiment <class> --start <ISO> --end <ISO>`.
- Pulls every trace in the window from Jaeger, one JSON file per service,
  into `data/raw/jaeger/<class>_<label>/`, plus a manifest with the
  distinct-trace count.
- Windows come from the stage-1 `.jsonl` timestamps, padded by only ~10s (a
  pad larger than the inter-class gap would re-overlap the windows).
- *Why per service:* Jaeger stores a trace under every service it touched,
  so the same trace appears in multiple files — handled by dedup later.

### 3. Capture the logs (same windows)
`kubectl logs -n default <pod> --since-time=<window start> > .../<svc>.log`
for every `ts-*` pod, into `data/raw/logs/<class>_<label>/`.
- Use `2>/dev/null`, **not** `2>&1` — the latter merges kubectl's own banner
  into every file (a real bug we hit on 2026-08-21).
- Times are **UTC**; the collection box is CDT (UTC-5) — mind the offset.
- *Why:* this is the log arm of the study, and it must cover the same
  requests as the traces so the two can be joined.

### 4. THE GATE — audit for label leakage
`scripts/preprocessing/corpus_audit.py '<normal>/*.json' '<attack>/*.json'
--by-filename-label`.
- Deduplicates to a **distinct** trace count (never a per-service sum),
  reports the infra-noise fraction, and — the non-negotiable check —
  **`Traces carrying MORE THAN ONE label : 0`**.
- If it is not zero, the windows overlapped: re-export, do **not** proceed.
- *Why:* this is the exact check that would have caught `experiment_001`.
  No data is trusted until it passes.

### 5. Parse to CSV, build the feature table, parse the logs
- **`parse_jaeger_traces.py`** — raw Jaeger JSON → `traces.csv` (one row per
  trace) + `spans.csv` (one row per span). Flags pure infra-noise traces
  (NacosWatch service-discovery polling, ~82/min) so they can be dropped.
- **`build_feature_table.py`** — `spans.csv`+`traces.csv` → one **feature
  row per trace**: ~29 numeric features in named families (structural,
  timing, error, interaction, identity). See "What the feature table is for"
  below. This is the table the detectors actually consume.
- **`parse_service_logs.py`** — raw pod logs → `logs.csv` (one row per line)
  + `logs_by_trace.csv` (per-trace line/error/warn counts), and reports the
  **join rate**: what fraction of real traces have ≥1 log line, and whether
  every logged `trace_id` resolves to a real trace. This is the bridge that
  makes the combined arm possible.

### 6. Characterize the signal, then scale and freeze
- Compare attack vs. normal **within the shared `root_operation` only**
  (never pooled — pooling confounds the attack with the workload mix; this
  is why the old 82-vs-46 span finding was withdrawn). One paragraph per
  class: how it differs, and in which direction.
- A **pilot** is 15 normal + 15 attack — enough to validate the method and
  the signal, not to cite detection numbers. Once clean, **scale to
  ~150+/class**, re-run stages 1–5, and fold into the frozen corpus.
- Each class gets a `metadata/*.md` file and a `docs/phase_logs/` entry.

---

## What the feature table is for (build_feature_table.py)

The raw parse gives one row **per span** (`spans.csv`) — thousands of rows,
not directly comparable across traces of different sizes. A detector needs
one row **per request (trace)** with a fixed set of numeric columns. That is
what `build_feature_table.py` produces, and why it exists:

- **One row per trace, fixed schema.** Collapses each trace's many spans
  into ~29 numeric features, so every trace — big or small — is one
  comparable vector. This is the input format the Phase 3 detectors
  (rule-based, Isolation Forest, supervised, one deep baseline) train and
  score on.
- **Feature families for the ablation.** Columns are grouped —
  *structural* (span_count, service_count, max_depth, fan-out, edges),
  *timing* (durations/percentiles), *error* (error/4xx/5xx counts),
  *interaction* (db/http span counts, distinct targets), *identity*
  (trace_id, root_operation, label). The trace-only / log-only /
  combined comparison is done by **selecting column groups**, so the
  ablation needs no re-extraction.
- **Correct de-duplication.** `--spans` takes all per-service export files
  at once and dedups on `(trace_id, span_id)`, so a trace that crossed four
  services is counted once, not four times. (A past bug fan-out-multiplied
  rows here; there is now an assertion guarding it.)
- **Drops infra noise** by default (NacosWatch polling), keeping only real
  request traces.
- **Carries `root_operation`** on every row so all attack-vs-normal
  comparisons can be stratified by entry point — the project's standing
  rule against pooled comparisons.

Run it (per window):
```
python3 scripts/feature_extraction/build_feature_table.py \
    --spans  data/processed/traces/<class>_<label>/spans.csv \
    --traces data/processed/traces/<class>_<label>/traces.csv \
    --out    data/processed/combined/<class>_<label>_features.csv
```
First time against a new parser output, add `--inspect` to confirm column
resolution; `--keep-noise` retains infra-noise traces if ever needed.

---

## Data layout produced
```
data/raw/traffic/<class>_<label>_<stamp>.jsonl   # session log (labels + UTC ts)
data/raw/jaeger/<class>_<label>/*.json           # exported traces (per service) + manifest
data/raw/logs/<class>_<label>/*.log              # captured pod logs
data/processed/traces/<class>_<label>/{traces,spans}.csv
data/processed/combined/<class>_<label>_features.csv   # <- detector input
data/processed/logs/<class>_<label>/{logs,logs_by_trace}.csv
```

## The non-negotiables (memorize these)
- Separate windows per label, explicit `--start`/`--end`, **≥60s gap**,
  export immediately.
- **`corpus_audit.py --by-filename-label` must report ZERO multi-label
  traces** before any class is trusted.
- Never cite a per-service **sum** of trace counts — only **distinct**
  counts (dedup on `trace_id`, or `(trace_id, span_id)` at span level).
- Compare attack vs. normal **stratified by `root_operation`**, never pooled.
- Logs and traces in **UTC**; the box is CDT (UTC-5).

## Prerequisites
- `requests` for the generators.
- `pandas`/`numpy`/`matplotlib` for parse/feature/stats:
  `pip install -r scripts/feature_extraction/requirements.txt -r scripts/visualization/requirements.txt`.

## Known gaps (update as fixed)
- `parse_service_logs.py` does not yet recognize the **Python/Flask
  (gunicorn)** log format of the SSRF-injected `ts-avatar-service`; those
  lines count as UNPARSED. Harmless for classes that don't touch avatar, but
  worth adding a format for (noted 2026-09-03).
