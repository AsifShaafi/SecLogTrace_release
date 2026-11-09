# Post-Session Collection & Processing Runbook (parameterized)

Reusable procedure for turning any collection session — labmate UI sweep, or
attack-traffic run — into audited, processed data. Run in order, from
`~/SecLogTrace`, right after the session ends.

**This is a TEMPLATE. Fill the variable block below first, then paste it into
your shell so every command picks up your values.** Nothing downstream is
hardcoded — if a command references a session-specific value, it comes from
here. A worked example (the 2026-08-18 coverage sweep) is at the bottom for
reference; do not copy from the example, copy from the variable block.

---

## 0. SET THESE — the only place you edit

```bash
# --- identity of this collection ---
export EXPERIMENT="<set me>"        # e.g. cred_abuse_pilot, ssrf_full_normal
export LABEL="<normal|attack>"      # must contain 'normal' or 'attack' so
                                    # corpus_audit.py --by-filename-label works

# --- time window, in UTC (the box is CDT = UTC-5, so add 5h to local) ---
# Take these from the session summary block / traffic-generator output.
# Pad ~10s each side. kubectl logs --since-time REQUIRES UTC with a Z.
export START_UTC="<set me>"         # e.g. 2026-08-27T08:08:50Z
export END_UTC="<set me>"           # e.g. 2026-08-27T08:09:45Z

# --- export limit (raise if any service truncates) ---
export LIMIT="20000"                # 5000 is fine for a small pilot window

# --- derived paths (leave as-is) ---
export RUNDIR="data/raw/jaeger/${EXPERIMENT}_${LABEL}"
export LOGDIR="data/raw/logs/${EXPERIMENT}"
echo "Collecting: EXPERIMENT=$EXPERIMENT LABEL=$LABEL"
echo "Window (UTC): $START_UTC -> $END_UTC"
```

If `$EXPERIMENT` or `$START_UTC` still shows `<set me>` when you echo it, stop
— you have not set the block.

---

## 1. Confirm nothing reverted (30 seconds)

```bash
kubectl get deploy jaeger -o jsonpath='{.spec.template.spec.containers[0].env[?(@.name=="SPAN_STORAGE_TYPE")].value}'; echo
# must print: badger

kubectl logs $(kubectl get pods -o name | grep -m1 '/ts-travel-service') --tail=50 | grep -c 'trace_id='
# must be non-zero
```

If either fails, fix before collecting — the data would be unusable.

## 2. Export traces (all services, explicit window)

```bash
./scripts/collection/export_jaeger_traces.sh \
    --label "$LABEL" \
    --experiment "$EXPERIMENT" \
    --start "$START_UTC" \
    --end   "$END_UTC" \
    --limit "$LIMIT"
```

Then CHECK THE MANIFEST before going further:

```bash
python3 -c "import json,glob; m=json.load(open(glob.glob('$RUNDIR/manifest.json')[0])); \
print('distinct:', m['distinct_trace_count'], '| truncated:', repr(m['truncated_services']))"
```

`truncated_services` must be empty. If not, raise `LIMIT` and re-run.
Record `distinct_trace_count` — that is the only count you cite.

## 3. Capture logs for the same window (all ts-* services)

```bash
mkdir -p "$LOGDIR"
for p in $(kubectl get pods -o name | grep '/ts-'); do
  svc=$(basename "$p")
  kubectl logs -n default "$p" --since-time="$START_UTC" \
    > "$LOGDIR/${svc}.log" 2>/dev/null
  printf "  %-34s %s lines\n" "$svc" "$(wc -l < "$LOGDIR/${svc}.log")"
done
```

`--since-time` is UTC and has no end bound — it captures to "now". Over-capture
is safe; the parser filters by trace join later. Do this the SAME DAY — log
buffers rotate.

## 4. Back up raw immediately (raw/ is server-disk-only)

```bash
tar czf ~/seclogtrace_${EXPERIMENT}_$(date +%Y%m%d).tar.gz "$RUNDIR" "$LOGDIR"
# copy this tarball off the server
```

## 5. Audit — the mandatory gate

```bash
python3 scripts/preprocessing/corpus_audit.py "$RUNDIR/*.json" --by-filename-label
```

For a single-label run, read the distinct count, noise fraction, and the
root_operation inventory. For a normal+attack pair, pass BOTH dirs and confirm
**Traces carrying MORE THAN ONE label : 0** before trusting anything:

```bash
# after collecting the matching opposite-label window into its own dir:
python3 scripts/preprocessing/corpus_audit.py \
    "data/raw/jaeger/${EXPERIMENT}_normal/*.json" \
    "data/raw/jaeger/${EXPERIMENT}_attack/*.json" \
    --by-filename-label
```

## 6. Parse traces to CSV

```bash
python3 scripts/preprocessing/parse_jaeger_traces.py \
    --input-dir "$RUNDIR" \
    --output-dir "data/processed/traces/${EXPERIMENT}" \
    --label "$LABEL"
```

(Flags are `--input-dir`/`--output-dir`/`--label {normal,attack}`; run with
`--help` if unsure.)

## 7. Build the trace feature table (dedups across all files)

```bash
python3 scripts/feature_extraction/build_feature_table.py \
    --spans  data/processed/traces/${EXPERIMENT}/*spans*.csv \
    --traces data/processed/traces/${EXPERIMENT}/*traces*.csv \
    --out    data/processed/combined/${EXPERIMENT}_features.csv
```

Confirm the retained-trace count matches the distinct count from steps 2/5.

## 8. Parse logs to CSV, report join rate

```bash
python3 scripts/preprocessing/parse_service_logs.py \
    "$LOGDIR"/*.log \
    --out data/processed/logs/${EXPERIMENT}_logs.csv \
    --agg data/processed/logs/${EXPERIMENT}_logs_by_trace.csv
```

Report the trace↔log join rate: fraction of trace_ids in the feature table
with ≥1 matching log line. Services that received no traffic contribute 0
legitimately — not a failure.

## 9. Baseline stats (sanity, not a paper result)

```bash
python3 scripts/visualization/baseline_stats.py \
    --features data/processed/combined/${EXPERIMENT}_features.csv \
    --outdir results/${EXPERIMENT}
```

## 10. Write the metadata file

`metadata/${EXPERIMENT}.md`, containing: the session log / traffic-generator
output verbatim, the exact window (local and UTC), distinct_trace_count, noise
fraction, service coverage, the root_operation inventory, and — if this is a
hand-run or exploratory session — an explicit **DEV/COVERAGE DATA, NOT CORPUS
DATA** label.

## 11. Update tracking

- `docs/PHASE_STATUS.md`: note the collection, distinct count, endpoint coverage
- `docs/phase_logs/phase_log_$(date +%Y%m%d).md`: what was collected, join rate,
  anything that errored
- `docs/daily_logs/command_log_$(date +%Y%m%d).md`: the export + log commands
  with paths

---

## WORKED EXAMPLE (reference only — do NOT copy from here)

This is what the block looked like for the 2026-08-18 labmate coverage sweep,
shown only to illustrate the shape of filled-in values:

```bash
# EXAMPLE VALUES — for illustration, not for reuse
export EXPERIMENT="experiment_002"
export LABEL="coverage_sweep"        # note: contains neither 'normal' nor
                                     # 'attack' — that sweep was single-label
                                     # dev data, audited for inventory not leakage
export START_UTC="2026-08-18T16:35:00Z"   # 11:35 CDT + 5h
export END_UTC="2026-08-18T17:31:00Z"     # 12:31 CDT + 5h
export LIMIT="20000"
```

That sweep produced 4,715 distinct / 123 real traces across 42 services,
cross-validated against a 118-call browser HAR. Its purpose was the endpoint
inventory, not a normal/attack comparison — which is why its LABEL doesn't
follow the normal/attack convention. For the attack-class collections, LABEL
must contain 'normal' or 'attack'.
