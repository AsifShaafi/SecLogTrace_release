#!/usr/bin/env bash
# run_reliability_check.sh — SecLogTrace Phase 1
#
# The last open item in PHASE_1_CHECKLIST.md item 8: repeat the scripted
# baseline + attack-demo collection on a DIFFERENT CALENDAR DAY from
# experiment_003/attack_demo_003 (2026-08-21), then compare distributions
# with baseline_stats.py to check the pipeline produces consistent results
# across runs, not just once.
#
# This is a generalized, re-runnable version of
# docs/daily_logs/phase1_recollection_20260820_commands.sh (same step
# sequence) with experiment IDs and run parameters as flags instead of
# hardcoded, since this script is meant to be invoked again in the future
# whenever another reliability re-run is needed.
#
# Run ON THE SERVER (<research-host>), not the local Box-synced checkout --
# needs kubectl cluster access for the log-capture steps. Assumes the
# research repo is checked out at ~/SecLogTrace and jq is installed. Does
# NOT touch the SSRF endpoint -- that's handled separately (Phase 2).
#
# To get a combined commands+output log:
#   ./scripts/collection/run_reliability_check.sh 2>&1 | \
#     tee docs/daily_logs/reliability_check_$(date -u +%Y%m%d)_log.md
#
# Does NOT use `set -e`: export_jaeger_traces.sh exits 3 (not 0) on a
# truncation warning, which is informative, not fatal -- later steps
# (log capture, the corpus_audit gate) should still run.
#
# kubectl log capture uses `2>/dev/null`, not `2>&1` -- the first real run
# (2026-08-21) merged kubectl's own stderr banner into every raw log file
# before this was fixed. Don't reintroduce it.
set -uo pipefail

usage() {
  cat <<'EOF'
Usage: run_reliability_check.sh [options]

  --normal-id ID          experiment ID for the new normal collection
                           (default: experiment_004)
  --attack-id ID          experiment ID for the new attack-demo collection
                           (default: attack_demo_004)
  --baseline-id ID        prior normal collection to compare against
                           (default: experiment_003 -- the current frozen-
                           corpus candidate)
  --baseline-date DATE    calendar date (YYYY-MM-DD) the baseline was
                           collected on, used only for the different-day
                           guard (default: 2026-08-21)
  --sessions N            baseline traffic sessions (default: 15, matches
                           the baseline run so distributions are comparable)
  --attack-count N        attack-demo traffic count (default: 20)
  --gap-seconds N         gap between normal and attack collection windows
                           (default: 300 -- experiment_001's postmortem
                           found label leakage from skipping this)
  --window-pad-seconds N  padding on each side of the Jaeger export window
                           (default: 60)
  --skip-attack           only repeat the normal baseline, skip the attack
                           demo re-run and the reliability comparison stays
                           normal-vs-normal either way
  -h, --help              show this help
EOF
}

NORMAL_ID="experiment_004"
ATTACK_ID="attack_demo_004"
BASELINE_ID="experiment_003"
BASELINE_DATE="2026-08-21"
BASELINE_SESSIONS=15
ATTACK_COUNT=20
GAP_SECONDS=300
WINDOW_PAD_SECONDS=60
SKIP_ATTACK=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --normal-id)          NORMAL_ID="$2"; shift 2 ;;
    --attack-id)          ATTACK_ID="$2"; shift 2 ;;
    --baseline-id)        BASELINE_ID="$2"; shift 2 ;;
    --baseline-date)      BASELINE_DATE="$2"; shift 2 ;;
    --sessions)           BASELINE_SESSIONS="$2"; shift 2 ;;
    --attack-count)       ATTACK_COUNT="$2"; shift 2 ;;
    --gap-seconds)        GAP_SECONDS="$2"; shift 2 ;;
    --window-pad-seconds) WINDOW_PAD_SECONDS="$2"; shift 2 ;;
    --skip-attack)        SKIP_ATTACK=1; shift ;;
    -h|--help)            usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

cd ~/SecLogTrace || { echo "FATAL: ~/SecLogTrace not found -- adjust the cd at the top of this script"; exit 1; }
export TZ=UTC

command -v jq >/dev/null || { echo "FATAL: jq not found."; exit 1; }
command -v kubectl >/dev/null || { echo "FATAL: kubectl not found."; exit 1; }
kubectl get pods -n default >/dev/null 2>&1 || { echo "FATAL: kubectl cannot reach the cluster from here. Check VPN/kubeconfig."; exit 1; }
python3 -c "import pandas, numpy, matplotlib" >/dev/null 2>&1 || {
  echo "FATAL: pandas/numpy/matplotlib not importable from python3 -- Steps 9-11"
  echo "(build_feature_table.py, baseline_stats.py) need them and would fail only"
  echo "after Steps 1-8 already generated real traffic against the live gateway."
  echo "Install first: pip install -r scripts/feature_extraction/requirements.txt -r scripts/visualization/requirements.txt"
  exit 1
}

TODAY=$(date -u +%Y-%m-%d)
if [[ "$TODAY" == "$BASELINE_DATE" ]]; then
  echo "FATAL: today ($TODAY) is the same calendar day as the baseline"
  echo "($BASELINE_DATE, $BASELINE_ID). The reliability check is defined as"
  echo "a run on a DIFFERENT day -- see PHASE_1_CHECKLIST.md item 8. Re-run"
  echo "this tomorrow, or pass --baseline-date if that date is wrong."
  exit 1
fi

if [[ -d "data/raw/jaeger/${NORMAL_ID}_normal" ]]; then
  echo "FATAL: data/raw/jaeger/${NORMAL_ID}_normal already exists -- pick a"
  echo "new --normal-id so this run doesn't clobber prior data."
  exit 1
fi

echo "==================================================================="
echo "Reliability check: ${NORMAL_ID} (+ ${ATTACK_ID}) vs baseline ${BASELINE_ID} (${BASELINE_DATE})"
echo "==================================================================="

echo
echo "==================================================================="
echo "STEP 1: Baseline traffic generation (${NORMAL_ID}, label=normal)"
echo "==================================================================="
NORMAL_START=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
python3 scripts/collection/generate_baseline_traffic.py \
  --sessions "$BASELINE_SESSIONS" --out-dir data/raw/traffic --demo-user-ratio 0.3
NORMAL_END=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
echo "Recorded window: $NORMAL_START -> $NORMAL_END"

NORMAL_EXPORT_START=$(date -u -d "$NORMAL_START -${WINDOW_PAD_SECONDS} seconds" +"%Y-%m-%dT%H:%M:%SZ")
NORMAL_EXPORT_END=$(date -u -d "$NORMAL_END +${WINDOW_PAD_SECONDS} seconds" +"%Y-%m-%dT%H:%M:%SZ")

echo
echo "==================================================================="
echo "STEP 2: Export Jaeger traces for ${NORMAL_ID}"
echo "==================================================================="
./scripts/collection/export_jaeger_traces.sh --label normal --experiment "$NORMAL_ID" \
  --start "$NORMAL_EXPORT_START" --end "$NORMAL_EXPORT_END" --limit 20000

echo
echo "==================================================================="
echo "STEP 3: Capture service logs for the SAME window (${NORMAL_ID})"
echo "==================================================================="
mkdir -p "data/raw/logs/${NORMAL_ID}"
for p in $(kubectl get pods -o name -n default | grep '/ts-'); do
  svc=$(basename "$p")
  kubectl logs -n default "$p" --since-time="$NORMAL_EXPORT_START" \
    > "data/raw/logs/${NORMAL_ID}/${svc}.log" 2>/dev/null
  echo "  $svc: $(wc -l < "data/raw/logs/${NORMAL_ID}/${svc}.log") lines"
done

if [[ "$SKIP_ATTACK" -eq 0 ]]; then
  echo
  echo "==================================================================="
  echo "STEP 4: Waiting ${GAP_SECONDS}s before the attack run (avoid overlap)"
  echo "==================================================================="
  sleep "$GAP_SECONDS"

  echo
  echo "==================================================================="
  echo "STEP 5: Attack demo traffic generation (${ATTACK_ID}, label=attack)"
  echo "  NOTE: preliminary/demo classes only (auth_abuse, resource_exhaustion,"
  echo "  injection_attempt) -- NOT the frozen Phase 2 corpus, and does not"
  echo "  include SSRF (handled separately)."
  echo "==================================================================="
  ATTACK_START=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  python3 scripts/collection/generate_attack_traffic.py \
    --class all --count "$ATTACK_COUNT" --out-dir data/raw/attack_demo
  ATTACK_END=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  echo "Recorded window: $ATTACK_START -> $ATTACK_END"

  ATTACK_EXPORT_START=$(date -u -d "$ATTACK_START -${WINDOW_PAD_SECONDS} seconds" +"%Y-%m-%dT%H:%M:%SZ")
  ATTACK_EXPORT_END=$(date -u -d "$ATTACK_END +${WINDOW_PAD_SECONDS} seconds" +"%Y-%m-%dT%H:%M:%SZ")

  echo
  echo "==================================================================="
  echo "STEP 6: Export Jaeger traces for ${ATTACK_ID}"
  echo "==================================================================="
  ./scripts/collection/export_jaeger_traces.sh --label attack --experiment "$ATTACK_ID" \
    --start "$ATTACK_EXPORT_START" --end "$ATTACK_EXPORT_END" --limit 20000

  echo
  echo "==================================================================="
  echo "STEP 7: Capture service logs for the SAME window (${ATTACK_ID})"
  echo "==================================================================="
  mkdir -p "data/raw/logs/${ATTACK_ID}"
  for p in $(kubectl get pods -o name -n default | grep '/ts-'); do
    svc=$(basename "$p")
    kubectl logs -n default "$p" --since-time="$ATTACK_EXPORT_START" \
      > "data/raw/logs/${ATTACK_ID}/${svc}.log" 2>/dev/null
    echo "  $svc: $(wc -l < "data/raw/logs/${ATTACK_ID}/${svc}.log") lines"
  done

  echo
  echo "==================================================================="
  echo "STEP 8: Corpus audit -- MUST report zero multi-label traces"
  echo "==================================================================="
  python3 scripts/preprocessing/corpus_audit.py \
    "data/raw/jaeger/${NORMAL_ID}_normal/*.json" \
    "data/raw/jaeger/${ATTACK_ID}_attack/*.json" \
    --by-filename-label | tee /tmp/reliability_corpus_audit_output.txt
  if grep -q "LABEL LEAKAGE" /tmp/reliability_corpus_audit_output.txt; then
    echo
    echo "!!! LABEL LEAKAGE DETECTED -- do NOT use this corpus for any paper"
    echo "!!! claim until this is resolved (see corpus_audit.py output above)."
  fi
else
  echo
  echo "==================================================================="
  echo "STEPS 4-8 skipped (--skip-attack): normal-only reliability re-run"
  echo "==================================================================="
fi

echo
echo "==================================================================="
echo "STEP 9: Parse traces to CSV + build feature tables"
echo "==================================================================="
python3 scripts/preprocessing/parse_jaeger_traces.py \
  --input-dir "data/raw/jaeger/${NORMAL_ID}_normal" \
  --output-dir "data/processed/traces/${NORMAL_ID}" --label normal

python3 scripts/feature_extraction/build_feature_table.py \
  --spans "data/processed/traces/${NORMAL_ID}/spans.csv" \
  --traces "data/processed/traces/${NORMAL_ID}/traces.csv" \
  --out "data/processed/combined/${NORMAL_ID}_features.csv"

if [[ "$SKIP_ATTACK" -eq 0 ]]; then
  python3 scripts/preprocessing/parse_jaeger_traces.py \
    --input-dir "data/raw/jaeger/${ATTACK_ID}_attack" \
    --output-dir "data/processed/traces/${ATTACK_ID}" --label attack

  python3 scripts/feature_extraction/build_feature_table.py \
    --spans "data/processed/traces/${ATTACK_ID}/spans.csv" \
    --traces "data/processed/traces/${ATTACK_ID}/traces.csv" \
    --out "data/processed/combined/${ATTACK_ID}_features.csv"
fi

echo
echo "==================================================================="
echo "STEP 10: Parse logs to CSV + join-rate check against the new traces"
echo "==================================================================="
python3 scripts/preprocessing/parse_service_logs.py \
  --input-dir "data/raw/logs/${NORMAL_ID}" \
  --output-dir "data/processed/logs/${NORMAL_ID}" \
  --experiment-id "$NORMAL_ID" \
  --traces-csv "data/processed/traces/${NORMAL_ID}/traces.csv"

if [[ "$SKIP_ATTACK" -eq 0 ]]; then
  python3 scripts/preprocessing/parse_service_logs.py \
    --input-dir "data/raw/logs/${ATTACK_ID}" \
    --output-dir "data/processed/logs/${ATTACK_ID}" \
    --experiment-id "$ATTACK_ID" \
    --traces-csv "data/processed/traces/${ATTACK_ID}/traces.csv"
fi

echo
echo "==================================================================="
echo "STEP 11: Reliability comparison -- ${BASELINE_ID} vs ${NORMAL_ID}"
echo "  (both label=normal, so grouped by experiment_id, not label)"
echo "==================================================================="
RELIABILITY_OUTDIR="results/reliability_check_${NORMAL_ID}"
if [[ -f "data/processed/combined/${BASELINE_ID}_features.csv" ]]; then
  python3 scripts/visualization/baseline_stats.py \
    --features "data/processed/combined/${BASELINE_ID}_features.csv" \
               "data/processed/combined/${NORMAL_ID}_features.csv" \
    --group-col experiment_id --compare --outdir "$RELIABILITY_OUTDIR"
else
  echo "SKIPPED: data/processed/combined/${BASELINE_ID}_features.csv not found."
  echo "Run build_feature_table.py for ${BASELINE_ID} first, or pass the"
  echo "correct --baseline-id."
fi

echo
echo "==================================================================="
echo "SUMMARY"
echo "==================================================================="
echo "Normal window : $NORMAL_START -> $NORMAL_END (exported $NORMAL_EXPORT_START -> $NORMAL_EXPORT_END)"
if [[ "$SKIP_ATTACK" -eq 0 ]]; then
  echo "Attack window : $ATTACK_START -> $ATTACK_END (exported $ATTACK_EXPORT_START -> $ATTACK_EXPORT_END)"
fi
echo "Jaeger raw    : data/raw/jaeger/${NORMAL_ID}_normal/$( [[ "$SKIP_ATTACK" -eq 0 ]] && echo ", data/raw/jaeger/${ATTACK_ID}_attack/" )"
echo "Features      : data/processed/combined/${NORMAL_ID}_features.csv$( [[ "$SKIP_ATTACK" -eq 0 ]] && echo ", ${ATTACK_ID}_features.csv" )"
echo "Reliability comparison tables/figures: ${RELIABILITY_OUTDIR}/"
echo
echo "Next: fill in metadata/${NORMAL_ID}_normal_baseline.md (+ metadata/${ATTACK_ID}.md"
echo "if collected) and a docs/phase_logs/phase_log_\$(date -u +%Y%m%d).md entry,"
echo "then update PHASE_1_CHECKLIST.md / PHASE_STATUS.md to mark the"
echo "reliability-check item Done, citing ${RELIABILITY_OUTDIR}/tables/stratified_comparison.csv."
