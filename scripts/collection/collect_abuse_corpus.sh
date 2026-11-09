#!/usr/bin/env bash
# collect_abuse_corpus.sh <class> [count]
#
# Full corpus-scale collection for ONE no-code-change abuse class, following
# the same discipline as the pilots: normal window -> 60s gap -> attack
# window -> windowed export -> log capture -> the zero-leakage audit gate ->
# parse + feature table + log parse. Generalizes the pilot workflow to any
# --count (default 150).
#
#   class : credential_abuse | resource_exhaustion | injection | data_exfiltration
#   count : requests PER LABEL (default 150) -> ~150 normal + ~150 attack real
#           traces (1 real trace per request; infra noise is filtered out).
#
# SSRF is NOT handled here (it uses generate_ssrf_traffic.py) -- see the
# separate SSRF commands in the handoff / ADVISOR notes.
#
# Run ON THE SERVER (gateway + Jaeger + kubectl reachable), from ~/SecLogTrace.
# Combined log:  ./collect_abuse_corpus.sh injection 2>&1 | tee \
#                  docs/daily_logs/corpus_injection_$(date -u +%Y%m%d).md
#
# No `set -e`: export_jaeger_traces.sh exits non-zero on a truncation warning,
# which is informative, not fatal.
set -uo pipefail
export TZ=UTC
cd ~/SecLogTrace || { echo "FATAL: ~/SecLogTrace not found"; exit 1; }

CLASS="${1:?usage: collect_abuse_corpus.sh <credential_abuse|resource_exhaustion|injection|data_exfiltration> [count]}"
COUNT="${2:-150}"
PAD=10          # export-window pad per side (< the 60s inter-window gap, so no overlap)
GAP=60          # gap between the normal and attack windows
GEN="python3 scripts/collection/generate_abuse_traffic.py --class $CLASS"

case "$CLASS" in
  credential_abuse|resource_exhaustion|injection|data_exfiltration) ;;
  *) echo "FATAL: unknown class '$CLASS' (SSRF is collected separately)"; exit 2 ;;
esac

# --- preflight ---
command -v jq >/dev/null || { echo "FATAL: jq not found"; exit 1; }
command -v kubectl >/dev/null || { echo "FATAL: kubectl not found"; exit 1; }
kubectl get pods -n default >/dev/null 2>&1 || { echo "FATAL: kubectl can't reach the cluster (VPN/kubeconfig?)"; exit 1; }
python3 -c "import pandas, numpy" 2>/dev/null || { echo "FATAL: pandas/numpy missing -- pip install -r scripts/feature_extraction/requirements.txt"; exit 1; }
if [ -d "data/raw/jaeger/${CLASS}_normal" ] || [ -d "data/raw/jaeger/${CLASS}_attack" ]; then
  echo "FATAL: data/raw/jaeger/${CLASS}_{normal,attack} already exists -- move/remove it or this run would mix data."; exit 1
fi

echo "==================================================================="
echo "CORPUS COLLECTION: $CLASS  (count=$COUNT per label)"
echo "  NOTE: attack windows are bursts for credential_abuse/resource_exhaustion/"
echo "  data_exfiltration -- a real load spike on the shared server. injection is"
echo "  paced (~${COUNT}x2s per window). Expect roughly 8-12 min total."
echo "==================================================================="

echo; echo "STEP 1: normal traffic ($COUNT)"
$GEN --mode normal --count "$COUNT"

echo; echo "STEP 2: ${GAP}s gap (keeps the export windows separable)"
sleep "$GAP"

echo; echo "STEP 3: attack traffic ($COUNT)"
$GEN --mode attack --count "$COUNT"

# --- windows from the two session logs (UTC ts), padded by $PAD ---
f_n=$(ls -t data/raw/traffic/${CLASS}_normal_*.jsonl | head -1)
f_a=$(ls -t data/raw/traffic/${CLASS}_attack_*.jsonl | head -1)
ts(){ python3 -c 'import sys,json;print(json.loads(sys.stdin.read())["ts"])'; }
ns=$(date -u -d "$(head -1 "$f_n" | ts) -${PAD} seconds" +"%Y-%m-%dT%H:%M:%SZ")
ne=$(date -u -d "$(tail -1 "$f_n" | ts) +${PAD} seconds" +"%Y-%m-%dT%H:%M:%SZ")
as=$(date -u -d "$(head -1 "$f_a" | ts) -${PAD} seconds" +"%Y-%m-%dT%H:%M:%SZ")
ae=$(date -u -d "$(tail -1 "$f_a" | ts) +${PAD} seconds" +"%Y-%m-%dT%H:%M:%SZ")
echo; echo "windows -> normal $ns .. $ne | attack $as .. $ae"

for w in normal attack; do
  [ "$w" = normal ] && { s=$ns; e=$ne; } || { s=$as; e=$ae; }
  echo; echo "STEP 4/$w: export Jaeger traces"
  ./scripts/collection/export_jaeger_traces.sh --label "$w" --experiment "$CLASS" \
    --start "$s" --end "$e" --limit 20000
  echo "STEP 5/$w: capture logs (same window start)"
  mkdir -p "data/raw/logs/${CLASS}_${w}"
  for p in $(kubectl get pods -o name -n default | grep '/ts-'); do
    svc=$(basename "$p")
    kubectl logs -n default "$p" --since-time="$s" > "data/raw/logs/${CLASS}_${w}/${svc}.log" 2>/dev/null
  done
  echo "  logs: $(ls "data/raw/logs/${CLASS}_${w}/" | wc -l) files"
done

echo; echo "==================================================================="
echo "STEP 6: AUDIT GATE -- must report ZERO multi-label traces"
echo "==================================================================="
AUDIT=/tmp/${CLASS}_corpus_audit.txt
python3 scripts/preprocessing/corpus_audit.py \
  "data/raw/jaeger/${CLASS}_normal/*.json" "data/raw/jaeger/${CLASS}_attack/*.json" \
  --by-filename-label | tee "$AUDIT"
LEAK=$(grep "MORE THAN ONE label" "$AUDIT" | grep -oE '[0-9]+$')
if [ "${LEAK:-x}" != "0" ]; then
  echo; echo "!!! LABEL LEAKAGE ($LEAK multi-label traces) -- DO NOT use this class until fixed."
  echo "!!! Windows likely overlapped; re-export or re-collect. Stopping before parse."; exit 3
fi
echo "GATE PASSED: zero multi-label traces."

echo; echo "STEP 7: parse -> feature table -> logs (both windows)"
for w in normal attack; do
  python3 scripts/preprocessing/parse_jaeger_traces.py --label "$w" \
    --input-dir  "data/raw/jaeger/${CLASS}_${w}" \
    --output-dir "data/processed/traces/${CLASS}_${w}"
  python3 scripts/feature_extraction/build_feature_table.py \
    --spans  "data/processed/traces/${CLASS}_${w}/spans.csv" \
    --traces "data/processed/traces/${CLASS}_${w}/traces.csv" \
    --out    "data/processed/combined/${CLASS}_${w}_features.csv"
  python3 scripts/preprocessing/parse_service_logs.py \
    --input-dir  "data/raw/logs/${CLASS}_${w}" \
    --output-dir "data/processed/logs/${CLASS}_${w}" \
    --experiment-id "${CLASS}_${w}" \
    --traces-csv "data/processed/traces/${CLASS}_${w}/traces.csv"
done

echo; echo "==================================================================="
echo "DONE: $CLASS corpus collected + audited clean."
echo "  features: data/processed/combined/${CLASS}_{normal,attack}_features.csv"
echo "  Next: fill metadata/${CLASS}.md, then repeat for the other classes."
echo "  When all 5 are in, run corpus_audit across ALL classes together before freeze."
echo "==================================================================="
