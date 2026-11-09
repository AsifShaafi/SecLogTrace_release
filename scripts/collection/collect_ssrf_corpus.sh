#!/usr/bin/env bash
# collect_ssrf_corpus.sh [count] [image_file]
#
# SSRF corpus-scale collection. SSRF uses its OWN generator
# (generate_ssrf_traffic.py) and hits the avatar service DIRECTLY on port
# 17001 (it is not gateway-routed), so it can't share collect_abuse_corpus.sh
# (different generator, different session-log naming: ssrf_normal_*.jsonl and
# ssrf_ssrf_*.jsonl). Everything after traffic generation — windowed export,
# log capture, the zero-leakage audit gate, parse/features/logs — matches the
# abuse pipeline.
#
#   count : requests PER LABEL (default 150).
#   image : the normal-class face image (default external/pic.jpg — verified
#           2026-09-04 to return HTTP 200 from the avatar endpoint). A real
#           face is REQUIRED; the placeholder PNG returns 500 (dlib rejects it).
#
# Two SSRF-specific timing notes:
#   - The attack set is weighted across 3 targets; the closed-port target
#     times out ~10s each, so the attack window runs several minutes at N=150.
#   - Larger export pad (15s) to comfortably cover those slow traces.
#
# Run ON THE SERVER, from ~/SecLogTrace.
set -uo pipefail
export TZ=UTC
cd ~/SecLogTrace || { echo "FATAL: ~/SecLogTrace not found"; exit 1; }

COUNT="${1:-150}"
IMG="${2:-external/pic.jpg}"
URL="http://<research-host>:17001/api/v1/avatar"
EXP="ssrf"
PAD=15
GAP=60
GEN="python3 scripts/collection/generate_ssrf_traffic.py --url $URL"

# --- preflight ---
command -v jq >/dev/null || { echo "FATAL: jq not found"; exit 1; }
command -v kubectl >/dev/null || { echo "FATAL: kubectl not found"; exit 1; }
kubectl get pods -n default >/dev/null 2>&1 || { echo "FATAL: kubectl can't reach the cluster (VPN/kubeconfig?)"; exit 1; }
python3 -c "import pandas, numpy" 2>/dev/null || { echo "FATAL: pandas/numpy missing"; exit 1; }
[ -f "$IMG" ] || { echo "FATAL: normal-class image '$IMG' not found"; exit 1; }
if [ -d "data/raw/jaeger/${EXP}_normal" ] || [ -d "data/raw/jaeger/${EXP}_attack" ]; then
  echo "FATAL: data/raw/jaeger/${EXP}_{normal,attack} already exists -- move/remove it first."; exit 1
fi
code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$URL" 2>/dev/null || echo 000)
echo "avatar endpoint preflight ($URL): HTTP $code (404/405 on GET is fine; the service is up)"

echo "==================================================================="
echo "SSRF CORPUS COLLECTION  (count=$COUNT per label, image=$IMG)"
echo "  attack window is several minutes at N=$COUNT (closed-port timeouts)."
echo "==================================================================="

echo; echo "STEP 1: normal traffic ($COUNT base64 uploads of $IMG)"
$GEN --mode normal --count "$COUNT" --normal-image-file "$IMG"

echo; echo "STEP 2: ${GAP}s gap"
sleep "$GAP"

echo; echo "STEP 3: attack traffic ($COUNT SSRF requests, weighted targets)"
$GEN --mode ssrf --count "$COUNT"

# --- windows from the two session logs (normal: ssrf_normal_*; attack: ssrf_ssrf_*) ---
f_n=$(ls -t data/raw/traffic/ssrf_normal_*.jsonl | head -1)
f_a=$(ls -t data/raw/traffic/ssrf_ssrf_*.jsonl | head -1)
ts(){ python3 -c 'import sys,json;print(json.loads(sys.stdin.read())["ts"])'; }
ns=$(date -u -d "$(head -1 "$f_n" | ts) -${PAD} seconds" +"%Y-%m-%dT%H:%M:%SZ")
ne=$(date -u -d "$(tail -1 "$f_n" | ts) +${PAD} seconds" +"%Y-%m-%dT%H:%M:%SZ")
as=$(date -u -d "$(head -1 "$f_a" | ts) -${PAD} seconds" +"%Y-%m-%dT%H:%M:%SZ")
ae=$(date -u -d "$(tail -1 "$f_a" | ts) +${PAD} seconds" +"%Y-%m-%dT%H:%M:%SZ")
echo; echo "windows -> normal $ns .. $ne | attack $as .. $ae"

for w in normal attack; do
  [ "$w" = normal ] && { s=$ns; e=$ne; } || { s=$as; e=$ae; }
  echo; echo "STEP 4/$w: export Jaeger traces"
  ./scripts/collection/export_jaeger_traces.sh --label "$w" --experiment "$EXP" \
    --start "$s" --end "$e" --limit 20000
  echo "STEP 5/$w: capture logs (same window start)"
  mkdir -p "data/raw/logs/${EXP}_${w}"
  for p in $(kubectl get pods -o name -n default | grep '/ts-'); do
    svc=$(basename "$p")
    kubectl logs -n default "$p" --since-time="$s" > "data/raw/logs/${EXP}_${w}/${svc}.log" 2>/dev/null
  done
  echo "  logs: $(ls "data/raw/logs/${EXP}_${w}/" | wc -l) files"
done

echo; echo "==================================================================="
echo "STEP 6: AUDIT GATE -- must report ZERO multi-label traces"
echo "==================================================================="
AUDIT=/tmp/${EXP}_corpus_audit.txt
python3 scripts/preprocessing/corpus_audit.py \
  "data/raw/jaeger/${EXP}_normal/*.json" "data/raw/jaeger/${EXP}_attack/*.json" \
  --by-filename-label | tee "$AUDIT"
LEAK=$(grep "MORE THAN ONE label" "$AUDIT" | grep -oE '[0-9]+$')
if [ "${LEAK:-x}" != "0" ]; then
  echo; echo "!!! LABEL LEAKAGE ($LEAK) -- re-export/re-collect; stopping before parse."; exit 3
fi
echo "GATE PASSED: zero multi-label traces."

echo; echo "STEP 7: parse -> feature table -> logs (both windows)"
for w in normal attack; do
  python3 scripts/preprocessing/parse_jaeger_traces.py --label "$w" \
    --input-dir  "data/raw/jaeger/${EXP}_${w}" \
    --output-dir "data/processed/traces/${EXP}_${w}"
  python3 scripts/feature_extraction/build_feature_table.py \
    --spans  "data/processed/traces/${EXP}_${w}/spans.csv" \
    --traces "data/processed/traces/${EXP}_${w}/traces.csv" \
    --out    "data/processed/combined/${EXP}_${w}_features.csv"
  python3 scripts/preprocessing/parse_service_logs.py \
    --input-dir  "data/raw/logs/${EXP}_${w}" \
    --output-dir "data/processed/logs/${EXP}_${w}" \
    --experiment-id "${EXP}_${w}" \
    --traces-csv "data/processed/traces/${EXP}_${w}/traces.csv"
done

echo; echo "==================================================================="
echo "DONE: SSRF corpus collected + audited clean."
echo "  NOTE: ts-avatar-service is Python/Flask -- parse_service_logs.py flags"
echo "  its lines UNPARSED (known gap). The trace side is SSRF's main signal."
echo "  features: data/processed/combined/ssrf_{normal,attack}_features.csv"
echo "==================================================================="
