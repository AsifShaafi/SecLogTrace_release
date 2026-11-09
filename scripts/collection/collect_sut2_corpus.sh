#!/usr/bin/env bash
# collect_sut2_corpus.sh <class> [count]
#
# SUT2 (TeaStore) corpus collection, TRACES + LOGS. Mirrors the SUT1
# collect_abuse_corpus.sh discipline (normal window -> 60s gap -> attack
# window -> windowed export -> the zero-leakage audit gate -> parse/features),
# with two SUT2-specific differences:
#   - traffic via generate_sut2_traffic.py; traces from the local OTel Jaeger
#     (http://localhost:16686/api), not the server Jaeger;
#   - logs captured from `docker compose logs` per service (not kubectl).
#
#   class : credential_abuse | resource_exhaustion | injection |
#           data_exfiltration | ssrf
#   count : requests PER LABEL (default 15 -> a pilot; use 500 for v2 corpus).
#
# Window precision: each window's [start,end] is derived from the first/last
# request timestamp in the generator's JSONL session log, which EXCLUDES the
# generator's seed-discovery GETs (those are not logged via fire()). This keeps
# benign discovery traffic out of the attack window.
#
# Run from the SecLogTrace repo root. TeaStore is a separate clone; point
# TEASTORE_COMPOSE at its docker-compose_otel.yaml (default assumes the sibling
# layout ../TeaStore/examples/docker/).
set -uo pipefail
export TZ=UTC
cd "$(dirname "$0")/../.." || { echo "FATAL: cannot find repo root"; exit 1; }

CLASS="${1:?usage: collect_sut2_corpus.sh <class> [count] [pace]}"
COUNT="${2:-15}"
# Inter-request pace (s). Lower = faster collection. SAFE to lower for
# credential_abuse/injection/data_exfiltration/ssrf (their signals are per-trace,
# not rate-based). DO NOT lower for resource_exhaustion: its attack is an unpaced
# burst and normal uses this pace, so the pace IS the class's rate contrast.
PACE="${3:-2.0}"
PADS=0          # NO pad before window start: the generator's seed-discovery GETs
                # run 1-2s before the first logged request, so any start pad would
                # pull them in and mislabel them. Server spans start at/after the
                # client request ts, so PADS=0 loses no real request.
PADE=12         # pad after each window end (a span may finish late); < the 60s gap
GAP=60
COMPOSE="${TEASTORE_COMPOSE:-../TeaStore/examples/docker/docker-compose_otel.yaml}"
JAEGER_API="${JAEGER_API:-http://localhost:16686/api}"
LOGSVCS="webui image persistence auth recommender"
# Pick the interpreter that actually has `requests` (on Windows `python3` may be
# a non-functional Store stub; on the server it is the real one).
PY=""
for c in python3 python py; do
  if command -v "$c" >/dev/null 2>&1 && "$c" -c "import requests" >/dev/null 2>&1; then PY="$c"; break; fi
done

case "$CLASS" in credential_abuse|resource_exhaustion|injection|data_exfiltration|ssrf) ;;
  *) echo "FATAL: unknown class '$CLASS'"; exit 2 ;; esac

# --- preflight ---
command -v jq >/dev/null   || { echo "FATAL: jq not found"; exit 1; }
command -v docker >/dev/null || { echo "FATAL: docker not found"; exit 1; }
[ -n "$PY" ] || { echo "FATAL: python not found"; exit 1; }
[ -f "$COMPOSE" ] || { echo "FATAL: compose file not found: $COMPOSE (set TEASTORE_COMPOSE)"; exit 1; }
"$PY" -c "import requests" 2>/dev/null || { echo "FATAL: python 'requests' missing"; exit 1; }
curl -sf --max-time 10 "${JAEGER_API}/services" -o /dev/null || { echo "FATAL: Jaeger not reachable at $JAEGER_API (is the OTel stack up?)"; exit 1; }
# v2 is namespaced sut2v2_ so it never collides with the frozen v1 SUT2
# (trace-only, sut2_) data in the working tree — no branch needed.
EXPERIMENT="sut2v2_${CLASS}"
if [ -d "data/raw/jaeger/${EXPERIMENT}_normal" ] || [ -d "data/raw/jaeger/${EXPERIMENT}_attack" ]; then
  echo "FATAL: data/raw/jaeger/${EXPERIMENT}_{normal,attack} already exists -- move/remove it or this run would mix data."; exit 1
fi
TRACES_OUT="data/processed/traces/${EXPERIMENT}"
LOGS_OUT="data/processed/logs/${EXPERIMENT}"
LOGRAW="data/raw/logs/${EXPERIMENT}"
mkdir -p "$TRACES_OUT" "$LOGS_OUT" "$LOGRAW" data/raw/traffic

iso_epoch() { date -u -d "$1" +%s; }
epoch_iso() { date -u -d "@$1" +%Y-%m-%dT%H:%M:%SZ; }
# first/last request ts from a JSONL session log (ISO sorts chronologically)
win_start() { jq -rs 'min_by(.ts).ts' "$1"; }
win_end()   { jq -rs 'max_by(.ts).ts' "$1"; }

run_window() {   # $1=mode(normal|attack)  -> sets WSTART/WEND (padded ISO)
  local mode="$1"
  echo; echo "=== $CLASS / $mode : $COUNT requests ==="
  "$PY" scripts/collection/generate_sut2_traffic.py --class "$CLASS" --mode "$mode" --count "$COUNT" --pace "$PACE"
  local jf; jf="$(ls -t data/raw/traffic/sut2_${CLASS}_${mode}_*.jsonl 2>/dev/null | head -1)"
  [ -n "$jf" ] || { echo "FATAL: no session log for $mode"; exit 1; }
  local s e; s="$(win_start "$jf")"; e="$(win_end "$jf")"
  WSTART="$(epoch_iso $(( $(iso_epoch "$s") - PADS )))"
  WEND="$(epoch_iso $(( $(iso_epoch "$e") + PADE )))"
  echo "  window ($mode): $WSTART .. $WEND   (from $(basename "$jf"))"
}

capture() {   # $1=label  $2=start  $3=end  -> export traces + docker logs for the window
  local label="$1" start="$2" end="$3"
  echo "  exporting traces ($label)..."
  JAEGER_API="$JAEGER_API" LIMIT="${LIMIT:-5000}" \
    scripts/collection/export_jaeger_traces.sh \
      --experiment "$EXPERIMENT" --label "$label" --start "$start" --end "$end" --jaeger-api "$JAEGER_API"
  echo "  capturing logs ($label)..."
  local ld="${LOGRAW}/${label}"; mkdir -p "$ld"
  for svc in $LOGSVCS; do
    docker compose -f "$COMPOSE" logs --no-log-prefix --since "$start" --until "$end" "$svc" 2>/dev/null \
      > "${ld}/${svc}.log"
  done
}

# --- normal window ---
run_window normal;  N_START="$WSTART"; N_END="$WEND"
echo; echo "--- ${GAP}s gap ---"; sleep "$GAP"
# --- attack window ---
run_window attack;  A_START="$WSTART"; A_END="$WEND"

echo; echo "=== export + log capture ==="
capture normal "$N_START" "$N_END"
capture attack "$A_START" "$A_END"

echo; echo "=== AUDIT GATE (must be ZERO multi-label) ==="
"$PY" scripts/preprocessing/corpus_audit.py \
  data/raw/jaeger/${EXPERIMENT}_normal/*.json \
  data/raw/jaeger/${EXPERIMENT}_attack/*.json \
  --by-filename-label

echo; echo "=== parse traces (normal, then attack --append) ==="
"$PY" scripts/preprocessing/parse_jaeger_traces.py --input-dir "data/raw/jaeger/${EXPERIMENT}_normal" --output-dir "$TRACES_OUT" --label normal
"$PY" scripts/preprocessing/parse_jaeger_traces.py --input-dir "data/raw/jaeger/${EXPERIMENT}_attack" --output-dir "$TRACES_OUT" --label attack --append

echo; echo "=== parse logs (both windows) + join report ==="
# flatten the per-label log dirs into one input dir (service.log names are reused,
# so suffix by label to keep both)
PARSELOGS="${LOGS_OUT}/_raw"; mkdir -p "$PARSELOGS"
for label in normal attack; do
  for f in "${LOGRAW}/${label}"/*.log; do [ -f "$f" ] && cp "$f" "${PARSELOGS}/$(basename "${f%.log}")_${label}.log"; done
done
"$PY" scripts/preprocessing/parse_service_logs.py --input-dir "$PARSELOGS" --output-dir "$LOGS_OUT" --experiment-id "$EXPERIMENT" --traces-csv "${TRACES_OUT}/traces.csv"

echo; echo "=== build combined feature table ==="
"$PY" scripts/feature_extraction/build_feature_table.py --spans "${TRACES_OUT}/spans.csv" --traces "${TRACES_OUT}/traces.csv" --out "data/processed/combined/${EXPERIMENT}_features.csv"

echo; echo "DONE: $CLASS (count=$COUNT). Review the AUDIT GATE output above:"
echo "  require ZERO multi-label traces and real ~= ${COUNT} normal + ${COUNT} attack before trusting."
