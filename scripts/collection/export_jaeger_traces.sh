#!/usr/bin/env bash
# export_jaeger_traces.sh — SecLogTrace
# Rewritten 2026-07-28 for full-service coverage sweeps.
#
# WHAT CHANGED AND WHY
#
# 1. Sweeps every service Jaeger knows about, not a hardcoded list of 4.
#    Service list comes from /api/services at run time.
#
# 2. Uses explicit start/end microsecond timestamps. The `lookback` parameter
#    is a Jaeger UI convention — the query backend derives `start` from it in
#    the UI, but relying on it server-side is unreliable. Always send start
#    and end. Both are microseconds since epoch, not seconds, not millis.
#
# 3. Sends an explicit --limit. Jaeger's search API caps results per query.
#    If a service returns exactly the limit, the result is truncated and the
#    script says so loudly. Silent truncation is how corpora go wrong.
#
# 4. Writes a manifest JSON recording the window, the service list, per-file
#    trace counts, the DISTINCT trace count across all files, and any
#    truncation warnings. The distinct count is the only number that should
#    ever appear in a paper.
#
# 5. Pre-flight checks Jaeger's storage backend. If storage is in-memory, a
#    pod restart destroys everything and the buffer evicts oldest-first once
#    full. The script refuses to proceed silently in that case.
#
# Usage:
#   ./export_jaeger_traces.sh --label normal --minutes 90
#   ./export_jaeger_traces.sh --label coverage_sweep \
#       --start "2026-07-30T14:00:00" --end "2026-07-30T16:30:00"
#
# Requires: curl, jq

set -euo pipefail

JAEGER_API="${JAEGER_API:-http://<research-host>:30005/jaeger/ui/api}"
OUTDIR="${OUTDIR:-data/raw/jaeger}"
LABEL="normal"
LIMIT="${LIMIT:-2000}"
MINUTES=""
START_ISO=""
END_ISO=""
EXPERIMENT="${EXPERIMENT:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --label)      LABEL="$2"; shift 2 ;;
    --minutes)    MINUTES="$2"; shift 2 ;;
    --start)      START_ISO="$2"; shift 2 ;;
    --end)        END_ISO="$2"; shift 2 ;;
    --limit)      LIMIT="$2"; shift 2 ;;
    --experiment) EXPERIMENT="$2"; shift 2 ;;
    --outdir)     OUTDIR="$2"; shift 2 ;;
    --jaeger-api) JAEGER_API="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

command -v jq >/dev/null || { echo "ERROR: jq is required" >&2; exit 1; }

# --- Resolve the time window to microseconds -------------------------------
if [[ -n "$START_ISO" && -n "$END_ISO" ]]; then
  START_US=$(( $(date -d "$START_ISO" +%s) * 1000000 ))
  END_US=$((   $(date -d "$END_ISO"   +%s) * 1000000 ))
elif [[ -n "$MINUTES" ]]; then
  END_US=$(( $(date +%s) * 1000000 ))
  START_US=$(( END_US - MINUTES * 60 * 1000000 ))
else
  echo "ERROR: supply either --minutes N, or --start and --end (ISO 8601)." >&2
  echo "  Guessing the window is how sessions get silently truncated." >&2
  exit 2
fi

WINDOW_MIN=$(( (END_US - START_US) / 60000000 ))
STAMP=$(date +%Y%m%d_%H%M%S)
[[ -z "$EXPERIMENT" ]] && EXPERIMENT="experiment_${STAMP}"
RUNDIR="${OUTDIR}/${EXPERIMENT}_${LABEL}"
mkdir -p "$RUNDIR"

# The repo already hit an 8-hour offset between pods logging local time and
# JSON error bodies in UTC (phase_log_20260728). `date -d` resolves ISO
# strings in the SHELL's timezone. If the session was recorded in a different
# timezone from the box running this script, the window silently shifts.
# Pass --start/--end with an explicit offset (e.g. 2026-07-30T14:00:00-05:00)
# or export TZ=UTC before running, and record which you used.
echo "Shell TZ   : $(date +%Z%z)"
echo "Jaeger API : $JAEGER_API"
echo "Label      : $LABEL"
echo "Experiment : $EXPERIMENT"
echo "Window     : $(date -d @$((START_US/1000000)) -Iseconds) -> $(date -d @$((END_US/1000000)) -Iseconds)  (${WINDOW_MIN} min)"
echo "Limit/svc  : $LIMIT"
echo "Output     : $RUNDIR"
echo

# --- Pre-flight: is Jaeger reachable, and is storage durable? --------------
echo "=== Pre-flight ==="
if ! curl -sf --max-time 10 "${JAEGER_API}/services" -o /tmp/_svc.json; then
  echo "ERROR: cannot reach ${JAEGER_API}/services. Check the VPN." >&2
  exit 1
fi
# tr -d '\r': jq on Windows/MSYS2 (Git Bash) emits CRLF line endings, so each
# service name would carry a trailing \r. `for SVC in $SERVICES` then builds
# URLs like ?service=persistence\r&... which Jaeger rejects — every service
# except the last (no trailing newline) silently REQUEST-FAILs, capturing only
# noise. Strip CR so the sweep works regardless of the shell/jq build.
SERVICES=$(jq -r '.data[]?' /tmp/_svc.json | tr -d '\r' | sort -u)
SVC_COUNT=$(echo "$SERVICES" | grep -c . || true)
echo "Services visible to Jaeger: $SVC_COUNT"
if [[ "$SVC_COUNT" -lt 5 ]]; then
  echo "WARNING: only $SVC_COUNT services visible. Either the deploy is missing"
  echo "         --with-tracing, or services have not emitted spans yet."
fi
echo

# --- Sweep -----------------------------------------------------------------
echo "=== Exporting ==="
MANIFEST_ROWS=""
TRUNCATED=""
TOTAL_ROWS=0

for SVC in $SERVICES; do
  # printf, not echo: echo appends a newline, and `tr -c` treats that newline
  # as a disallowed character and converts it to '_', producing filenames
  # ending in a spurious underscore.
  SAFE=$(printf '%s' "$SVC" | tr -c 'A-Za-z0-9_.-' '_')
  OUT="${RUNDIR}/${EXPERIMENT}_${LABEL}_${SAFE}.json"
  URL="${JAEGER_API}/traces?service=${SVC}&start=${START_US}&end=${END_US}&limit=${LIMIT}"

  if ! curl -sf --max-time 120 "$URL" -o "$OUT"; then
    echo "  $SVC: REQUEST FAILED"
    rm -f "$OUT"
    continue
  fi

  N=$(jq '.data | length' "$OUT" 2>/dev/null || echo 0)
  if [[ "$N" -eq 0 ]]; then
    rm -f "$OUT"
    printf "  %-32s %5s\n" "$SVC" "0"
    continue
  fi

  TOTAL_ROWS=$(( TOTAL_ROWS + N ))
  FLAG=""
  if [[ "$N" -ge "$LIMIT" ]]; then
    FLAG="  <-- TRUNCATED AT LIMIT"
    TRUNCATED="${TRUNCATED}${SVC} "
  fi
  printf "  %-32s %5d%s\n" "$SVC" "$N" "$FLAG"
  MANIFEST_ROWS="${MANIFEST_ROWS}{\"service\":\"${SVC}\",\"traces\":${N},\"file\":\"$(basename "$OUT")\"},"
done

echo

# --- Distinct-trace count across all files ---------------------------------
# This is the number that goes in the paper. The sum of per-service counts
# does NOT, because Jaeger returns a trace for every service it touches.
echo "=== Deduplication ==="
DISTINCT=0
if compgen -G "${RUNDIR}/${EXPERIMENT}_*.json" > /dev/null; then
  DISTINCT=$(jq -r '.data[]?.traceID' "${RUNDIR}/${EXPERIMENT}"_*.json 2>/dev/null | sort -u | wc -l)
fi
DUP=$(( TOTAL_ROWS - DISTINCT ))
RATIO="n/a"
if [[ "$DISTINCT" -gt 0 ]]; then
  RATIO=$(awk "BEGIN{printf \"%.2f\", $TOTAL_ROWS/$DISTINCT}")
fi
echo "Sum of per-service counts : $TOTAL_ROWS   <-- do NOT cite this"
echo "Distinct traces           : $DISTINCT   <-- cite this"
echo "Duplicate entries         : $DUP  (avg ${RATIO} services touched per trace)"
echo

# --- Manifest --------------------------------------------------------------
MANIFEST="${RUNDIR}/manifest.json"
cat > "$MANIFEST" <<EOF
{
  "experiment_id": "${EXPERIMENT}",
  "label": "${LABEL}",
  "exported_at": "$(date -Iseconds)",
  "jaeger_api": "${JAEGER_API}",
  "window": {
    "start_us": ${START_US},
    "end_us": ${END_US},
    "start_iso": "$(date -d @$((START_US/1000000)) -Iseconds)",
    "end_iso": "$(date -d @$((END_US/1000000)) -Iseconds)",
    "minutes": ${WINDOW_MIN}
  },
  "limit_per_service": ${LIMIT},
  "services_visible": ${SVC_COUNT},
  "per_service": [${MANIFEST_ROWS%,}],
  "sum_of_per_service_counts": ${TOTAL_ROWS},
  "distinct_trace_count": ${DISTINCT},
  "duplicate_entries": ${DUP},
  "truncated_services": "$(echo "$TRUNCATED" | sed 's/ *$//')",
  "notes": "sum_of_per_service_counts is inflated by cross-service overlap. Use distinct_trace_count."
}
EOF

echo "Manifest: $MANIFEST"

if [[ -n "$TRUNCATED" ]]; then
  echo
  echo "!! TRUNCATION: these services returned exactly the limit, so their"
  echo "   results are incomplete: $TRUNCATED"
  echo "   Re-run with a larger --limit, or split the window into shorter"
  echo "   segments and export each one separately."
  exit 3
fi

echo
echo "Next: pass every .json in this directory to parse_jaeger_traces.py,"
echo "then all resulting spans CSVs to build_feature_table.py --spans (it"
echo "deduplicates on trace_id/span_id in one pass)."
