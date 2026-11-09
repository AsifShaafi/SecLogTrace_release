#!/usr/bin/env bash
# enable_trace_id_logging.sh — SecLogTrace Phase 1, checklist item 6
#
# Turns on trace_id/span_id in Train-Ticket application logs.
#
# NO IMAGE REBUILD IS NEEDED. check_log_correlation.sh found the OTel Java
# agent already attached and found no logback.xml or log4j2.xml on disk,
# which means logging config is packed inside the fat jar. Spring Boot's
# relaxed binding lets an environment variable override it anyway:
# `logging.pattern.level` becomes `LOGGING_PATTERN_LEVEL`. That is a
# Deployment env change, not a fork.
#
# The agent's logback-mdc instrumentation is on by default and populates the
# MDC keys trace_id / span_id / trace_flags. They are already there — they
# are simply not in the output pattern.
#
# Run in two stages. Stage 1 confirms the key names on one service before
# touching the other forty.
#
#   ./enable_trace_id_logging.sh probe
#   ./enable_trace_id_logging.sh apply
#   ./enable_trace_id_logging.sh verify
#   ./enable_trace_id_logging.sh revert
#
# WARNING: apply and probe both trigger rolling restarts. Jaeger's in-memory
# store is wiped by a Jaeger restart, not by these, but any traces collected
# between now and the sweep are disposable anyway. Do this BEFORE the
# coverage sweep, never after.

set -euo pipefail

NS="${NS:-default}"
PROBE_SVC="${PROBE_SVC:-ts-travel-service}"

# %mdc with no key dumps the entire MDC map. Used only for the probe, so we
# discover the real key names instead of assuming them.
PROBE_PATTERN='MDCDUMP[%mdc] %5p'

# Documented OTel pattern. Keys per the logback-mdc-1.0 README.
APPLY_PATTERN='trace_id=%mdc{trace_id} span_id=%mdc{span_id} trace_flags=%mdc{trace_flags} %5p'

targets() {
  kubectl get deploy -n "$NS" -o name | grep '/ts-'
}

case "${1:-}" in

  probe)
    echo "Setting a full-MDC dump pattern on $PROBE_SVC only."
    echo "This reveals the actual MDC key names rather than assuming them."
    echo
    kubectl set env -n "$NS" "deployment/$PROBE_SVC" \
      LOGGING_PATTERN_LEVEL="$PROBE_PATTERN"
    kubectl rollout status -n "$NS" "deployment/$PROBE_SVC" --timeout=180s
    echo
    echo "Now drive one request through $PROBE_SVC (a trip search is enough),"
    echo "then run:  $0 verify"
    echo
    echo "You are looking for a line like:"
    echo "  MDCDUMP[trace_id=4bf92f..., span_id=00f067..., trace_flags=01] INFO"
    echo
    echo "If the keys come back as traceId/spanId instead of trace_id/span_id,"
    echo "the agent is an older build — edit APPLY_PATTERN at the top of this"
    echo "script to match before running apply."
    echo
    echo "If the brackets are empty, LOGGING_PATTERN_LEVEL is not being read."
    echo "Fall back to LOGGING_PATTERN_CONSOLE, which overrides the whole"
    echo "console pattern rather than just the level field."
    ;;

  apply)
    echo "Applying trace_id logging to every ts-* deployment in $NS."
    echo "Pattern: $APPLY_PATTERN"
    echo
    N=0
    for d in $(targets); do
      kubectl set env -n "$NS" "$d" LOGGING_PATTERN_LEVEL="$APPLY_PATTERN" >/dev/null
      echo "  set: $d"
      N=$((N + 1))
    done
    echo
    echo "$N deployments updated. Waiting for rollouts."
    for d in $(targets); do
      kubectl rollout status -n "$NS" "$d" --timeout=300s || \
        echo "  TIMEOUT/FAILED: $d  <-- investigate before the sweep"
    done
    echo
    echo "Done. Run: $0 verify"
    ;;

  verify)
    echo "=== Checking for trace context in recent log lines ==="
    ANY=0
    for d in $(targets); do
      SVC=$(basename "$d")
      POD=$(kubectl get pods -n "$NS" -l "app=$SVC" -o name 2>/dev/null | head -1)
      [[ -z "$POD" ]] && POD=$(kubectl get pods -n "$NS" -o name | grep -m1 "$SVC" || true)
      [[ -z "$POD" ]] && continue
      HIT=$(kubectl logs -n "$NS" "$POD" --tail=300 2>/dev/null \
            | grep -cE 'trace_id=[0-9a-f]{8}|MDCDUMP' || true)
      if [[ "${HIT:-0}" -gt 0 ]]; then
        printf "  %-34s %3d lines with trace context\n" "$SVC" "$HIT"
        ANY=$((ANY + 1))
        kubectl logs -n "$NS" "$POD" --tail=300 2>/dev/null \
          | grep -m1 -E 'trace_id=[0-9a-f]{8}|MDCDUMP' | sed 's/^/      /'
      else
        printf "  %-34s none\n" "$SVC"
      fi
    done
    echo
    if [[ "$ANY" -eq 0 ]]; then
      echo "No trace context found anywhere."
      echo "Either no traffic has run since the restart — drive a booking and"
      echo "retry — or LOGGING_PATTERN_LEVEL is not being honoured. In that"
      echo "case try LOGGING_PATTERN_CONSOLE instead."
    else
      echo "$ANY services emitting trace context."
      echo
      echo "END-TO-END CHECK, do not skip this:"
      echo "  1. Drive one booking through the UI"
      echo "  2. Pull a trace_id out of a log line"
      echo "  3. Open http://<research-host>:30005/jaeger/ui/trace/<that_id>"
      echo "  4. Confirm it resolves to a real trace"
      echo "A trace_id that formats correctly but does not resolve in Jaeger"
      echo "means the join key is useless. Confirm before the sweep."
    fi
    ;;

  revert)
    echo "Removing LOGGING_PATTERN_LEVEL from all ts-* deployments."
    for d in $(targets); do
      kubectl set env -n "$NS" "$d" LOGGING_PATTERN_LEVEL- >/dev/null
      echo "  reverted: $d"
    done
    ;;

  *)
    echo "Usage: $0 {probe|apply|verify|revert}"
    echo
    echo "Order: probe -> drive traffic -> verify -> apply -> verify"
    exit 2
    ;;
esac
