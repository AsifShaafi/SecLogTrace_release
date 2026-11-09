#!/usr/bin/env bash
# check_log_correlation.sh — SecLogTrace Phase 1, checklist item 5
#
# Determines which tracing instrumentation path Train-Ticket uses on this
# deployment. The answer decides whether trace_id-in-logs is a config change
# or a multi-week instrumentation project. Run this before writing any
# correlation code.
#
# Usage: ./check_log_correlation.sh [namespace]

set -uo pipefail
NS="${1:-default}"
echo "Namespace: $NS"
echo "Date: $(date -Iseconds)"
echo

# --- 1. Is an OTel Java agent attached? ------------------------------------
echo "=== 1. OpenTelemetry Java agent ==="
OTEL=$(kubectl get pods -n "$NS" -o json 2>/dev/null \
  | grep -o 'opentelemetry-javaagent[^"]*' | sort -u)
if [ -n "$OTEL" ]; then
  echo "FOUND: $OTEL"
  echo "-> World 1. Low cost. Set the logging pattern and restart."
else
  echo "not found in pod specs"
fi
echo

# --- 2. Jaeger/OpenTracing client env --------------------------------------
echo "=== 2. Jaeger client environment variables ==="
kubectl get pods -n "$NS" -o json 2>/dev/null \
  | grep -oE '"(JAEGER_[A-Z_]+|OTEL_[A-Z_]+)"' | sort -u \
  || echo "none found"
echo

# --- 3. Istio / Envoy sidecar ----------------------------------------------
echo "=== 3. Service mesh sidecars ==="
SIDE=$(kubectl get pods -n "$NS" \
  -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.containers[*].name}{"\n"}{end}' \
  2>/dev/null | grep -c 'istio-proxy' || true)
echo "Pods with istio-proxy: ${SIDE:-0}"
if [ "${SIDE:-0}" -gt 0 ] && [ -z "$OTEL" ]; then
  echo "-> Possible World 3. If tracing comes only from Envoy, application"
  echo "   logs carry NO trace context. Escalate to advisor today."
fi
echo

# --- 4. Do current logs already contain a trace id? ------------------------
echo "=== 4. Trace context already present in logs? ==="
for SVC in ts-travel-service ts-order-service ts-preserve-service; do
  POD=$(kubectl get pods -n "$NS" -o name 2>/dev/null | grep -m1 "$SVC" || true)
  [ -z "$POD" ] && { echo "$SVC: pod not found"; continue; }
  HIT=$(kubectl logs -n "$NS" "$POD" --tail=400 2>/dev/null \
    | grep -icE 'trace[_-]?id|traceId|X-B3-TraceId' || true)
  echo "$SVC: $HIT of last 400 lines mention a trace id"
done
echo

# --- 5. Logging framework in use -------------------------------------------
echo "=== 5. Logging framework ==="
POD=$(kubectl get pods -n "$NS" -o name 2>/dev/null | grep -m1 ts-travel-service || true)
if [ -n "$POD" ]; then
  kubectl exec -n "$NS" "$POD" -- sh -c \
    'ls /app 2>/dev/null | head -20; find / -maxdepth 4 -name "logback*.xml" -o -maxdepth 4 -name "log4j2*.xml" 2>/dev/null | head' \
    2>/dev/null || echo "exec failed (image may lack a shell)"
fi
echo

# --- 6. Chaos tooling (Phase 1 checklist item 1) ---------------------------
echo "=== 6. Chaos-engineering tooling ==="
kubectl get pods -A 2>/dev/null | grep -iE 'chaos|litmus|gremlin' \
  || echo "no chaos pods found by name"
kubectl get crd 2>/dev/null | grep -iE 'chaos|litmus' \
  || echo "no chaos CRDs found"
echo
echo "If anything above is present, determine whether it was active during"
echo "2026-07-28T00:25:58 - 00:30:21 before trusting experiment_001."
echo
echo "=== Record the result in docs/phase_logs/ before proceeding. ==="
