#!/usr/bin/env bash
# Day 3 — Confirm Jaeger access and record known services
#
# Confirmed base path for this deployment: /jaeger/ui
# Confirmed reachable via NodePort at: http://<research-host>:30005/jaeger/ui
#
# Usage: ./check_jaeger_services.sh [base_path] [jaeger_root_url]
#   jaeger_root_url should NOT include /api/services — just the root
#   (e.g. http://<research-host>:30005/jaeger/ui)

set -euo pipefail

BASE="${1:-$HOME/SecLogTrace}"
JAEGER_ROOT="${2:-http://<research-host>:30005/jaeger/ui}"
OUT="$BASE/docs/setup_notes/jaeger_services_$(date +%Y%m%d).json"

URL="${JAEGER_ROOT}/api/services"
echo "Checking Jaeger at: $URL"

if curl -sf "$URL" -o "$OUT"; then
  echo "OK — services saved to: $OUT"
  echo "Services found:"
  python3 -c "import json,sys; d=json.load(open('$OUT')); print('\n'.join(d.get('data', [])))" 2>/dev/null || cat "$OUT"
else
  echo "FAILED to reach Jaeger at $URL"
  echo "Checklist:"
  echo "  1. kubectl get svc jaeger-query   (confirm NodePort, e.g. 16686:30005)"
  echo "  2. Try the root UI in a browser: ${JAEGER_ROOT}"
  echo "  3. Open browser DevTools -> Network tab -> reload -> find the *api/services* request"
  echo "     and copy its exact Request URL; the base path may differ from /jaeger/ui"
  echo "  4. Re-run: ./check_jaeger_services.sh $BASE <root_url_without_/api/services>"
  exit 1
fi
