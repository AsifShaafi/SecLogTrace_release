#!/usr/bin/env bash
# switch_jaeger_to_badger.sh — SecLogTrace
# REPO LOCATION: scripts/infra/switch_jaeger_to_badger.sh
#
# Moves Jaeger all-in-one from in-memory to Badger persistent storage.
#
# WHY: in-memory storage loses every trace when the pod restarts, and evicts
# oldest-first once --memory.max-traces is reached. Neither failure produces
# an error. Before a two-hour coverage sweep, both are unacceptable.
#
# SCOPE: touches the Jaeger Deployment only. The ~41 ts-* services are not
# restarted and need no changes — they keep sending OTLP to the same Service
# name and port. Ingestion and query APIs are unchanged.
#
# READ THIS FIRST: this script patches the LIVE Deployment. Train-Ticket is
# Helm-managed, so the next `helm upgrade`, `deploy.sh`, or `reset.sh` will
# revert everything here. Use this to get running today, then commit the
# equivalent change to the chart in your fork. See PART 2 at the bottom.
#
# Usage:
#   ./switch_jaeger_to_badger.sh inspect     # read-only, run this first
#   ./switch_jaeger_to_badger.sh apply
#   ./switch_jaeger_to_badger.sh verify
#   ./switch_jaeger_to_badger.sh rollback

set -euo pipefail

NS="${NS:-default}"
PVC_NAME="${PVC_NAME:-jaeger-badger-pvc}"
PVC_SIZE="${PVC_SIZE:-20Gi}"
STORAGE_CLASS="${STORAGE_CLASS:-standard}"

# 720h = 30 days. The Jaeger default is 72h — three days — after which spans
# are deleted. For a research corpus collected over weeks that default is a
# silent data-loss bug. Raise it deliberately.
TTL="${TTL:-720h}"

BACKUP="docs/setup_notes/jaeger_deploy_backup_$(date +%Y%m%d_%H%M%S).yaml"

find_deploy() {
  kubectl get deploy -n "$NS" -o name 2>/dev/null | grep -i jaeger | head -1
}

case "${1:-}" in

inspect)
  D=$(find_deploy)
  [[ -z "$D" ]] && { echo "No Jaeger deployment found in namespace $NS"; exit 1; }
  echo "Deployment      : $D"
  echo "Image           : $(kubectl get "$D" -n "$NS" -o jsonpath='{.spec.template.spec.containers[0].image}')"
  echo "Helm release    : $(kubectl get "$D" -n "$NS" -o jsonpath='{.metadata.annotations.meta\.helm\.sh/release-name}' 2>/dev/null || echo '(not Helm-annotated)')"
  echo
  echo "Current storage env:"
  kubectl get "$D" -n "$NS" -o jsonpath='{range .spec.template.spec.containers[0].env[*]}  {.name}={.value}{"\n"}{end}' \
    | grep -iE 'STORAGE|BADGER|MEMORY|OTLP' || echo "  (none set — defaults to in-memory)"
  echo
  echo "Runs as UID     : $(kubectl get "$D" -n "$NS" -o jsonpath='{.spec.template.spec.containers[0].securityContext.runAsUser}' 2>/dev/null || echo 'unset (image default)')"
  echo
  echo "Storage classes available:"
  kubectl get storageclass 2>/dev/null | sed 's/^/  /' || echo "  none"
  echo
  echo "Traces currently held (these will be LOST on restart):"
  curl -s --max-time 10 "http://<research-host>:30005/jaeger/ui/api/services" \
    | head -c 300 || echo "  (query failed)"
  echo
  echo
  echo "If the storage class above is not 'standard', re-run apply with"
  echo "STORAGE_CLASS=<name> ./switch_jaeger_to_badger.sh apply"
  ;;

apply)
  D=$(find_deploy)
  [[ -z "$D" ]] && { echo "No Jaeger deployment found in namespace $NS"; exit 1; }
  NAME=$(basename "$D")

  mkdir -p "$(dirname "$BACKUP")"
  kubectl get "$D" -n "$NS" -o yaml > "$BACKUP"
  echo "Backup written: $BACKUP"
  echo

  echo "Creating PVC $PVC_NAME (${PVC_SIZE}, class ${STORAGE_CLASS})..."
  cat <<EOF | kubectl apply -n "$NS" -f -
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: ${PVC_NAME}
spec:
  accessModes: [ReadWriteOnce]
  resources:
    requests:
      storage: ${PVC_SIZE}
  storageClassName: ${STORAGE_CLASS}
EOF
  echo

  echo "Setting storage environment variables..."
  # set env only adds/replaces the named variables. Existing OTLP and
  # sampling settings are left alone.
  kubectl set env -n "$NS" "$D" \
    SPAN_STORAGE_TYPE=badger \
    BADGER_EPHEMERAL=false \
    BADGER_DIRECTORY_VALUE=/badger/data \
    BADGER_DIRECTORY_KEY=/badger/key \
    BADGER_SPAN_STORE_TTL="$TTL"
  echo

  echo "Attaching the volume and fixing directory ownership..."
  # all-in-one runs as a non-root user. A freshly provisioned volume is
  # root-owned, and Jaeger will crash-loop with "permission denied". fsGroup
  # handles this on most provisioners; the initContainer is the belt-and-
  # braces fix for hostPath provisioners that ignore fsGroup.
  kubectl patch -n "$NS" "$D" --type=strategic -p "$(cat <<EOF
{
  "spec": {
    "template": {
      "spec": {
        "securityContext": {"fsGroup": 10001},
        "initContainers": [{
          "name": "badger-dir-permissions",
          "image": "busybox:1.36",
          "command": ["sh","-c","mkdir -p /badger/data /badger/key && chown -R 10001:10001 /badger"],
          "securityContext": {"runAsUser": 0},
          "volumeMounts": [{"name": "badger-storage", "mountPath": "/badger"}]
        }],
        "containers": [{
          "name": "${NAME}",
          "volumeMounts": [{"name": "badger-storage", "mountPath": "/badger"}]
        }],
        "volumes": [{
          "name": "badger-storage",
          "persistentVolumeClaim": {"claimName": "${PVC_NAME}"}
        }]
      }
    }
  }
}
EOF
)"
  echo
  echo "Rewriting container args..."
  # --memory.max-traces is registered ONLY when SPAN_STORAGE_TYPE=memory.
  # Once storage is badger the flag does not exist and the binary exits with
  # "unknown flag: --memory.max-traces" before it ever starts. Any other args
  # (query base path, prometheus URL) must be preserved.
  CUR_ARGS=$(kubectl get "$D" -n "$NS" -o json \
    | python3 -c '
import json,sys
d=json.load(sys.stdin)
a=d["spec"]["template"]["spec"]["containers"][0].get("args",[])
out=[];i=0
while i<len(a):
    if a[i]=="--memory.max-traces":
        i+=2; continue          # drop the flag and its value
    if a[i].startswith("--memory.max-traces="):
        i+=1; continue
    out.append(a[i]); i+=1
print(json.dumps(out))')
  echo "  new args: $CUR_ARGS"
  kubectl patch -n "$NS" "$D" --type=strategic -p \
    "{\"spec\":{\"template\":{\"spec\":{\"containers\":[{\"name\":\"${NAME}\",\"args\":${CUR_ARGS}}]}}}}"
  echo

  echo "Waiting for rollout..."
  kubectl rollout status -n "$NS" "$D" --timeout=300s || {
    echo
    echo "ROLLOUT FAILED. Check logs:"
    echo "  kubectl logs -n $NS $D --tail=50"
    echo "Most likely cause: the container name in the patch did not match."
    echo "Actual container names:"
    kubectl get "$D" -n "$NS" -o jsonpath='{.spec.template.spec.containers[*].name}'
    echo
    echo "Roll back with: $0 rollback"
    exit 1
  }
  echo
  echo "Applied. Run: $0 verify"
  ;;

verify)
  D=$(find_deploy)
  echo "=== Storage configuration ==="
  kubectl get "$D" -n "$NS" -o jsonpath='{range .spec.template.spec.containers[0].env[*]}  {.name}={.value}{"\n"}{end}' \
    | grep -iE 'STORAGE|BADGER' || echo "  NOT SET"
  echo
  echo "=== Pod status ==="
  kubectl get pods -n "$NS" -l app=jaeger -o wide 2>/dev/null \
    || kubectl get pods -n "$NS" | grep -i jaeger
  echo
  echo "=== Startup log (look for 'badger', not 'memory') ==="
  POD=$(kubectl get pods -n "$NS" -o name | grep -i jaeger | head -1)
  kubectl logs -n "$NS" "$POD" --tail=40 2>/dev/null \
    | grep -iE 'badger|storage|memory|permission|error' | sed 's/^/  /' || true
  echo
  echo "=== Data on disk ==="
  kubectl exec -n "$NS" "$POD" -- ls -la /badger /badger/data /badger/key 2>/dev/null \
    | sed 's/^/  /' || echo "  (exec failed — image may lack a shell)"
  echo
  echo "=== THE ACTUAL TEST ==="
  echo "Config alone proves nothing. Do this:"
  echo "  1. Drive one booking through the UI"
  echo "  2. Confirm the trace appears at http://<research-host>:30005/jaeger/ui/"
  echo "  3. kubectl rollout restart -n $NS $D"
  echo "  4. Wait for Ready, then look for the SAME trace again"
  echo "If it survives step 4, persistence works. If not, it does not,"
  echo "whatever the environment variables say."
  ;;

rollback)
  # `kubectl apply` on a dump of live state fails with a resourceVersion
  # conflict, because the dump carries metadata that cannot be re-applied.
  # rollout undo uses the revision history instead and does not have this
  # problem.
  D=$(find_deploy)
  echo "Rolling back via revision history:"
  kubectl rollout history -n "$NS" "$D"
  kubectl rollout undo -n "$NS" "$D"
  kubectl rollout status -n "$NS" "$D" --timeout=300s
  echo
  echo "If that failed, restore from the backup with the immutable fields"
  echo "stripped:"
  LATEST=$(ls -1t docs/setup_notes/jaeger_deploy_backup_*.yaml 2>/dev/null | head -1)
  echo "  python3 -c \"import yaml,sys; d=yaml.safe_load(open('$LATEST'));"
  echo "    d.pop('status',None); m=d['metadata'];"
  echo "    [m.pop(k,None) for k in ('resourceVersion','uid','generation',"
  echo "      'creationTimestamp','managedFields','annotations')];"
  echo "    yaml.safe_dump(d,sys.stdout)\" > /tmp/jaeger_clean.yaml"
  echo "  kubectl replace -n $NS -f /tmp/jaeger_clean.yaml"
  echo
  echo "The PVC $PVC_NAME still exists; delete it manually if unwanted."
  ;;

*)
  echo "Usage: $0 {inspect|apply|verify|rollback}"
  echo
  echo "Order: inspect -> apply -> verify -> restart test"
  echo
  echo "Overridable: NS, PVC_NAME, PVC_SIZE, STORAGE_CLASS, TTL"
  exit 2
  ;;
esac

# ---------------------------------------------------------------------------
# PART 2 — MAKING IT SURVIVE A REDEPLOY
#
# Everything above is a live patch. Helm does not know about it. The next
# `helm upgrade`, `deploy.sh`, or `reset.sh` reverts Jaeger to in-memory and
# nothing warns you — the same silent-failure pattern already documented for
# the tsdb release.
#
# Commit the equivalent change to the chart in AsifShaafi/train-ticket-injection:
#
#   1. Find the Jaeger template in the chart, likely under
#      charts/*/templates/ with "jaeger" in the filename.
#   2. Add the five env vars, the volume, the volumeMount, fsGroup, and the
#      init container to that template.
#   3. Add the PVC as its own template file.
#   4. Commit with a message explaining WHY, so the next person does not
#      revert it as clutter.
#
# Until that commit exists, treat every redeploy as destroying trace
# persistence, and re-run `apply` after each one.
# ---------------------------------------------------------------------------
