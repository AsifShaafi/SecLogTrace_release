#!/usr/bin/env python3
"""
verify_otel_manifest.py — SecLogTrace
REPO LOCATION: scripts/infra/verify_otel_manifest.py

Checks that the committed Jaeger manifest would produce a WORKING Badger
deployment on a fresh cluster.

WHY THIS EXISTS, AND WHY `kubectl diff` IS NOT ENOUGH

The live Jaeger Deployment was fixed imperatively with `kubectl patch` and
`kubectl set env`. Those changes never entered
`kubectl.kubernetes.io/last-applied-configuration`. `kubectl diff` computes
a three-way merge from (last-applied, file, live), so a field that is null
in the file AND absent from last-applied generates no directive and shows
no diff — even though live has the field and the file does not.

Concretely: a manifest containing

    volumeMounts:
    volumes:

parses those as null. `kubectl diff` reports nothing. `kubectl apply` on the
current cluster changes nothing. But `kubectl apply` on a FRESH namespace
produces a Jaeger pod with Badger configured and no volume attached. It
writes to the container's ephemeral filesystem and loses everything on
restart, silently, with correct-looking environment variables.

This script reads the file as data and asserts the properties that matter,
independent of any live cluster.

Usage:
    python3 verify_otel_manifest.py deployment/kubernetes-manifests/otel/otel.yml
    python3 verify_otel_manifest.py <otel.yml> --storage-dir deployment/kubernetes-manifests/storage
"""

import argparse
import glob
import os
import sys

try:
    import yaml
except ImportError:
    sys.exit("PyYAML required:  pip install pyyaml --user")

PASS, FAIL, WARN = [], [], []


def ok(m):
    PASS.append(m)


def bad(m, fix=""):
    FAIL.append((m, fix))


def warn(m):
    WARN.append(m)


def load(path):
    with open(path) as fh:
        return [d for d in yaml.safe_load_all(fh) if d]


def find_jaeger(docs):
    for d in docs:
        if d.get("kind") == "Deployment" and d.get("metadata", {}).get("name") == "jaeger":
            return d
    return None


def check_deployment(dep):
    pod = dep["spec"]["template"]["spec"]
    containers = pod.get("containers") or []
    jc = next((c for c in containers if c.get("name") == "jaeger"), None)
    if jc is None:
        bad("no container named 'jaeger' in the Deployment",
            "the strategic-merge patch keys on container name; it must be 'jaeger'")
        return
    ok("container 'jaeger' present")

    env = {e["name"]: e.get("value") for e in (jc.get("env") or [])}

    # --- storage backend ---
    if env.get("SPAN_STORAGE_TYPE") == "badger":
        ok("SPAN_STORAGE_TYPE=badger")
    else:
        bad(f"SPAN_STORAGE_TYPE is {env.get('SPAN_STORAGE_TYPE')!r}, expected 'badger'")

    if env.get("BADGER_EPHEMERAL") == "false":
        ok("BADGER_EPHEMERAL=false (persistence actually enabled)")
    else:
        bad(f"BADGER_EPHEMERAL is {env.get('BADGER_EPHEMERAL')!r}, expected the string 'false'",
            "badger defaults to ephemeral; without this it writes to a temp dir")

    ttl = env.get("BADGER_SPAN_STORE_TTL")
    if ttl == "720h":
        ok("BADGER_SPAN_STORE_TTL=720h")
    elif ttl is None:
        bad("BADGER_SPAN_STORE_TTL unset — Jaeger defaults to 72h",
            "spans older than three days get deleted mid-study")
    else:
        warn(f"BADGER_SPAN_STORE_TTL={ttl} (not the 720h agreed for this project)")

    for k, want in (("BADGER_DIRECTORY_VALUE", "/badger/data"),
                    ("BADGER_DIRECTORY_KEY", "/badger/key")):
        if env.get(k) == want:
            ok(f"{k}={want}")
        else:
            bad(f"{k} is {env.get(k)!r}, expected {want!r}")

    # --- things that must be preserved ---
    if env.get("COLLECTOR_OTLP_ENABLED") == "true":
        ok("COLLECTOR_OTLP_ENABLED=true (services reach Jaeger over OTLP)")
    else:
        bad("COLLECTOR_OTLP_ENABLED is not 'true' — trace ingestion will break")

    # --- args ---
    args = jc.get("args") or []
    if any("memory.max-traces" in str(a) for a in args):
        bad("--memory.max-traces is present in args",
            "that flag exists only under SPAN_STORAGE_TYPE=memory; "
            "under badger the binary exits with 'unknown flag' and crash-loops")
    else:
        ok("--memory.max-traces absent from args")

    if any("--query.base-path" in str(a) for a in args):
        ok("--query.base-path preserved (the /jaeger/ui path depends on it)")
    else:
        bad("--query.base-path missing — the Jaeger UI and API move to /")

    # --- THE CHECK kubectl diff CANNOT MAKE ---
    vm = jc.get("volumeMounts")
    vols = pod.get("volumes")

    if vm is None:
        bad("container volumeMounts is null or missing",
            "a bare 'volumeMounts:' line parses as null. On a fresh deploy "
            "badger writes to the container filesystem and loses all data "
            "on restart. kubectl diff will NOT catch this.")
    elif not any(m.get("mountPath") == "/badger" for m in vm):
        bad("no volumeMount at /badger",
            "BADGER_DIRECTORY_* point at /badger; nothing is mounted there")
    else:
        ok("volumeMount at /badger present")

    if vols is None:
        bad("pod volumes is null or missing",
            "a bare 'volumes:' line parses as null")
    else:
        claim = None
        for v in vols:
            pvc = v.get("persistentVolumeClaim")
            if pvc:
                claim = pvc.get("claimName")
        if claim:
            ok(f"volume backed by PVC '{claim}'")
        else:
            bad("no persistentVolumeClaim among the pod volumes",
                "an emptyDir survives container restarts but not pod "
                "rescheduling — not durable enough for a research corpus")

    # cross-check mount name against volume name
    if vm and vols:
        names = {v.get("name") for v in vols}
        for m in vm:
            if m.get("mountPath") == "/badger" and m.get("name") not in names:
                bad(f"volumeMount references volume {m.get('name')!r}, which is not defined",
                    "the pod will fail to schedule")

    # --- permissions (belt and braces on this deployment) ---
    if (pod.get("securityContext") or {}).get("fsGroup"):
        ok("pod securityContext.fsGroup set")
    else:
        warn("no fsGroup set — fine while the image runs as root (it does "
             "here, verified 2026-08-05), but breaks if that changes upstream")

    if pod.get("initContainers"):
        ok("init container present to create and chown /badger")
    else:
        warn("no init container preparing /badger")

    return jc.get("env") or []


def check_pvc(otel_docs, storage_dir):
    in_otel = [d for d in otel_docs if d.get("kind") == "PersistentVolumeClaim"]
    if in_otel:
        bad("a PersistentVolumeClaim is defined inside otel.yml",
            "reset.sh runs `kubectl delete -f .../otel`, which deletes every "
            "manifest in that directory. The reclaim policy is Delete, so a "
            "routine reset would destroy the whole trace corpus. Move it to "
            "deployment/kubernetes-manifests/storage/")
    else:
        ok("no PVC inside otel.yml (a reset cannot delete trace data)")

    if not storage_dir or not os.path.isdir(storage_dir):
        warn(f"storage dir not found ({storage_dir}) — cannot confirm the PVC "
             f"is defined anywhere; a fresh deploy would leave Jaeger Pending")
        return
    found = []
    for f in sorted(glob.glob(os.path.join(storage_dir, "*.y*ml"))):
        for d in load(f):
            if d.get("kind") == "PersistentVolumeClaim":
                found.append((d["metadata"]["name"], f))
    if found:
        for name, f in found:
            ok(f"PVC '{name}' defined in {os.path.basename(f)}")
    else:
        bad(f"no PVC found in {storage_dir}",
            "Jaeger mounts a claim that nothing creates; the pod stays Pending")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("otel_yaml")
    ap.add_argument("--storage-dir",
                    default="deployment/kubernetes-manifests/storage")
    a = ap.parse_args()

    docs = load(a.otel_yaml)
    dep = find_jaeger(docs)
    if dep is None:
        sys.exit("No Deployment named 'jaeger' found in that file.")

    print("=" * 68)
    print("  JAEGER MANIFEST VERIFICATION")
    print(f"  {a.otel_yaml}")
    print("=" * 68)
    print()

    check_deployment(dep)
    check_pvc(docs, a.storage_dir)

    for m in PASS:
        print(f"  PASS  {m}")
    print()
    for m in WARN:
        print(f"  WARN  {m}")
    if WARN:
        print()
    for m, fix in FAIL:
        print(f"  FAIL  {m}")
        if fix:
            for line in fix.split("\n"):
                print(f"        -> {line}")
    print()
    print("=" * 68)
    print(f"  {len(PASS)} passed, {len(WARN)} warnings, {len(FAIL)} failed")
    if FAIL:
        print()
        print("  This manifest would NOT produce a working persistent Jaeger")
        print("  on a fresh cluster, regardless of what `kubectl diff` says")
        print("  against the currently-patched live deployment.")
    else:
        print()
        print("  Manifest is fresh-deploy correct. Confirm with a scratch")
        print("  namespace before trusting it:")
        print("    kubectl create ns tsverify")
        print("    kubectl apply -f <storage-dir> -n tsverify")
        print("    kubectl apply -f <otel.yml> -n tsverify")
        print("    kubectl get pod -n tsverify -l app.kubernetes.io/name=jaeger")
        print("    kubectl delete ns tsverify")
    print("=" * 68)
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
