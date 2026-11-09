#!/usr/bin/env python3
"""
generate_ssrf_traffic.py — SecLogTrace Phase 2
REPO LOCATION: scripts/collection/generate_ssrf_traffic.py

Generates labelled traffic against the injected SSRF sink at
POST /api/v1/avatar (ts-avatar-service, src_url field).

Revised 2026-08-22 after the pilot characterization run, whose traces
confirmed four cleanly distinct signatures at this one endpoint:

  TARGET                              SPANS  SIGNATURE
  ts-order-service:12031/.../order      8    full cross-service + DB chain, 200
  nacos:8848/                           2    outbound child, 404 (reachable/no-route)
  ts-order-service:9999/                2    outbound child, timeout (closed port)
  base64 image (benign)                 1    no outbound span at all, normal

The 8-span order-service chain is the headline SSRF signal: an image service
reaching across the mesh into another service's database. That target is now
first in the attack set.

Two labelled classes:
  normal — base64 image upload (the service's legitimate function). Produces
           a single-span trace with NO outbound request. This IS the clean
           normal class for this endpoint — confirmed by the pilot traces.
  ssrf   — src_url pointed at internal cluster targets. Three targets, in
           decreasing order of signal strength (deep DB reach, internal
           service no-route, closed port).

Because both classes hit the SAME endpoint and differ only in input, this is
a controlled within-endpoint comparison — the confound that invalidated the
earlier 82-vs-46 span finding is structurally absent here.

Usage:
    python3 generate_ssrf_traffic.py --mode normal --count 30 \
        --url http://<research-host>:17001/api/v1/avatar
    python3 generate_ssrf_traffic.py --mode ssrf --count 30 \
        --url http://<research-host>:17001/api/v1/avatar
    python3 generate_ssrf_traffic.py --mode pilot \
        --url http://<research-host>:17001/api/v1/avatar

IMPORTANT: run --mode normal and --mode ssrf as SEPARATE, clearly-windowed
sessions, exported separately (see PHASE_0_CHECKLIST.md item 8 — export-window
overlap caused real label leakage once already). --mode pilot does both with
a 60s gap and is for the first small validation run only.
"""

import argparse
import json
import sys
import time
from datetime import datetime, timezone

import requests

DEFAULT_URL = "http://<research-host>:17001/api/v1/avatar"

# A tiny valid PNG. Decodes cleanly so the base64 path returns a trace with
# the correct SHAPE (single span, no outbound request). dlib may find no face
# in a 1x1 image, but the trace shape is what defines the normal class. For a
# clean 200 on the benign path, pass --normal-image-file with a real face.
BENIGN_PNG_B64 = ("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVR4"
                  "2mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==")

# (target_label, url, weight). Weight controls how many of the attack
# requests go to each target. The db_reach target is the headline SSRF
# signal (8-span cross-service+DB chain, per the pilot), so it is weighted
# highest — a corpus where the strongest signature is only 1/3 of the
# attack class under-represents the class's most detectable form. The other
# two (2-span each: no-route and closed-port timeout) still get meaningful
# representation so the per-sub-type analysis (RQ3) has enough of each.
#
# Weights are relative, not counts — run_ssrf normalizes them against
# --count. Adjust the ratio here, not the total.
SSRF_TARGETS = [
    ("ssrf_db_reach",     "http://ts-order-service:12031/api/v1/orderservice/order", 3),
    ("ssrf_internal_svc", "http://nacos:8848/",                                      2),
    ("ssrf_closed_port",  "http://ts-order-service:9999/",                           1),
    # ("ssrf_k8s_api",    "https://kubernetes.default.svc/api/v1/namespaces",        1),
    #   ^ uncomment only after advisor sign-off (design doc section 4)
]


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def fire(session, url, payload, label, log):
    t0 = time.time()
    entry = {"ts": now_iso(), "class_label": label,
             "target": payload.get("src_url", "base64_upload")}
    try:
        r = session.post(url, json=payload, timeout=20)
        entry["http_status"] = r.status_code
        entry["elapsed_s"] = round(time.time() - t0, 3)
        try:
            body = r.json()
            entry["msg_head"] = str(body.get("msg", body))[:160]
        except Exception:
            entry["body_raw"] = r.text[:160]
    except requests.RequestException as e:
        entry["error"] = str(e)
        entry["elapsed_s"] = round(time.time() - t0, 3)
    log.append(entry)
    return entry


def run_normal(url, count, pace_s, img_b64, log):
    print(f"NORMAL: {count} base64 image uploads -> {url}")
    print("  (legitimate avatar function; single-span traces, no outbound call)")
    session = requests.Session()
    payload = {"img": img_b64}
    for i in range(count):
        e = fire(session, url, payload, "normal", log)
        print(f"  [{i+1:>3}/{count}] status={e.get('http_status','ERR')} "
              f"{e.get('elapsed_s','')}s")
        time.sleep(pace_s)


def _weighted_schedule(count):
    """Build an interleaved request schedule honoring target weights.
    Returns a list of (label, url) of length `count`. Interleaves rather
    than blocking each target together, so the closed-port 10s timeouts are
    spread through the run instead of clustered (keeps trace windows even
    and total wall-clock predictable)."""
    total_w = sum(w for _, _, w in SSRF_TARGETS)
    # target counts proportional to weight, distributing remainder fairly
    quotas = []
    allocated = 0
    for i, (label, url, w) in enumerate(SSRF_TARGETS):
        if i == len(SSRF_TARGETS) - 1:
            n = count - allocated              # last target absorbs remainder
        else:
            n = round(count * w / total_w)
        quotas.append([label, url, n])
        allocated += n
    # interleave by repeatedly taking from whichever target is most "behind"
    schedule = []
    taken = {q[0]: 0 for q in quotas}
    plan = {q[0]: q[2] for q in quotas}
    urlmap = {q[0]: q[1] for q in quotas}
    for _ in range(count):
        # pick the target furthest from its quota (largest remaining fraction)
        cand = max((q for q in quotas if taken[q[0]] < q[2]),
                   key=lambda q: (q[2] - taken[q[0]]) / q[2] if q[2] else 0,
                   default=None)
        if cand is None:
            break
        schedule.append((cand[0], urlmap[cand[0]]))
        taken[cand[0]] += 1
    return schedule, plan


def run_ssrf(url, count, pace_s, log):
    schedule, plan = _weighted_schedule(count)
    print(f"SSRF: {count} requests, weighted across {len(SSRF_TARGETS)} targets -> {url}")
    print("  planned per-target counts: " +
          ", ".join(f"{lab}={n}" for lab, n in plan.items()))
    # rough time estimate: closed-port requests take ~10s each, others ~0.02s
    slow = plan.get("ssrf_closed_port", 0)
    est = (count - slow) * (pace_s + 0.05) + slow * (pace_s + 10.1)
    print(f"  estimated wall-clock: ~{est/60:.1f} min "
          f"({slow} closed-port requests at ~10s each dominate this)")
    session = requests.Session()
    actual = {}
    for i, (label, target_url) in enumerate(schedule):
        e = fire(session, url, {"src_url": target_url}, label, log)
        actual[label] = actual.get(label, 0) + 1
        print(f"  [{i+1:>3}/{count}] {label:<18} status={e.get('http_status','ERR')} "
              f"{e.get('elapsed_s','')}s")
        time.sleep(pace_s)
    print("  actual per-target counts:  " +
          ", ".join(f"{lab}={n}" for lab, n in actual.items()))


def write_log(log, out_path):
    with open(out_path, "w") as fh:
        for e in log:
            fh.write(json.dumps(e) + "\n")
    print(f"\nSession log written: {out_path}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["normal", "ssrf", "pilot"], required=True)
    ap.add_argument("--url", default=DEFAULT_URL,
                    help=f"avatar endpoint (default {DEFAULT_URL})")
    ap.add_argument("--count", type=int, default=30)
    ap.add_argument("--pace", type=float, default=2.0,
                    help="seconds between requests; keep >0 so traces stay separable")
    ap.add_argument("--normal-image-file", default=None,
                    help="path to a real image; base64-encoded and used as the "
                         "normal payload instead of the 1x1 placeholder")
    ap.add_argument("--out", default=None)
    a = ap.parse_args()

    img_b64 = BENIGN_PNG_B64
    using_placeholder = True
    if a.normal_image_file:
        import base64
        with open(a.normal_image_file, "rb") as fh:
            img_b64 = base64.b64encode(fh.read()).decode()
        using_placeholder = False
        print(f"Using {a.normal_image_file} as the normal-class image.")

    # Sanity checks before a potentially long run.
    if a.mode in ("normal", "pilot") and using_placeholder:
        print("WARNING: normal class uses the 1x1 placeholder PNG, which the")
        print("  face detector rejects -> HTTP 500. Fine for the pilot (trace")
        print("  SHAPE is still correct), but for the FULL corpus pass")
        print("  --normal-image-file <real face> so normal returns 200 and")
        print("  status code is a clean discriminator. Continuing in 3s...")
        time.sleep(3)

    if a.mode in ("normal", "ssrf") and a.count < 30:
        print(f"NOTE: --count {a.count} is small for a corpus-scale run. The")
        print("  pilot used 15/class; a detection split needs more. Consider")
        print("  --count 150 or higher per class. (Proceeding as requested.)")

    if a.mode in ("normal", "ssrf") and a.count > 1000:
        print(f"NOTE: --count {a.count} is large; at {a.pace}s pace this is")
        est_min = a.count * (a.pace + 0.05) / 60
        print(f"  ~{est_min:.0f}+ min (more if it includes closed-port targets).")
        print("  Ctrl-C now if that was not intended. Proceeding in 3s...")
        time.sleep(3)

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    print(f"Session start: {now_iso()}")
    print(f"Endpoint: {a.url}\n")

    if a.mode == "pilot":
        nlog, slog = [], []
        print("=== PILOT: 15 normal, 60s gap, 15 ssrf ===\n")
        run_normal(a.url, 15, a.pace, img_b64, nlog)
        npath = a.out or f"data/raw/traffic/ssrf_pilot_normal_{stamp}.jsonl"
        write_log(nlog, npath)
        print("\n--- 60s gap to keep the export windows separable ---")
        gap_end = time.time() + 60
        while time.time() < gap_end:
            time.sleep(5)
        print()
        run_ssrf(a.url, 15, a.pace, slog)
        spath = f"data/raw/traffic/ssrf_pilot_ssrf_{stamp}.jsonl"
        write_log(slog, spath)
        print(f"\nSession end: {now_iso()}")
        print("\nTwo windows logged. Export each separately with explicit")
        print("--start/--end from the timestamps in each .jsonl, then:")
        print("  corpus_audit.py '<both dirs>/*.json' --by-filename-label")
        print("Expect ZERO multi-label traces (the 60s gap guarantees it if")
        print("the export windows respect the logged start/end times).")
        return

    log = []
    if a.mode == "normal":
        run_normal(a.url, a.count, a.pace, img_b64, log)
    else:
        run_ssrf(a.url, a.count, a.pace, log)
    out = a.out or f"data/raw/traffic/ssrf_{a.mode}_{stamp}.jsonl"
    write_log(log, out)
    print(f"Session end: {now_iso()}")
    print("\nNext: export the Jaeger window matching this session, then")
    print("corpus_audit.py to confirm the endpoint appears distinctly.")


if __name__ == "__main__":
    if "-h" not in sys.argv and "--help" not in sys.argv:
        try:
            import requests  # noqa
        except ImportError:
            sys.exit("requests not installed: pip install --user requests")
    main()