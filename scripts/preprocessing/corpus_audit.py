#!/usr/bin/env python3
"""
corpus_audit.py — SecLogTrace
REPO LOCATION: scripts/preprocessing/corpus_audit.py

Answers, from raw Jaeger export JSON, the questions the project documents
currently answer wrongly:

  1. How many DISTINCT traces exist (not the sum of per-service exports)?
  2. How many survive infra-noise filtering?
  3. How many export files does each trace appear in? A trace crossing N
     queried services appears N times. A low fan-out means the corpus is
     mostly single-service traces, which for this deployment means noise.
  4. Do any trace IDs appear under more than one label? That is label
     leakage and it silently invalidates a detection study.
  5. What is the span-count median per label, STRATIFIED by root operation?
     The pooled median compares workload mixes, not attack behaviour.

Usage:
    python3 corpus_audit.py data/raw/jaeger/experiment_001_*.json
    python3 corpus_audit.py data/raw/jaeger/*.json --by-filename-label
"""

import argparse
import glob
import json
import os
import statistics
import sys
from collections import defaultdict, Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from stratification import find_root_span, root_operation_from_spans, best_url_tag  # noqa: E402

# Infra noise: service-discovery polling (NacosWatch) plus the Jaeger query
# API's own operations. jaeger-query traces are created by
# export_jaeger_traces.sh's calls to Jaeger; when a collection script exports
# right after an attack burst they land in the attack window (found
# 2026-09-04). Train-Ticket endpoints are all /api/v1/... so "/api/traces"
# and "/api/services" only ever come from jaeger-query — safe to treat as
# noise. Mirrors the INFRA_SERVICES filter in parse_jaeger_traces.py.
NOISE_OPS = {"NacosWatch$$Lambda$.run", "/api/traces", "/api/services"}

# Infra noise, by URL pattern on SINGLE-SPAN traces. SUT2 (TeaStore)'s
# registry heartbeat/service-discovery polling has no distinct operationName
# the way SUT1's NacosWatch does — the OTel HTTP-client instrumentation just
# names these spans "GET" / "PUT", the same as any real request. Matching on
# operationName alone (as NOISE_OPS does) would misclassify every real
# GET/PUT in the corpus. Match on the request URL instead, and ONLY for
# single-span traces — a multi-span trace that happens to touch the registry
# along the way (e.g. a real request whose service looks itself up) must not
# be discarded.
#
# Verified 2026-09-18 (docs/phase_logs/phase_log_20260918.md): of 20 captured
# traces around a real SSRF/exfiltration test, 19 were single-span
# image<->registry heartbeat calls matching this pattern; the 1 real trace
# was 6 spans and did not match. Confirmed on both `auth` (2026-09-14) and
# `image` (2026-09-18) — the pattern is service-agnostic, not specific to one
# TeaStore component.
NOISE_URL_SUBSTRINGS = (
    "/tools.descartes.teastore.registry/rest/services",
)


def _root_url(spans):
    """Best-effort URL for the (only) span of a single-span trace, using the
    same tag preference as stratification.py."""
    if len(spans) != 1:
        return None
    return best_url_tag(spans[0].get("tags") or [])


def label_from_filename(path):
    base = os.path.basename(path).lower()
    for lab in ("attack", "normal", "devdata"):
        if lab in base:
            return lab
    return "unknown"


def root_span(spans):
    return find_root_span(spans)


def root_operation(spans):
    """Entry point of the trace. See stratification.py — extracted
    2026-08-20, this used to be a standalone copy of the same logic now
    also used by build_feature_table.py and parse_jaeger_traces.py."""
    return root_operation_from_spans(spans)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--by-filename-label", action="store_true",
                    help="derive label from filename (attack/normal/devdata)")
    ap.add_argument("--dump-root-tags", action="store_true",
                    help="print the tag keys present on root spans and exit; "
                         "use this when root_operation looks like a wildcard")
    a = ap.parse_args()

    paths = []
    for pat in a.files:
        paths.extend(glob.glob(pat) if any(c in pat for c in "*?[") else [pat])
    paths = [p for p in sorted(set(paths)) if os.path.basename(p) != "manifest.json"]
    if not paths:
        sys.exit("No input files matched.")

    traces = {}                       # traceID -> spans (first copy wins)
    appears_in = defaultdict(set)     # traceID -> {filename}
    labels_of = defaultdict(set)      # traceID -> {label}
    rows = 0

    for p in paths:
        lab = label_from_filename(p) if a.by_filename_label else "all"
        try:
            with open(p) as fh:
                doc = json.load(fh)
        except Exception as e:
            print(f"  SKIP {os.path.basename(p)}: {e}", file=sys.stderr)
            continue
        for t in doc.get("data") or []:
            tid = t.get("traceID")
            if not tid:
                continue
            rows += 1
            appears_in[tid].add(os.path.basename(p))
            labels_of[tid].add(lab)
            if tid not in traces:
                traces[tid] = t.get("spans") or []

    if a.dump_root_tags:
        keys = Counter()
        samples = {}
        for tid, spans in list(traces.items())[:4000]:
            rs = root_span(spans)
            if rs is None:
                continue
            for t in rs.get("tags") or []:
                k = t.get("key")
                keys[k] += 1
                samples.setdefault(k, str(t.get("value"))[:70])
        print("Tag keys on root spans (count, example value):")
        for k, c in keys.most_common(40):
            print(f"  {c:>6}  {k:<32} {samples.get(k,'')}")
        print()
        print("Pick the key holding the real request path and put it first")
        print("in URL_TAGS in stratification.py (shared by corpus_audit.py,")
        print("build_feature_table.py, and parse_jaeger_traces.py).")
        return

    def is_noise(spans):
        ops = {s.get("operationName") for s in spans}
        if ops and ops <= NOISE_OPS:
            return True
        # SUT2 (TeaStore) registry-heartbeat noise. These spans carry NO
        # http.url tag AT ALL (verified 2026-09-17 against real captured data:
        # 260/260 single-span noise traces had no url), so the
        # NOISE_URL_SUBSTRINGS check below can NEVER fire on real SUT2 data —
        # it was a silent no-op producing 0% noise. The reliable signature is
        # a single-span trace whose operationName is a bare HTTP verb
        # ("GET"/"PUT") — every real request span's operationName carries its
        # path, so this cannot hit a real request. Mirrors the identical fix
        # in parse_jaeger_traces.py's classify_span().
        if len(spans) == 1 and spans[0].get("operationName") in ("GET", "PUT") \
                and not _root_url(spans):
            return True
        # Retained for a future SUT whose infra noise DOES carry a url tag.
        url = _root_url(spans)
        if url and any(sub in url for sub in NOISE_URL_SUBSTRINGS):
            return True
        return False

    noise = {t for t, s in traces.items() if is_noise(s)}
    real = [t for t in traces if t not in noise]

    print("=" * 66)
    print("  CORPUS AUDIT")
    print("=" * 66)
    print(f"  Files read                  : {len(paths)}")
    print(f"  Trace entries (sum)         : {rows}    <-- never cite this")
    print(f"  DISTINCT traces             : {len(traces)}    <-- cite this")
    print(f"  Duplicate entries           : {rows - len(traces)}")
    print(f"  Infra-noise-only traces     : {len(noise)}  "
          f"({100*len(noise)/max(len(traces),1):.1f}%)")
    print(f"  REAL traces (noise removed) : {len(real)}    <-- the usable N")
    print()

    # --- fan-out --------------------------------------------------------
    print("  Export files each trace appears in")
    print("  (a trace crossing N of the queried services appears N times)")
    fan = Counter(len(v) for v in appears_in.values())
    for k in sorted(fan):
        share = 100 * fan[k] / max(len(traces), 1)
        print(f"    in {k} file(s): {fan[k]:>6}  ({share:5.1f}%)")
    fan_real = Counter(len(appears_in[t]) for t in real)
    print("  Same, for REAL traces only:")
    for k in sorted(fan_real):
        share = 100 * fan_real[k] / max(len(real), 1)
        print(f"    in {k} file(s): {fan_real[k]:>6}  ({share:5.1f}%)")
    print()

    # --- label leakage --------------------------------------------------
    if a.by_filename_label:
        leaked = {t: labels_of[t] for t in labels_of if len(labels_of[t]) > 1}
        print(f"  Traces carrying MORE THAN ONE label : {len(leaked)}")
        if leaked:
            print("  *** LABEL LEAKAGE. The same trace is in both classes. ***")
            print("  *** Any detection metric computed on this is invalid. ***")
            per_lab = Counter()
            for t in leaked:
                for l in labels_of[t]:
                    per_lab[l] += 1
            for l in sorted(per_lab):
                tot = sum(1 for t in traces if l in labels_of[t])
                print(f"      {l}: {per_lab[l]} of {tot} traces "
                      f"({100*per_lab[l]/max(tot,1):.0f}%) also carry another label")
            src = Counter()
            for t in leaked:
                src[tuple(sorted(appears_in[t]))] += 1
            print("      file combinations responsible:")
            for combo, c in src.most_common(4):
                print(f"        {c:>5}x  {' + '.join(combo)}")
        print()

    # --- span counts, pooled and stratified ------------------------------
    def med(xs):
        return statistics.median(xs) if xs else float("nan")

    by_label = defaultdict(list)
    by_label_op = defaultdict(list)
    clean = [t for t in real if len(labels_of[t]) == 1]
    if a.by_filename_label and len(clean) < len(real):
        print(f"  Excluding {len(real)-len(clean)} multi-label traces from the")
        print(f"  comparison below. Comparing {len(clean)} cleanly-labelled traces.")
        print()
    for t in (clean if a.by_filename_label else real):
        lab = sorted(labels_of[t])[0] if a.by_filename_label else "all"
        n = len(traces[t])
        by_label[lab].append(n)
        by_label_op[(lab, root_operation(traces[t]))].append(n)

    print("  Span count per REAL trace, pooled by label")
    for lab in sorted(by_label):
        v = sorted(by_label[lab])
        print(f"    {lab:<10} n={len(v):<6} median={med(v):<7.1f} "
              f"p25={v[len(v)//4]:<6} p75={v[3*len(v)//4]:<6} max={v[-1]}")
    print("    NOTE: pooled medians compare workload mixes. Read the table")
    print("          below before drawing any conclusion from them.")
    print()

    print("  Span count by root operation (top 15 by trace count)")
    top = sorted(by_label_op.items(), key=lambda kv: -len(kv[1]))[:15]
    print(f"    {'label':<9} {'n':>5}  {'median':>7}  root_operation")
    for (lab, op), v in top:
        print(f"    {lab:<9} {len(v):>5}  {med(v):>7.1f}  {op[:52]}")
    print()

    # --- shared entry points --------------------------------------------
    if a.by_filename_label and len(by_label) > 1:
        ops = defaultdict(set)
        for (lab, op) in by_label_op:
            ops[lab].add(op)
        labs = sorted(ops)
        shared = set.intersection(*(ops[l] for l in labs))
        print(f"  Root operations per label: " +
              ", ".join(f"{l}={len(ops[l])}" for l in labs))
        print(f"  Shared root operations   : {len(shared)}")
        if not shared:
            print()
            print("  *** NO SHARED ENTRY POINTS between the labels. ***")
            print("  The two classes exercise entirely different endpoints, so")
            print("  any span-count difference measures WHICH ENDPOINT was")
            print("  called, not whether an attack occurred. The comparison is")
            print("  not valid as collected.")
        else:
            print()
            print("  Within-entry-point comparison (the only valid one):")
            for op in sorted(shared):
                cells = []
                for l in labs:
                    v = by_label_op.get((l, op), [])
                    if len(v) >= 5:
                        cells.append(f"{l} n={len(v)} med={med(v):.0f}")
                if len(cells) > 1:
                    print(f"    {op[:44]:<44} " + " | ".join(cells))
    print("=" * 66)


if __name__ == "__main__":
    main()
