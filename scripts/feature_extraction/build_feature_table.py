#!/usr/bin/env python3
"""
build_feature_table.py — SecLogTrace Phase 1

Builds a trace-level feature table from the CSVs emitted by
parse_jaeger_traces.py. One row per trace. Features are grouped into named
families so Paper B can run trace-only / log-only / combined ablations by
selecting column groups rather than rewriting extraction.

Design decisions worth knowing before you run it:

1. Column names are resolved through an alias map, because this script was
   written without sight of parse_jaeger_traces.py's exact output schema.
   Run with --inspect first. Fix ALIASES below if anything is unresolved.

2. Every trace carries `root_operation`. Attack-vs-normal comparisons must
   be stratified on it. Pooled comparisons confound the attack signal with
   the workload mix, which is the flaw in the current 82-vs-46 span-count
   finding.

3. `path_signature` is a hash of the sorted set of caller->callee service
   edges. It supports rarity scoring in Phase 3 without leaking raw IDs.

4. Infra-noise traces are dropped by default (--keep-noise to retain).

5. --spans takes MULTIPLE files. Jaeger exports per service, so a trace
   crossing four services lands in four export files. The script
   deduplicates on (trace_id, span_id) and reports the distinct trace
   count. Summing per-service trace counts overstates corpus size.

Usage:
    python3 build_feature_table.py --inspect --spans <spans.csv>
    python3 build_feature_table.py \
        --spans data/processed/traces/experiment_001_*_spans.csv \
        --traces data/processed/traces/experiment_001_traces.csv \
        --out data/processed/combined/experiment_001_features.csv
"""

import argparse
import hashlib
import os
import sys
from collections import defaultdict

import pandas as pd
import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                 "..", "preprocessing"))
from stratification import root_operation_from_parts  # noqa: E402

# --------------------------------------------------------------------------
# Column alias map. Left = canonical name used in this script.
# Right = candidate names, checked in order, case-insensitive.
# --------------------------------------------------------------------------
ALIASES = {
    "trace_id":       ["trace_id", "traceID", "traceId"],
    "span_id":        ["span_id", "spanID", "spanId"],
    "parent_span_id": ["parent_span_id", "parentSpanID", "parent_id", "references"],
    "service":        ["service", "service_name", "serviceName", "process"],
    "operation":      ["operation", "operation_name", "operationName"],
    "start_time":     ["start_time", "startTime", "start_time_us", "timestamp"],
    "duration_us":    ["duration_us", "duration", "duration_micros"],
    "is_error":       ["is_error", "error", "error_flag", "has_error"],
    "http_method":    ["http_method", "http.method"],
    "http_url":       ["http_url", "http.url", "http_target", "http.target"],
    "http_status":    ["http_status_code", "http.status_code", "status_code"],
    "db_statement":   ["db_statement", "db.statement"],
    "label":          ["label", "class"],
    "experiment_id":  ["experiment_id", "experiment"],
    "infra_noise":    ["is_infra_noise_only", "infra_noise", "is_noise"],
}

FEATURE_FAMILIES = {
    "structural": [
        "span_count", "service_count", "operation_count",
        "max_depth", "max_fanout", "edge_count", "unique_edge_count",
    ],
    "timing": [
        "trace_duration_us", "span_dur_mean", "span_dur_median",
        "span_dur_p95", "span_dur_max", "span_dur_std",
    ],
    "error": [
        "error_span_count", "error_span_rate",
        "http_4xx_count", "http_5xx_count",
    ],
    "interaction": [
        "db_span_count", "http_span_count",
        "distinct_http_targets", "distinct_db_statements",
        "distinct_http_methods",
    ],
    "identity": [
        "trace_id", "root_service", "root_operation", "path_signature",
        "label", "experiment_id",
    ],
}


def resolve(df, canonical):
    """Return the actual column name in df for a canonical field, or None."""
    lower = {c.lower(): c for c in df.columns}
    for cand in ALIASES.get(canonical, [canonical]):
        if cand.lower() in lower:
            return lower[cand.lower()]
    return None


def inspect(path):
    df = pd.read_csv(path, nrows=200)
    print(f"\nFile: {path}")
    print(f"Columns ({len(df.columns)}): {list(df.columns)}\n")
    print("Alias resolution:")
    unresolved = []
    for canon in ALIASES:
        got = resolve(df, canon)
        mark = "OK " if got else "-- "
        print(f"  {mark} {canon:<16} -> {got}")
        if not got:
            unresolved.append(canon)
    print(f"\nUnresolved: {unresolved or 'none'}")
    print("Edit ALIASES at the top of this script for anything you need.\n")


def _norm_root_op(op_name, url):
    """Entry-point label for stratification — see stratification.py.
    Extracted 2026-08-20; this used to be a standalone copy that had
    already diverged once from corpus_audit.py's version (fixed there
    first, not ported here until 2026-08-18 — see
    docs/phase_logs/phase_log_20260818.md)."""
    url = None if (url is None or (isinstance(url, float) and pd.isna(url))) else str(url)
    return root_operation_from_parts(op_name, url)


def compute_depth(parents):
    """Depth per span_id from a {span_id: parent_span_id} map. Cycle-safe."""
    depth = {}

    def walk(sid, seen):
        if sid in depth:
            return depth[sid]
        p = parents.get(sid)
        if not p or p not in parents or p in seen:
            depth[sid] = 0
            return 0
        seen.add(sid)
        d = walk(p, seen) + 1
        depth[sid] = d
        return d

    for sid in parents:
        walk(sid, set())
    return depth


def build(spans_paths, traces_path, out_path, keep_noise=False):
    # Accept multiple spans files. The Jaeger export is per-service, so a
    # trace crossing N services appears in N export files. Concatenating and
    # deduplicating on (trace_id, span_id) is REQUIRED, not optional. Without
    # it, corpus size is overstated and the same trace can land in both the
    # train and test split.
    frames = [pd.read_csv(p) for p in spans_paths]
    spans = pd.concat(frames, ignore_index=True)
    cols = {c: resolve(spans, c) for c in ALIASES}

    if cols["trace_id"] and cols["span_id"]:
        before_rows = len(spans)
        before_traces = spans[cols["trace_id"]].nunique()
        spans = spans.drop_duplicates(subset=[cols["trace_id"], cols["span_id"]])
        print(f"Input files:      {len(spans_paths)}")
        print(f"Span rows:        {before_rows} -> {len(spans)} "
              f"({before_rows - len(spans)} duplicate spans removed)")
        print(f"Distinct traces:  {before_traces}")
        if before_rows != len(spans):
            print("NOTE: duplicates found. Any trace count taken by summing "
                  "per-service exports is inflated. Use the distinct count.")
        print()

    required = ["trace_id", "span_id", "service", "operation", "duration_us"]
    missing = [c for c in required if not cols[c]]
    if missing:
        sys.exit(f"ERROR: required columns unresolved: {missing}\n"
                 f"Run with --inspect and fix ALIASES.")

    # Optional trace-level file supplies label / noise flag if spans lack them.
    trace_meta = None
    if traces_path:
        trace_meta = pd.read_csv(traces_path)
        tcols = {c: resolve(trace_meta, c) for c in ALIASES}
    else:
        tcols = {}

    rows = []
    for tid, g in spans.groupby(cols["trace_id"]):
        f = {"trace_id": tid}

        dur = pd.to_numeric(g[cols["duration_us"]], errors="coerce").dropna()
        svc = g[cols["service"]].astype(str)
        op = g[cols["operation"]].astype(str)

        # --- structural ---
        f["span_count"] = len(g)
        f["service_count"] = svc.nunique()
        f["operation_count"] = op.nunique()

        if cols["parent_span_id"]:
            sid = g[cols["span_id"]].astype(str)
            pid = g[cols["parent_span_id"]].astype(str)
            parents = dict(zip(sid, pid))
            depths = compute_depth(parents)
            f["max_depth"] = max(depths.values()) if depths else 0
            fanout = defaultdict(int)
            for p in pid:
                fanout[p] += 1
            f["max_fanout"] = max(fanout.values()) if fanout else 0

            # service-level call edges
            sid_to_svc = dict(zip(sid, svc))
            edges = set()
            n_edges = 0
            for s, p in parents.items():
                if p in sid_to_svc:
                    caller, callee = sid_to_svc[p], sid_to_svc[s]
                    if caller != callee:
                        edges.add(f"{caller}>{callee}")
                        n_edges += 1
            f["edge_count"] = n_edges
            f["unique_edge_count"] = len(edges)
            f["path_signature"] = hashlib.sha1(
                "|".join(sorted(edges)).encode()
            ).hexdigest()[:16]

            roots = [s for s in parents if parents[s] not in sid_to_svc]
            root_sid = roots[0] if roots else None
            f["root_service"] = sid_to_svc.get(root_sid, "") if root_sid else ""
            root_op_name = dict(zip(sid, op)).get(root_sid, "") if root_sid else ""
            root_url = None
            if root_sid and cols["http_url"]:
                url_by_sid = dict(zip(sid, g[cols["http_url"]]))
                root_url = url_by_sid.get(root_sid)
            f["root_operation"] = _norm_root_op(root_op_name, root_url)
        else:
            for k in ["max_depth", "max_fanout", "edge_count",
                      "unique_edge_count"]:
                f[k] = np.nan
            f["path_signature"] = hashlib.sha1(
                "|".join(sorted(set(svc))).encode()
            ).hexdigest()[:16]
            f["root_service"] = svc.iloc[0]
            first_url = (g[cols["http_url"]].iloc[0]
                        if cols["http_url"] and g[cols["http_url"]].notna().any()
                        else None)
            f["root_operation"] = _norm_root_op(op.iloc[0], first_url)

        # --- timing ---
        if cols["start_time"]:
            st = pd.to_numeric(g[cols["start_time"]], errors="coerce")
            f["trace_duration_us"] = float(
                (st + pd.to_numeric(g[cols["duration_us"]], errors="coerce")).max()
                - st.min()
            ) if st.notna().any() else float(dur.sum())
        else:
            f["trace_duration_us"] = float(dur.max()) if len(dur) else 0.0

        f["span_dur_mean"] = float(dur.mean()) if len(dur) else 0.0
        f["span_dur_median"] = float(dur.median()) if len(dur) else 0.0
        f["span_dur_p95"] = float(dur.quantile(0.95)) if len(dur) else 0.0
        f["span_dur_max"] = float(dur.max()) if len(dur) else 0.0
        f["span_dur_std"] = float(dur.std()) if len(dur) > 1 else 0.0

        # --- error ---
        if cols["is_error"]:
            err = g[cols["is_error"]].astype(str).str.lower().isin(
                ["true", "1", "yes", "error"])
            f["error_span_count"] = int(err.sum())
        else:
            f["error_span_count"] = 0
        f["error_span_rate"] = f["error_span_count"] / max(f["span_count"], 1)

        if cols["http_status"]:
            hs = pd.to_numeric(g[cols["http_status"]], errors="coerce")
            f["http_4xx_count"] = int(((hs >= 400) & (hs < 500)).sum())
            f["http_5xx_count"] = int((hs >= 500).sum())
        else:
            f["http_4xx_count"] = f["http_5xx_count"] = 0

        # --- interaction ---
        f["db_span_count"] = int(
            g[cols["db_statement"]].notna().sum()) if cols["db_statement"] else 0
        f["http_span_count"] = int(
            g[cols["http_url"]].notna().sum()) if cols["http_url"] else 0
        f["distinct_http_targets"] = int(
            g[cols["http_url"]].nunique()) if cols["http_url"] else 0
        f["distinct_db_statements"] = int(
            g[cols["db_statement"]].nunique()) if cols["db_statement"] else 0
        f["distinct_http_methods"] = int(
            g[cols["http_method"]].nunique()) if cols["http_method"] else 0

        # --- labels ---
        f["label"] = g[cols["label"]].iloc[0] if cols["label"] else "unknown"
        f["experiment_id"] = (g[cols["experiment_id"]].iloc[0]
                              if cols["experiment_id"] else "")
        f["infra_noise"] = (str(g[cols["infra_noise"]].iloc[0]).lower()
                            in ("true", "1", "yes")) if cols["infra_noise"] else False

        rows.append(f)

    out = pd.DataFrame(rows)

    # Merge trace-level label / noise flag if the spans file lacked them.
    if trace_meta is not None and tcols.get("trace_id"):
        keep = {}
        for k in ("label", "infra_noise", "experiment_id"):
            if tcols.get(k):
                keep[tcols[k]] = k
        if keep:
            tm = trace_meta[[tcols["trace_id"]] + list(keep)].rename(
                columns={tcols["trace_id"]: "trace_id", **keep})
            # trace_meta (traces.csv from parse_jaeger_traces.py) has one row
            # per SERVICE a trace touched — it is not deduplicated upstream.
            # A plain merge on trace_id is one-to-many and fans out every
            # feature row once per duplicate, silently inflating the trace
            # count by exactly the fan-out factor. Confirmed 2026-08-18:
            # 123 real traces became 439 output rows, matching their
            # per-trace fan-out counts exactly. label/infra_noise/
            # experiment_id are trace-level attributes — identical
            # regardless of which service emitted the row — so dedup
            # before merging rather than after.
            before = len(tm)
            tm = tm.drop_duplicates(subset=["trace_id"])
            if before != len(tm):
                print(f"NOTE: trace_meta had {before - len(tm)} duplicate "
                      f"trace_id rows (multi-service traces); deduplicated "
                      f"before merge to prevent row fan-out.\n")
            out = out.drop(columns=[c for c in keep.values() if c in out.columns],
                           errors="ignore").merge(tm, on="trace_id", how="left")
            assert len(out) == out["trace_id"].nunique(), \
                "fan-out still occurred after dedup — investigate before trusting output"

    n_total = len(out)
    if "infra_noise" in out.columns and not keep_noise:
        out = out[~out["infra_noise"].fillna(False).astype(bool)]
    n_kept = len(out)

    out.to_csv(out_path, index=False)

    print(f"Traces in:        {n_total}")
    print(f"Traces retained:  {n_kept}  ({n_total - n_kept} dropped as infra noise)")
    print(f"Features/trace:   {len(out.columns)}")
    print(f"Written:          {out_path}\n")
    if "label" in out.columns:
        print("Label counts:")
        print(out["label"].value_counts().to_string(), "\n")
    if "root_operation" in out.columns:
        print("Top root operations (stratify comparisons on this):")
        print(out["root_operation"].value_counts().head(10).to_string())
    print("\nFeature families:")
    for fam, cs in FEATURE_FAMILIES.items():
        present = [c for c in cs if c in out.columns]
        print(f"  {fam:<12} {len(present)}/{len(cs)}: {present}")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--spans", required=True, nargs="+",
                   help="one or more spans CSVs; per-service exports should "
                        "all be passed here so duplicates can be removed")
    p.add_argument("--traces", default=None)
    p.add_argument("--out", default="features.csv")
    p.add_argument("--keep-noise", action="store_true")
    p.add_argument("--inspect", action="store_true")
    a = p.parse_args()

    if a.inspect:
        for sp in a.spans:
            inspect(sp)
        if a.traces:
            inspect(a.traces)
        return
    build(a.spans, a.traces, a.out, a.keep_noise)


if __name__ == "__main__":
    main()
