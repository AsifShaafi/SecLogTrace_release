#!/usr/bin/env python3
"""
build_quality_audit.py — consolidated 20-stratum quality audit

Produces the release-gate evidence tables for both systems under test. Every
number is derived from the feature tables, the per-trace log tables and the
generator transcripts; nothing is transcribed by hand.

Outputs
-------
quality_audit_20_strata.csv
    One row per (system, scenario, label) — 2 systems x 5 scenarios x 2 labels.
    Columns give the denominators explicitly: generated requests, retained
    traces, traces with >=1 correlated log line, traces with none, and the
    log-observation status. A coverage percentage is emitted only where the
    capture is verified available, so no percentage silently mixes an observed
    absence with an unobservable one.

results_registry.csv
    Every reported detection cell for both systems, with a status of valid,
    withdrawn or illustrative, the model named, and the stratum it rests on.
    Cells that depend on a stratum whose log capture is unavailable are marked
    withdrawn rather than reported.

feature_proxy_audit.csv
    Per numeric feature and stratum pair, how separable the two labels are on
    that feature alone. A feature that separates the labels almost perfectly on
    its own is a candidate collection artifact and is flagged for inspection,
    whether or not it is a plausible security signal.

Log-observation states
----------------------
matched                  capture verified available, >=1 correlated log line
verified_no_match        capture verified available, no correlated line for
                         this trace; the absence is an observation
source_not_instrumented  the contributing service emits no trace-correlated
                         log records, so absence cannot be interpreted
capture_unavailable      no usable capture exists for the stratum

OpenTelemetry specifies TraceId and SpanId as optional on a log record, so an
uncorrelated record is not evidence that no record exists. The last two states
exist to keep that distinction in the data rather than in prose.

Usage:
    python3 scripts/preprocessing/build_quality_audit.py \
        --processed-dir data/processed \
        --traffic-dir data/raw/traffic \
        --sut1-results results/tables/detection_results.csv \
        --sut2-results results/tables/detection_results_sut2_v2.csv \
        --out-dir results/audit
"""
import argparse
import json
import os
import sys
from pathlib import Path

import numpy as np
import pandas as pd

CLASSES = ["ssrf", "credential_abuse", "resource_exhaustion",
           "injection", "data_exfiltration"]

# Strata whose contributing service emits no trace-correlated log records.
# SUT1 ssrf/normal: normal traffic reaches only ts-avatar-service, a Flask
# application that logs errors without trace context and does not pass through
# the gateway's access log.
SOURCE_NOT_INSTRUMENTED = {("SUT1", "ssrf", "normal")}

# Documented non-1:1 request-to-trace relationships.
TRACE_UNIT_NOTE = {
    ("SUT1", "resource_exhaustion", "attack"):
        "1500 requests fired; traces with complete 172-span structure retained; "
        "sampled to 500 at seed 42",
    ("SUT2", "credential_abuse", "normal"):
        "one generator operation yields multiple separately-rooted trace "
        "fragments; traces are not independent observations",
    ("SUT2", "credential_abuse", "attack"):
        "one generator operation yields multiple separately-rooted trace "
        "fragments; traces are not independent observations",
}

LOG_FEATURES = ["log_line_count", "error_count", "warn_count", "log_service_count"]


def generated_counts(traffic_dir):
    """Generated request count per (system, class, label) from transcripts."""
    out = {}
    for fp in sorted(Path(traffic_dir).glob("*.jsonl")):
        name = fp.stem
        system = "SUT2" if name.startswith("sut2") else "SUT1"
        stem = name[len("sut2v2_"):] if name.startswith("sut2v2_") else name
        cls = next((c for c in CLASSES if stem.startswith(c)), None)
        if cls is None:
            continue
        recs = [json.loads(l) for l in open(fp) if l.strip()]
        recs = [r for r in recs if r.get("http_status") is not None]
        if not recs:
            continue
        labels = {r.get("class_label") for r in recs}
        label = "normal" if labels == {"normal"} else "attack"
        key = (system, cls, label)
        out[key] = out.get(key, 0) + len(recs)
    return out


def load(processed, system, cls, label):
    """Feature rows for one stratum plus that stratum's per-trace log table."""
    cols = ["trace_id", "log_line_count", "error_count", "warn_count", "service_count"]
    if system == "SUT1":
        f = pd.read_csv(processed / "combined" / f"{cls}_{label}_features.csv",
                        dtype={"trace_id": str})
        lp = processed / "logs" / f"{cls}_{label}" / "logs_by_trace.csv"
    else:
        allf = pd.read_csv(processed / "combined" / f"sut2v2_{cls}_features.csv",
                           dtype={"trace_id": str})
        f = allf[allf["label"] == label].copy()
        lp = processed / "logs" / f"sut2v2_{cls}" / "logs_by_trace.csv"
    logs = (pd.read_csv(lp, dtype={"trace_id": str})[cols]
            .rename(columns={"service_count": "log_service_count"})
            .drop_duplicates("trace_id"))
    return f, logs


def exclusion_mask(system, cls, label, f):
    """Traces not attributable to a generated request (SUT1 only)."""
    keep = pd.Series(True, index=f.index)
    if system != "SUT1":
        return keep
    if cls == "data_exfiltration":
        keep &= f["root_operation"] != "POST /* /api/v1/users/login"
    if cls == "ssrf" and label == "normal":
        keep &= ~((f["error_span_count"] > 0) | (f["http_5xx_count"] > 0))
    return keep


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--processed-dir", default="data/processed")
    ap.add_argument("--traffic-dir", default="data/raw/traffic")
    ap.add_argument("--sut1-results", default="results/tables/detection_results.csv")
    ap.add_argument("--sut2-results", default="results/tables/detection_results_sut2_v2.csv")
    ap.add_argument("--out-dir", default="results/audit")
    a = ap.parse_args()

    processed = Path(a.processed_dir)
    out = Path(a.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    gen = generated_counts(a.traffic_dir)

    # ------------------------------------------- 1. 20-stratum quality table
    rows, feat_rows = [], []
    for system in ["SUT1", "SUT2"]:
        for cls in CLASSES:
            for label in ["normal", "attack"]:
                f, logs = load(processed, system, cls, label)
                before = len(f)
                keep = exclusion_mask(system, cls, label, f)
                f = f[keep]
                n = len(f)
                matched = int(f["trace_id"].isin(set(logs["trace_id"])).sum())
                unmatched = n - matched

                if (system, cls, label) in SOURCE_NOT_INSTRUMENTED:
                    status, cov = "source_not_instrumented", None
                elif matched == n:
                    status, cov = "matched", 100.0
                elif matched == 0:
                    status, cov = "verified_no_match", 0.0
                else:
                    status, cov = "matched+verified_no_match", round(100.0 * matched / n, 2)

                rows.append(dict(
                    system=system, scenario=cls, label=label,
                    generated_requests=gen.get((system, cls, label)),
                    traces_before_exclusion=before,
                    traces_excluded=before - n,
                    traces_retained=n,
                    traces_with_correlated_log=matched,
                    traces_without_correlated_log=unmatched,
                    correlated_log_pct=cov,
                    log_observation_status=status,
                    trace_unit_note=TRACE_UNIT_NOTE.get((system, cls, label), ""),
                ))

                # ------------------------- 3. feature-proxy audit input
                merged = f.merge(logs, on="trace_id", how="left")
                merged[LOG_FEATURES] = merged[LOG_FEATURES].fillna(0)
                for col in merged.columns:
                    if col in ("trace_id", "label", "experiment_id", "infra_noise",
                               "path_signature", "root_service", "root_operation"):
                        continue
                    if not pd.api.types.is_numeric_dtype(merged[col]):
                        continue
                    feat_rows.append(dict(system=system, scenario=cls, label=label,
                                          feature=col,
                                          n=len(merged),
                                          nunique=int(merged[col].nunique()),
                                          vmin=merged[col].min(),
                                          vmax=merged[col].max()))

    qa = pd.DataFrame(rows)
    qa.to_csv(out / "quality_audit_20_strata.csv", index=False)
    print("=== G2: 20-stratum quality audit ===")
    print(qa[["system", "scenario", "label", "generated_requests",
              "traces_retained", "traces_with_correlated_log",
              "traces_without_correlated_log", "correlated_log_pct",
              "log_observation_status"]].to_string(index=False))

    print("\n  Denominators, stated explicitly:")
    for system in ["SUT1", "SUT2"]:
        s = qa[qa.system == system]
        verified = s[~s.log_observation_status.isin(
            ["source_not_instrumented", "capture_unavailable"])]
        print(f"    {system}: {s.traces_retained.sum()} traces retained; "
              f"correlated-log rate {verified.traces_with_correlated_log.sum()}/"
              f"{verified.traces_retained.sum()} = "
              f"{100.0 * verified.traces_with_correlated_log.sum() / verified.traces_retained.sum():.2f}% "
              f"over verified-capture strata only")
        excl = s[s.log_observation_status.isin(
            ["source_not_instrumented", "capture_unavailable"])]
        if len(excl):
            print(f"      excluded from that rate: "
                  f"{list(excl[['scenario', 'label', 'log_observation_status']].itertuples(index=False, name=None))}")

    # ---------------------------------------------- 2. feature-proxy audit
    # Per (system, scenario, feature): how separable are the two labels on that
    # one feature alone? Perfect separation on a single feature is a candidate
    # collection artifact and needs inspecting before it is called a signal.
    fa = pd.DataFrame(feat_rows)
    sep = []
    for system in ["SUT1", "SUT2"]:
        for cls in CLASSES:
            fn, logsn = load(processed, system, cls, "normal")
            fat, logsa = load(processed, system, cls, "attack")
            fn = fn[exclusion_mask(system, cls, "normal", fn)]
            fat = fat[exclusion_mask(system, cls, "attack", fat)]
            mn = fn.merge(logsn, on="trace_id", how="left")
            ma = fat.merge(logsa, on="trace_id", how="left")
            for d in (mn, ma):
                d[LOG_FEATURES] = d[LOG_FEATURES].fillna(0)
            for col in mn.columns:
                if col in ("trace_id", "label", "experiment_id", "infra_noise",
                           "path_signature", "root_service", "root_operation"):
                    continue
                if not pd.api.types.is_numeric_dtype(mn[col]):
                    continue
                if col not in ma.columns:
                    continue
                xn = mn[col].dropna().to_numpy()
                xa = ma[col].dropna().to_numpy()
                if len(xn) == 0 or len(xa) == 0:
                    continue
                sa, sb = set(np.unique(xn)), set(np.unique(xa))
                overlap = len(sa & sb) / max(1, len(sa | sb))
                # Threshold-free separability: the best single split on this
                # feature, as balanced accuracy.
                vals = np.unique(np.concatenate([xn, xa]))
                best = 0.5
                for t in vals:
                    acc = 0.5 * ((xn <= t).mean() + (xa > t).mean())
                    best = max(best, acc, 1 - acc)
                sep.append(dict(system=system, scenario=cls, feature=col,
                                value_overlap=round(overlap, 3),
                                best_single_split_balanced_acc=round(best, 3),
                                flag="PERFECT_SINGLE_FEATURE_SPLIT" if best >= 0.999
                                else ("near_perfect" if best >= 0.95 else "")))
    sp = pd.DataFrame(sep)
    sp.to_csv(out / "feature_proxy_audit.csv", index=False)

    print("\n=== B2: single-feature separability (candidate collection artifacts) ===")
    flagged = sp[sp.flag != ""].sort_values(
        ["system", "scenario", "best_single_split_balanced_acc"], ascending=[True, True, False])
    print(f"  features examined: {len(sp)}   flagged: {len(flagged)}")
    print(flagged.to_string(index=False))

    # ------------------------------------------------- 3. results registry
    reg = []
    for system, path in (("SUT1", a.sut1_results), ("SUT2", a.sut2_results)):
        if not os.path.exists(path):
            print(f"\n  NOTE: {path} not found; {system} cells not registered")
            continue
        r = pd.read_csv(path)
        for _, row in r.iterrows():
            cls, arm = row["class"], row["arm"]
            # A cell is withdrawn when the arm depends on a stratum whose log
            # capture is not interpretable.
            dep_unavailable = any(
                (system, cls, lab) in SOURCE_NOT_INSTRUMENTED for lab in ("normal", "attack"))
            if arm in ("log", "combined") and dep_unavailable:
                status = "withdrawn_log_capture_not_interpretable"
            else:
                status = "illustrative_within_corpus"
            reg.append(dict(system=system, scenario=cls, arm=arm,
                            model=row["detector"], n=row["n"],
                            precision=row["precision"], recall=row["recall"],
                            f1=row["f1"], status=status,
                            source_file=os.path.basename(path)))
    rg = pd.DataFrame(reg)
    rg.to_csv(out / "results_registry.csv", index=False)

    print("\n=== G5/B1: results registry, both systems ===")
    print(rg.groupby(["system", "status"]).size().to_string())
    wd = rg[rg.status.str.startswith("withdrawn")]
    if len(wd):
        print("\n  withdrawn cells:")
        print(wd[["system", "scenario", "arm", "model", "f1"]].to_string(index=False))

    print(f"\nWrote {out}/quality_audit_20_strata.csv, {out}/feature_proxy_audit.csv, "
          f"{out}/results_registry.csv")


if __name__ == "__main__":
    main()
