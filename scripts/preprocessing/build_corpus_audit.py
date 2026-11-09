#!/usr/bin/env python3
"""
build_corpus_audit.py — corpus accounting and telemetry-availability audit

Generates the three audit artifacts that the corpus release and the data
showcase paper's composition table are built from:

  sut1_stratum_ledger.csv
      One row per SUT1 trace: scenario, label, hashed trace id, include /
      exclude decision, and the reason. Traces that cannot be attributed to a
      generated request are excluded, with the reason recorded rather than
      summarised.

  telemetry_availability.csv
      Per stratum, the three-state log-observation status:
        matched            - capture verified available, >=1 log line joined
        verified_no_match  - capture verified available, no log line for this
                             trace (a real observation; the absence is signal)
        unavailable        - no trace-correlated capture exists for the
                             stratum, so per-trace absence cannot be verified
      Coverage percentages are reported only over strata whose capture is
      verified available. Unavailable strata are reported separately and are
      never counted as zero.

  detection_before_after.csv
      Reported detection F1 against F1 recomputed after the exclusions, per
      class x arm x detector, so the effect of the exclusions on every
      published cell is measured rather than assumed.

Counts come from the feature tables and the generator transcripts in
data/raw/traffic/. Nothing is hard-coded except the documented sampling of
resource_exhaustion (1500 requests fired, 920 clean 172-span traces retained,
sampled to 500 at seed 42) and the generated-request totals read from the
transcripts.

Usage:
    python3 scripts/preprocessing/build_corpus_audit.py \
        --processed-dir data/processed \
        --traffic-dir data/raw/traffic \
        --results-csv results/tables/detection_results.csv \
        --out-dir results/audit
"""
import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

import numpy as np
import pandas as pd

CLASSES = ["ssrf", "credential_abuse", "resource_exhaustion",
           "injection", "data_exfiltration"]

# Strata with no trace-correlated log capture. SUT1 ssrf/normal: the SSRF sink
# (ts-avatar-service) is a Flask application that logs errors only and emits no
# trace context, so no line in the normal window carries a trace id. Per-trace
# log absence therefore cannot be verified for this stratum.
UNAVAILABLE = {("ssrf", "normal")}

# resource_exhaustion attack is over-provisioned by design; see module docstring.
SAMPLED_NOTE = {("resource_exhaustion", "attack"):
                "over_provisioned_1500_fired_920_clean_sampled_500_seed42"}


def sha16(s):
    return hashlib.sha256(s.encode()).hexdigest()[:16]


def generated_counts(traffic_dir):
    """Generated request count per (class, label) from the transcripts."""
    counts = {}
    for fp in sorted(Path(traffic_dir).glob("*.jsonl")):
        name = fp.stem
        if name.startswith("sut2"):
            continue
        recs = [json.loads(l) for l in open(fp) if l.strip()]
        # The SSRF attack transcript is named ssrf_ssrf_* and its class_label
        # values are sub-types, so derive the label from the records, not the
        # filename. A record whose class_label is not "normal" is an attack.
        if not recs:
            continue
        labels = {r.get("class_label") for r in recs}
        label = "normal" if labels == {"normal"} else "attack"
        cls = next((c for c in CLASSES if name.startswith(c)), None)
        if cls is None:
            continue
        # Skip aborted runs: records with no http_status never reached the SUT.
        usable = [r for r in recs if r.get("http_status") is not None]
        counts[(cls, label)] = counts.get((cls, label), 0) + len(usable)
    return counts


def load_stratum(processed, cls, label):
    f = pd.read_csv(processed / "combined" / f"{cls}_{label}_features.csv",
                    dtype={"trace_id": str})
    lp = processed / "logs" / f"{cls}_{label}" / "logs_by_trace.csv"
    cols = ["trace_id", "log_line_count", "error_count", "warn_count", "service_count"]
    logs = (pd.read_csv(lp, dtype={"trace_id": str})[cols]
            .rename(columns={"service_count": "log_service_count"})
            .drop_duplicates("trace_id"))
    return f, logs


def exclusion_mask(cls, label, f):
    """Return a Series of reasons; the default reason means 'keep'."""
    reason = pd.Series("attributable_to_generated_request", index=f.index)

    if cls == "data_exfiltration":
        # The generator authenticates before issuing admin reads. That setup
        # login falls inside the export window and is not a data-exfiltration
        # observation: it is a login trace (12 spans, 3 DB calls) at a
        # different endpoint from every other trace in the class.
        m = f["root_operation"] == "POST /* /api/v1/users/login"
        reason[m] = "generator_setup_login"

    if cls == "ssrf" and label == "normal":
        # The generator issued 500 normal uploads, all HTTP 200. Traces
        # carrying an error or 5xx span in this window are not attributable to
        # a generated request.
        m = (f["error_span_count"] > 0) | (f["http_5xx_count"] > 0)
        reason[m] = "stray_non_generator_traffic"

    return reason


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--processed-dir", default="data/processed")
    ap.add_argument("--traffic-dir", default="data/raw/traffic")
    ap.add_argument("--results-csv", default="results/tables/detection_results.csv")
    ap.add_argument("--out-dir", default="results/audit")
    ap.add_argument("--detection-module-dir", default="scripts/detection",
                    help="directory holding run_detection.py, imported for its "
                         "DROP / LOG_FEATURES / DETECTORS definitions so the "
                         "recomputation matches the published protocol exactly")
    a = ap.parse_args()

    processed = Path(a.processed_dir)
    out = Path(a.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    sys.path.insert(0, os.path.abspath(a.detection_module_dir))
    from run_detection import DROP, LOG_FEATURES, DETECTORS  # noqa: E402

    gen = generated_counts(a.traffic_dir)

    # ---------------------------------------------------------- 1. ledger
    ledger, strata = [], []
    for cls in CLASSES:
        for label in ["normal", "attack"]:
            f, _ = load_stratum(processed, cls, label)
            reason = exclusion_mask(cls, label, f)
            excluded = reason != "attributable_to_generated_request"
            for tid, rsn, exc in zip(f["trace_id"], reason, excluded):
                ledger.append(dict(
                    system="SUT1", scenario=cls, label=label,
                    trace_id_sha256_16=sha16(tid),
                    decision="excluded" if exc else "included", reason=rsn))
            strata.append(dict(
                scenario=cls, label=label,
                generated_requests=gen.get((cls, label)),
                traces_before=len(f),
                excluded=int(excluded.sum()),
                traces_after=int((~excluded).sum()),
                note=SAMPLED_NOTE.get((cls, label), "")))

    led = pd.DataFrame(ledger)
    led.to_csv(out / "sut1_stratum_ledger.csv", index=False)
    st = pd.DataFrame(strata)

    print("=== SUT1 stratum ledger ===")
    print(st.to_string(index=False))
    b, e, aft = st.traces_before.sum(), st.excluded.sum(), st.traces_after.sum()
    print(f"\n  before {b}  excluded {e}  after {aft}   ({b} - {e} = {b - e}, "
          f"consistent: {b - e == aft})")
    print(f"  reasons: {led[led.decision == 'excluded'].reason.value_counts().to_dict()}")

    # ------------------------------------------ 2. telemetry availability
    rows = []
    for cls in CLASSES:
        for label in ["normal", "attack"]:
            f, logs = load_stratum(processed, cls, label)
            keep = exclusion_mask(cls, label, f) == "attributable_to_generated_request"
            f = f[keep]
            matched = int(f["trace_id"].isin(set(logs["trace_id"])).sum())
            n = len(f)
            if (cls, label) in UNAVAILABLE:
                status, cov, vnm = "unavailable", None, None
            else:
                cov = round(100.0 * matched / n, 2) if n else None
                vnm = n - matched
                status = "matched" if matched == n else "matched+verified_no_match"
            rows.append(dict(system="SUT1", scenario=cls, label=label, traces=n,
                             matched=matched, verified_no_match=vnm,
                             coverage_pct=cov, log_observation_status=status))
    av = pd.DataFrame(rows)
    av.to_csv(out / "telemetry_availability.csv", index=False)
    print("\n=== Telemetry availability (three-state) ===")
    print(av.to_string(index=False))
    verified = av[av.log_observation_status != "unavailable"]
    print(f"\n  coverage over verified-capture strata only: "
          f"{verified.matched.sum()}/{verified.traces.sum()} = "
          f"{100.0 * verified.matched.sum() / verified.traces.sum():.2f}%")
    print(f"  strata marked unavailable: "
          f"{list(av[av.log_observation_status == 'unavailable'][['scenario', 'label']].itertuples(index=False, name=None))}")

    # --------------------------------------- 3. detection before / after
    recomputed = []
    for cls in CLASSES:
        frames = []
        for label, y in (("normal", 0), ("attack", 1)):
            f, logs = load_stratum(processed, cls, label)
            keep = exclusion_mask(cls, label, f) == "attributable_to_generated_request"
            d = f[keep].merge(logs, on="trace_id", how="left")
            d[LOG_FEATURES] = d[LOG_FEATURES].fillna(0)
            d["_y"] = y
            frames.append(d)
        data = pd.concat(frames, ignore_index=True)
        y = data["_y"].to_numpy()
        tcols = [c for c in data.columns
                 if c not in DROP and c not in LOG_FEATURES and c != "_y"
                 and pd.api.types.is_numeric_dtype(data[c])]
        Xt = data[tcols].fillna(0).to_numpy()
        Xl = data[LOG_FEATURES].fillna(0).to_numpy()
        for arm, X in {"trace": Xt, "log": Xl,
                       "combined": np.hstack([Xt, Xl])}.items():
            for det, fn in DETECTORS.items():
                p, r, f1 = fn(X, y)
                recomputed.append({"class": cls, "arm": arm, "detector": det,
                                   "n_after": len(y), "f1_after": round(f1, 3)})

    new = pd.DataFrame(recomputed)
    pub = pd.read_csv(a.results_csv)
    cmp = pub.merge(new, on=["class", "arm", "detector"])
    cmp["delta"] = (cmp["f1_after"] - cmp["f1"]).round(3)
    cmp.to_csv(out / "detection_before_after.csv", index=False)

    print("\n=== Detection: published vs recomputed after exclusions ===")
    moved = cmp[cmp.delta.abs() >= 0.001]
    print(f"  cells compared : {len(cmp)}")
    print(f"  cells moved    : {len(moved)}")
    print(f"  max |delta|    : {cmp.delta.abs().max():.3f}")
    if len(moved):
        print(moved[["class", "arm", "detector", "f1", "f1_after", "delta"]]
              .to_string(index=False))
    print(f"\nWrote {out}/sut1_stratum_ledger.csv, {out}/telemetry_availability.csv, "
          f"{out}/detection_before_after.csv")


if __name__ == "__main__":
    main()
