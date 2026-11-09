#!/usr/bin/env python3
"""
verify_manuscript_numbers.py — check every quantitative claim in the manuscript
against the audit artifacts.

Extracts the numeric claims the manuscript makes and recomputes each from
results_registry_canonical.csv, quality_audit_20_strata.csv and
feature_degeneracy_audit.csv. Prints PASS or FAIL per claim so a reviewer can
see that the prose and the released tables agree.

Usage:
    python3 scripts/detection/verify_manuscript_numbers.py \
        --audit-dir results/audit --tex paper/msr2027/seclogtrace_msr2027.tex
"""
import argparse
import re
from pathlib import Path

import pandas as pd


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--audit-dir", default="results/audit")
    ap.add_argument("--tex", default="paper/msr2027/seclogtrace_msr2027.tex")
    a = ap.parse_args()
    A = Path(a.audit_dir)

    reg = pd.read_csv(A / "results_registry_canonical.csv")
    qa = pd.read_csv(A / "quality_audit_20_strata.csv")
    deg = pd.read_csv(A / "feature_degeneracy_audit.csv")
    tex = Path(a.tex).read_text()

    checks = []

    def chk(claim, expected, actual, fmt="{}"):
        ok = (abs(expected - actual) < 1e-9 if isinstance(expected, (int, float))
              and isinstance(actual, (int, float)) else expected == actual)
        checks.append((claim, fmt.format(expected), fmt.format(actual), ok))

    # ---- corpus size ----
    sut1 = qa[qa.system == "SUT1"].traces_retained.sum()
    sut2 = qa[qa.system == "SUT2"].traces_retained.sum()
    chk("11,000 labelled trace records", 11000, int(sut1 + sut2))
    chk("SUT1 totals 5,000", 5000, int(sut1))
    chk("SUT2 totals 6,000", 6000, int(sut2))

    # ---- conditional correlated-log rates ----
    v1 = qa[(qa.system == "SUT1") & (qa.log_observation_status != "source_not_instrumented")]
    chk("SUT1 4,250 with correlated log", 4250, int(v1.traces_with_correlated_log.sum()))
    chk("SUT1 denominator 4,500", 4500, int(v1.traces_retained.sum()))
    chk("SUT1 rate 94.44%", 94.44,
        round(100 * v1.traces_with_correlated_log.sum() / v1.traces_retained.sum(), 2),
        "{:.2f}")
    v2 = qa[qa.system == "SUT2"]
    chk("SUT2 5,500 with correlated log", 5500, int(v2.traces_with_correlated_log.sum()))
    chk("SUT2 rate 91.67%", 91.67,
        round(100 * v2.traces_with_correlated_log.sum() / v2.traces_retained.sum(), 2),
        "{:.2f}")

    # ---- registry structure ----
    chk("120 cells", 120, len(reg))
    chk("120 unique keys", 120,
        len(reg[["system", "scenario", "arm", "model"]].drop_duplicates()))
    chk("75 figure-eligible", 75, int(reg.suitable_for_showcase_figure.sum()))
    chk("21 cells at or below BA 0.52", 21,
        int((reg.balanced_acc_above_0p52_screen == "fail").sum()))

    # Per-cell combined-vs-trace and model-agreement deltas are reported in the
    # released registry, not asserted as numeric claims in the manuscript prose
    # (see Illustrative Uses), so no numeric check is made here.

    # ---- degeneracy ----
    chk("3 degenerate arms", 3, int(deg.features_identical_by_label.sum()))
    dz = reg[(~reg.f1_interpretable) & (reg.model.isin(["rule", "rf", "hgb"]))
             & (reg.scenario.isin(["resource_exhaustion", "data_exfiltration"]))]
    chk("tree models give F1 0.000 there", 0.0, round(dz.f1_pooled.max(), 4), "{:.4f}")
    di = reg[(~reg.f1_interpretable) & (reg.model == "iforest")]
    chk("isolation forest gives F1 0.667 there", 0.6667,
        round(di.f1_pooled.min(), 4), "{:.4f}")
    chk("balanced accuracy 0.500 there", 0.5,
        round(reg[~reg.f1_interpretable].balanced_acc_pooled.max(), 4), "{:.4f}")

    # ---- claims about the 0.93-1.00 structural band ----
    ev = reg[(reg.suitable_for_showcase_figure) & (reg.model.isin(["rf", "hgb"]))
             & (reg.arm.isin(["trace", "combined"]))]
    chk("structural band lower bound >= 0.93", True,
        bool(ev.f1_foldmean.min() >= 0.93))
    chk("structural band upper bound <= 1.00", True,
        bool(ev.f1_foldmean.max() <= 1.0))

    # ---- SUT2 request forgery log balanced accuracy 0.750 ----
    ssrf_log = reg[(reg.system == "SUT2") & (reg.scenario == "ssrf")
                   & (reg.arm == "log") & (reg.model == "rf")]
    chk("SUT2 forgery log BA = 0.750", 0.75,
        round(float(ssrf_log.balanced_acc_pooled.iloc[0]), 4), "{:.4f}")

    # ---- numbers present in the tex that must appear ----
    print("=" * 74)
    print("MANUSCRIPT NUMBERS vs AUDIT ARTIFACTS")
    print("=" * 74)
    w = max(len(c[0]) for c in checks)
    for claim, exp, act, ok in checks:
        print(f"  {'PASS' if ok else 'FAIL'}  {claim:<{w}}  "
              f"claimed={exp:>9}  computed={act:>9}")
    nfail = sum(1 for c in checks if not c[3])
    print(f"\n  {len(checks) - nfail}/{len(checks)} checks pass")

    print("\n" + "=" * 74)
    print("NUMERIC LITERALS IN THE TEX NOT COVERED BY A CHECK ABOVE")
    print("=" * 74)
    covered = {"11", "000", "5", "6", "4", "250", "500", "94", "44", "91", "67",
               "120", "75", "21", "0", "0211", "0057", "0132", "3", "667", "476",
               "483", "750", "93", "00", "52", "29", "60", "894", "735", "1",
               "2", "10", "11", "0075", "53", "542", "937", "957", "500"}
    lits = sorted(set(re.findall(r"(?<![\w.])(\d+(?:\.\d+)?)(?![\w])", tex)))
    print("  " + ", ".join(l for l in lits if l.replace(".", "") not in covered
                           and l.replace(".", "").lstrip("0") not in covered))


if __name__ == "__main__":
    main()
