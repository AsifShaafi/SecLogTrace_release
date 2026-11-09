#!/usr/bin/env python3
"""Generate paper figures for the SecLogTrace v2 corpus / detection study.

Figures (PDF for LaTeX + PNG for preview) -> results/figures/:
  fig1_detection_heatmap     : SUT1 RF F1, class x arm (trace/log/combined)   [RQ1/RQ2]
  fig2_trace_signatures      : median span-count, normal vs attack, per class [RQ3]
  fig3_cross_system          : SUT1 vs SUT2 combined-arm F1, per class         [generalization]
  fig4_detector_comparison   : rule/iforest/rf/hgb combined-arm F1 (SUT1)      [classifier not the bottleneck]

Colorblind-safe Okabe-Ito palette; one y-axis; thin marks; recessive axes;
direct value labels; legend for >=2 series.
"""
import csv, collections, os
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

OUT = "results/figures"; os.makedirs(OUT, exist_ok=True)
CLASSES = ["credential_abuse", "resource_exhaustion", "injection", "data_exfiltration", "ssrf"]
LABELS  = ["credential\nabuse", "resource\nexhaustion", "injection", "data\nexfiltration", "ssrf"]
# Okabe-Ito (CVD-safe)
C_NORMAL, C_ATTACK = "#0072B2", "#D55E00"      # blue / vermillion
C_SUT1,   C_SUT2   = "#0072B2", "#E69F00"      # blue / orange
C_DET = {"rule": "#999999", "iforest": "#56B4E9", "rf": "#0072B2", "hgb": "#009E73"}
INK, MUTED = "#222222", "#666666"

plt.rcParams.update({
    "font.size": 11, "font.family": "sans-serif", "axes.edgecolor": MUTED,
    "axes.labelcolor": INK, "text.color": INK, "xtick.color": MUTED, "ytick.color": MUTED,
    "axes.spines.top": False, "axes.spines.right": False, "figure.dpi": 150,
})

def save(fig, name):
    for ext in ("pdf", "png"):
        fig.savefig(f"{OUT}/{name}.{ext}", bbox_inches="tight")
    plt.close(fig); print(f"  wrote {OUT}/{name}.{{pdf,png}}")

# ---- load detection results ----
def load_det(path):
    d = collections.defaultdict(dict)  # d[class][(arm,detector)] = f1
    for r in csv.DictReader(open(path)):
        d[r["class"]][(r["arm"], r["detector"])] = float(r["f1"])
    return d
sut1 = load_det("results/tables/detection_results.csv")

# ---- Fig 1: detection heatmap (RF, class x arm) ----
arms = ["trace", "log", "combined"]
M = np.array([[sut1[c][(a, "rf")] for a in arms] for c in CLASSES])
fig, ax = plt.subplots(figsize=(5.2, 4.0))
im = ax.imshow(M, cmap="Blues", vmin=0, vmax=1, aspect="auto")
ax.set_xticks(range(len(arms))); ax.set_xticklabels([a.capitalize() for a in arms])
ax.set_yticks(range(len(CLASSES))); ax.set_yticklabels([l.replace("\n", " ") for l in LABELS])
for i in range(len(CLASSES)):
    for j in range(len(arms)):
        v = M[i, j]
        ax.text(j, i, f"{v:.2f}", ha="center", va="center",
                color="white" if v > 0.6 else INK, fontsize=11, fontweight="bold")
ax.set_title("SUT1 detection F1 (supervised RF), class × modality", fontsize=11)
cb = fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04); cb.set_label("F1 (attack class)", color=INK)
ax.tick_params(length=0)
save(fig, "fig1_detection_heatmap")

# ---- Fig 2: trace signatures (median span-count normal vs attack) ----
def median_spans():
    """Median total spans per trace, from the authoritative `span_count`
    feature column (one row per trace in the combined feature table)."""
    out = {}
    for c in CLASSES:
        for lab in ("normal", "attack"):
            vals = [int(float(r["span_count"]))
                    for r in csv.DictReader(open(f"data/processed/combined/{c}_{lab}_features.csv"))]
            out[(c, lab)] = int(np.median(vals)) if vals else 0
    return out
ms = median_spans()
x = np.arange(len(CLASSES)); w = 0.38
fig, ax = plt.subplots(figsize=(7.0, 4.0))
bn = ax.bar(x - w/2, [ms[(c,"normal")] for c in CLASSES], w, label="normal", color=C_NORMAL)
ba = ax.bar(x + w/2, [ms[(c,"attack")] for c in CLASSES], w, label="attack", color=C_ATTACK)
ax.set_yscale("log")
ax.set_ylabel("median spans per trace (log scale)")
ax.set_xticks(x); ax.set_xticklabels(LABELS)
ax.set_title("Per-class trace signature: span count, normal vs attack (SUT1)", fontsize=11)
for bars in (bn, ba):
    for b in bars:
        ax.annotate(f"{int(b.get_height())}", (b.get_x()+b.get_width()/2, b.get_height()),
                    ha="center", va="bottom", fontsize=9, color=INK, xytext=(0,1), textcoords="offset points")
ax.legend(frameon=False, loc="upper right")
ax.grid(axis="y", color="#dddddd", linewidth=0.6); ax.set_axisbelow(True)
save(fig, "fig2_trace_signatures")

# ---- Fig 3: cross-system (SUT1 vs SUT2, combined F1) ----
cs = {}  # cs[class] = (sut1, sut2)
for r in csv.DictReader(open("results/tables/cross_system_comparison.csv")):
    if r["arm"] == "combined":
        cs[r["class"]] = (float(r["sut1_rf_f1"]), float(r["sut2_rf_f1"]))
fig, ax = plt.subplots(figsize=(7.0, 4.0))
b1 = ax.bar(x - w/2, [cs[c][0] for c in CLASSES], w, label="SUT1 (Train-Ticket)", color=C_SUT1)
b2 = ax.bar(x + w/2, [cs[c][1] for c in CLASSES], w, label="SUT2 (TeaStore)", color=C_SUT2)
ax.set_ylabel("combined-arm F1 (RF)"); ax.set_ylim(0, 1.08)
ax.set_xticks(x); ax.set_xticklabels(LABELS)
ax.set_title("Cross-system generalization: combined-arm F1 by class", fontsize=11)
for bars in (b1, b2):
    for b in bars:
        ax.annotate(f"{b.get_height():.2f}", (b.get_x()+b.get_width()/2, b.get_height()),
                    ha="center", va="bottom", fontsize=9, color=INK, xytext=(0,1), textcoords="offset points")
ax.legend(frameon=False, loc="lower left")
ax.grid(axis="y", color="#dddddd", linewidth=0.6); ax.set_axisbelow(True)
save(fig, "fig3_cross_system")

# ---- Fig 4: detector comparison (combined arm, SUT1) ----
dets = ["rule", "iforest", "rf", "hgb"]; dw = 0.2
fig, ax = plt.subplots(figsize=(7.4, 4.0))
for k, det in enumerate(dets):
    vals = [sut1[c].get(("combined", det), 0.0) for c in CLASSES]
    ax.bar(x + (k-1.5)*dw, vals, dw, label=det.upper() if det!="iforest" else "IsoForest", color=C_DET[det])
ax.set_ylabel("combined-arm F1 (attack)"); ax.set_ylim(0, 1.08)
ax.set_xticks(x); ax.set_xticklabels(LABELS)
ax.set_title("Detector comparison (SUT1, combined F1): gradient boosting ≈ RF — classifier is not the bottleneck", fontsize=9.5)
ax.legend(frameon=False, ncol=4, loc="lower center", fontsize=9)
ax.grid(axis="y", color="#dddddd", linewidth=0.6); ax.set_axisbelow(True)
save(fig, "fig4_detector_comparison")

# ---- Fig 5: SUT2 detection heatmap (RF, class x arm) ----
# Companion to fig1; Oranges (vs fig1 Blues) keeps the two systems visually
# distinct. SUT2's per-arm profile is the cross-system half of RQ1/RQ2.
sut2 = load_det("results/tables/detection_results_sut2_v2.csv")
M2 = np.array([[sut2[c][(a, "rf")] for a in arms] for c in CLASSES])
fig, ax = plt.subplots(figsize=(5.2, 4.0))
im = ax.imshow(M2, cmap="Oranges", vmin=0, vmax=1, aspect="auto")
ax.set_xticks(range(len(arms))); ax.set_xticklabels([a.capitalize() for a in arms])
ax.set_yticks(range(len(CLASSES))); ax.set_yticklabels([l.replace("\n", " ") for l in LABELS])
for i in range(len(CLASSES)):
    for j in range(len(arms)):
        v = M2[i, j]
        ax.text(j, i, f"{v:.2f}", ha="center", va="center",
                color="white" if v > 0.6 else INK, fontsize=11, fontweight="bold")
ax.set_title("SUT2 detection F1 (supervised RF), class × modality", fontsize=11)
cb = fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04); cb.set_label("F1 (attack class)", color=INK)
ax.tick_params(length=0)
save(fig, "fig5_detection_heatmap_sut2")

print("done")
