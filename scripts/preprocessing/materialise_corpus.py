#!/usr/bin/env python3
"""
materialise_corpus.py - apply the SUT1 exclusion to the shipped feature tables.

Five SUT1 traces are not attributable to a generated request. Until now the
exclusion lived only in build_results_registry.py, so the shipped tables held
11,005 rows while every reported number was computed over 11,000. A reviewer
loading the CSVs directly got a different corpus from the one in the paper.

This script closes that gap. It rewrites the ten SUT1 feature tables with the
excluded rows removed, and records what it removed.

Two design points matter.

Rows are filtered as TEXT, not through a DataFrame round-trip. Retained lines
are copied byte for byte, so no float is reformatted, no quoting changes and no
column order shifts. Only the dropped lines disappear. The alternative -
read_csv then to_csv - silently rewrites every value in the file.

Nothing is destroyed. Every dropped row is written out verbatim, with its
source file and the predicate that matched it, to
results/audit/excluded_traces.csv. The operation is reversible from that
ledger.

The script is idempotent. A table already at its post-exclusion row count is
left untouched, so a second run is a no-op rather than a second deletion.

Usage:
    python3 scripts/preprocessing/materialise_corpus.py \\
        --processed-dir data/processed --out-dir results/audit

    python3 scripts/preprocessing/materialise_corpus.py --dry-run
"""
import argparse
import csv
import hashlib
import sys
from pathlib import Path

import pandas as pd

SCENARIOS = ["ssrf", "credential_abuse", "injection",
             "data_exfiltration", "resource_exhaustion"]
EXPECTED_PER_LABEL = 500

# The predicate, stated once. It is the same rule as exclusion_keep() in
# scripts/detection/build_results_registry.py; this script is what makes it
# visible in the data rather than only in the code.
#
#   data_exfiltration : traces rooted at the login operation are driven by the
#                       harness authenticating, not by a generated scenario
#                       request.
#   ssrf / normal     : normal-window traces carrying an error span or a 5xx
#                       are not clean baseline traffic.
PREDICATES = {
    ("data_exfiltration", "normal"): "root_operation == 'POST /* /api/v1/users/login'",
    ("data_exfiltration", "attack"): "root_operation == 'POST /* /api/v1/users/login'",
    ("ssrf", "normal"): "error_span_count > 0 or http_5xx_count > 0",
}


def drop_mask(cls, label, f):
    """True where a row must be dropped."""
    drop = pd.Series(False, index=f.index)
    if cls == "data_exfiltration":
        drop |= f["root_operation"] == "POST /* /api/v1/users/login"
    if cls == "ssrf" and label == "normal":
        drop |= (f["error_span_count"] > 0) | (f["http_5xx_count"] > 0)
    return drop


def sha256_file(path):
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--processed-dir", default="data/processed")
    ap.add_argument("--out-dir", default="results/audit")
    ap.add_argument("--dry-run", action="store_true",
                    help="report what would change and write nothing")
    a = ap.parse_args()

    processed = Path(a.processed_dir)
    ledger_rows, summary, header_ref = [], [], None
    total_before = total_after = 0

    for cls in SCENARIOS:
        for label in ("normal", "attack"):
            fp = processed / "combined" / f"{cls}_{label}_features.csv"
            if not fp.is_file():
                sys.exit(f"missing: {fp}")

            f = pd.read_csv(fp, dtype={"trace_id": str})
            before = len(f)
            total_before += before

            if before == EXPECTED_PER_LABEL:
                summary.append((cls, label, before, before, 0, "already applied"))
                total_after += before
                continue

            drop = drop_mask(cls, label, f)
            ndrop = int(drop.sum())
            after = before - ndrop

            if after != EXPECTED_PER_LABEL:
                sys.exit(
                    f"REFUSING to write {fp.name}: predicate leaves {after} rows, "
                    f"expected {EXPECTED_PER_LABEL}. The predicate and the data "
                    f"disagree; resolve that before materialising."
                )

            dropped_ids = set(f.loc[drop, "trace_id"].astype(str))
            pred = PREDICATES.get((cls, label), "n/a")
            sha_before = sha256_file(fp)

            # Record the dropped rows verbatim before touching the file.
            for _, row in f.loc[drop].iterrows():
                d = {"source_file": fp.name, "scenario": cls, "label": label,
                     "predicate": pred}
                d.update({k: row[k] for k in f.columns})
                ledger_rows.append(d)
                if header_ref is None:
                    header_ref = ["source_file", "scenario", "label",
                                  "predicate"] + list(f.columns)

            if not a.dry_run:
                # Text-exact filter: keep the header and every line whose
                # trace_id is not dropped. Retained lines are byte-identical.
                raw = fp.read_text(encoding="utf-8").splitlines(keepends=True)
                head, body = raw[0], raw[1:]
                tid_col = list(f.columns).index("trace_id")
                kept = []
                for line in body:
                    if not line.strip():
                        continue
                    fields = next(csv.reader([line]))
                    if fields[tid_col] not in dropped_ids:
                        kept.append(line)
                if len(kept) != EXPECTED_PER_LABEL:
                    sys.exit(f"text filter kept {len(kept)} lines for {fp.name}, "
                             f"expected {EXPECTED_PER_LABEL}; not writing")
                if kept and not kept[-1].endswith("\n"):
                    kept[-1] += "\n"
                fp.write_text(head + "".join(kept), encoding="utf-8",
                              newline="")
                sha_after = sha256_file(fp)
            else:
                sha_after = "(dry-run)"

            total_after += after
            summary.append((cls, label, before, after, ndrop,
                            f"{sha_before[:12]} -> {sha_after[:12]}"))

    print("=" * 92)
    print("MATERIALISE SUT1 EXCLUSION" + ("  (DRY RUN)" if a.dry_run else ""))
    print("=" * 92)
    print(f"  {'scenario':22s} {'label':7s} {'before':>7} {'after':>7} "
          f"{'dropped':>8}  note")
    for cls, label, b, af, nd, note in summary:
        print(f"  {cls:22s} {label:7s} {b:>7} {af:>7} {nd:>8}  {note}")
    print(f"\n  SUT1 rows: {total_before} -> {total_after}   dropped "
          f"{total_before - total_after}")
    print(f"  SUT2 is unchanged at 6,000, so the corpus becomes "
          f"{total_after + 6000}.")

    if total_after != 5000:
        sys.exit(f"\n  FAIL: SUT1 total is {total_after}, expected 5000")

    if ledger_rows and not a.dry_run:
        out = Path(a.out_dir) / "excluded_traces.csv"
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=header_ref)
            w.writeheader()
            w.writerows(ledger_rows)
        print(f"\n  wrote {out} - {len(ledger_rows)} excluded row(s), verbatim")
        print("  The exclusion is reversible from that file.")
    elif not ledger_rows:
        print("\n  nothing to do; the exclusion is already materialised")

    print("\n  Re-run build_results_registry.py and verify_manuscript_numbers.py now.")
    print("  The predicate becomes a no-op, and every number must be unchanged.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
