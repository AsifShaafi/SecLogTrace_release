#!/usr/bin/env bash
# Day 1 — Create SecLogTrace workspace
# Usage: ./init_workspace.sh [base_path]
# Default base_path: ~/SecLogTrace

set -euo pipefail

BASE="${1:-$HOME/SecLogTrace}"

echo "Creating SecLogTrace workspace at: $BASE"

mkdir -p "$BASE"/data/raw/{jaeger,logs,traffic}
mkdir -p "$BASE"/data/processed/{traces,logs,combined}
mkdir -p "$BASE"/scripts/{collection,preprocessing,feature_extraction,modeling,visualization}
mkdir -p "$BASE"/notebooks
mkdir -p "$BASE"/metadata
mkdir -p "$BASE"/docs/{daily_logs,weekly_reports,setup_notes,experiment_protocols,error_logs,advisor_updates,paper_notes}
mkdir -p "$BASE"/results/{figures,tables,models}
mkdir -p "$BASE"/manuscript

# README
cat > "$BASE/README.md" << 'EOF'
# SecLogTrace

Security anomaly detection in microservice systems via fused OpenTelemetry
distributed traces and logs. Benchmark: Train-Ticket on Kubernetes.

Start date: 2026-07-08
Target: two conference papers (SANER 2027, MSR 2027) feeding a March 2027
PhD preliminary exam.

## Rules
- `data/raw/` is never edited by hand. Raw exports only.
- `data/processed/` is only ever produced by a script in `scripts/`.
- Every experiment gets one metadata file in `metadata/` before and after
  collection.
- Every Friday: write `docs/weekly_reports/week_NN_report.md`.

See `docs/setup_notes/` for environment details and
`docs/experiment_protocols/` for how each dataset was produced.
EOF

# Master log
cat > "$BASE/research_master_log.md" << 'EOF'
# SecLogTrace Master Log

Running index of what happened, when, and why. Append-only; newest entry on top.

---

## 2026-07-08 — Day 1: Workspace created
- Ran init_workspace.sh
- Folder tree created under this repo root
- Next: document system setup (Day 2), confirm Jaeger access (Day 3)
EOF

# Command log
touch "$BASE/docs/daily_logs/command_log.md"
echo "# Command Log" > "$BASE/docs/daily_logs/command_log.md"
echo "" >> "$BASE/docs/daily_logs/command_log.md"
echo "## $(date +%Y-%m-%d)" >> "$BASE/docs/daily_logs/command_log.md"
echo "- $0 $BASE" >> "$BASE/docs/daily_logs/command_log.md"

find "$BASE" -maxdepth 3 -type d | sort > "$BASE/docs/setup_notes/folder_tree_$(date +%Y%m%d).txt"

echo "Done. Folder tree:"
find "$BASE" -maxdepth 3 -type d | sort
