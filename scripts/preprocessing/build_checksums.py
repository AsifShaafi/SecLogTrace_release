#!/usr/bin/env python3
"""
build_checksums.py - emit a SHA-256 manifest for the release-bound files.

A reviewer who downloads the archive needs a way to confirm the bytes match
what the paper was computed against. This writes one line per file so that
check can be mechanical rather than a matter of trust.

The manifest is sorted by path and uses forward slashes, so it is identical on
Windows and POSIX and diffs cleanly between releases.

Verify a manifest later with:
    sha256sum -c CHECKSUMS.sha256          # POSIX
    python3 scripts/preprocessing/build_checksums.py --verify CHECKSUMS.sha256

Usage:
    python3 scripts/preprocessing/build_checksums.py \
        --root . --out CHECKSUMS.sha256
"""
import argparse
import hashlib
import os
import sys
from pathlib import Path

# Directories that never ship. review_package_anon is a superseded September
# snapshot; see ARTIFACT_README.md.
SKIP_DIRS = {".git", ".venv", ".venv-clean", "__pycache__", "node_modules",
             ".idea", ".vscode", "review_package_anon",
             "manuscript", "external", "fork_ts-avatar-service"}
SKIP_NAMES = {"CHECKSUMS.sha256", ".DS_Store", "Thumbs.db"}
SKIP_SUFFIXES = {".pyc", ".pyo", ".aux", ".fls", ".fdb_latexmk", ".out",
                 ".synctex.gz"}

CHUNK = 1 << 20


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(CHUNK), b""):
            h.update(block)
    return h.hexdigest()


def iter_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for fn in sorted(filenames):
            if fn in SKIP_NAMES or Path(fn).suffix.lower() in SKIP_SUFFIXES:
                continue
            yield Path(dirpath) / fn


def build(root: Path, out: Path) -> int:
    rows, total = [], 0
    for p in iter_files(root):
        rel = p.relative_to(root).as_posix()
        rows.append((sha256_file(p), rel))
        total += p.stat().st_size
    rows.sort(key=lambda r: r[1])
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8", newline="\n") as fh:
        for digest, rel in rows:
            fh.write(f"{digest}  {rel}\n")
    print(f"  files    {len(rows)}")
    print(f"  bytes    {total:,}")
    print(f"  wrote    {out}")
    return 0


def verify(root: Path, manifest: Path) -> int:
    bad = missing = ok = 0
    for line in manifest.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        digest, rel = line.split("  ", 1)
        p = root / rel
        if not p.is_file():
            print(f"  MISSING  {rel}")
            missing += 1
        elif sha256_file(p) != digest:
            print(f"  CHANGED  {rel}")
            bad += 1
        else:
            ok += 1
    print(f"\n  ok={ok}  changed={bad}  missing={missing}")
    return 0 if (bad == 0 and missing == 0) else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".")
    ap.add_argument("--out", default="CHECKSUMS.sha256")
    ap.add_argument("--verify", metavar="MANIFEST",
                    help="check an existing manifest instead of writing one")
    a = ap.parse_args()
    root = Path(a.root).resolve()
    if a.verify:
        return verify(root, Path(a.verify))
    return build(root, Path(a.out))


if __name__ == "__main__":
    sys.exit(main())
