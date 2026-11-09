#!/usr/bin/env python3
"""
scrub_scan.py - scan release-bound files for sensitive identifiers.

Reports every match with file, line, pattern name and the matched text, so a
sanitisation manifest records what was found and what was done about it. The
scanner never edits a file; it only reports. Deciding what to transform, and
recording that decision, stays a human step.

Patterns cover the categories named in the supervisor review: credentials and
tokens, research-server hostnames, internal IP addresses, VPN details,
absolute local paths, operator usernames and personal email addresses.

Usage:
    python3 scripts/preprocessing/scrub_scan.py \
        --root . \
        --out results/audit/sanitisation_findings.csv
"""
import argparse
import csv
import os
import re
import sys
from pathlib import Path

# Each entry: (name, compiled regex, why it matters).
PATTERNS = [
    ("private_ip_10",
     re.compile(r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),
     "RFC1918 10/8 address - may identify research network topology"),
    ("private_ip_192_168",
     re.compile(r"\b192\.168\.\d{1,3}\.\d{1,3}\b"),
     "RFC1918 192.168/16 address"),
    ("private_ip_172_16",
     re.compile(r"\b172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b"),
     "RFC1918 172.16/12 address"),
    ("public_ipv4",
     re.compile(r"\b(?!0\.)(?!10\.)(?!127\.)(?!169\.254\.)(?!192\.168\.)"
                r"(?!172\.(?:1[6-9]|2\d|3[01])\.)"
                r"(?:\d{1,3}\.){3}\d{1,3}\b"),
     "routable IPv4 literal - check it is not a real host"),
    ("windows_abs_path",
     re.compile(r"\b[A-Za-z]:[\\/](?:Users|home|phd_code)[\\/][^\s\"',)]*",
                re.IGNORECASE),
     "absolute Windows path - leaks the operator's directory layout"),
    ("unix_home_path",
     re.compile(r"/(?:home|Users)/[A-Za-z0-9._-]+(?:/[^\s\"',)]*)?"),
     "absolute POSIX home path - leaks a username"),
    ("email",
     re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
     "email address - confirm it is an intended contact address"),
    ("bearer_or_token",
     re.compile(r"(?i)\b(?:bearer\s+[A-Za-z0-9._~+/-]{12,}"
                r"|(?:api[_-]?key|secret|token|passwd|password)\s*[:=]\s*"
                r"[^\s\"',}]{6,})"),
     "credential or token literal"),
    ("private_key_block",
     re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
     "private key material"),
    ("aws_access_key",
     re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
     "AWS access key id"),
    ("jwt",
     re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
     "JSON web token"),
    ("vpn_reference",
     re.compile(r"(?i)\b(?:openvpn|wireguard|anyconnect|\.ovpn|vpn[_-]?(?:config|profile|gateway))\b"),
     "VPN configuration reference"),
    ("kube_context",
     re.compile(r"(?i)\b(?:kubeconfig|cluster-admin-token|service-account-token)\b"),
     "cluster credential reference"),
    ("university_host",
     re.compile(r"\b[A-Za-z0-9-]+\.(?:baylor|edu)\.?[A-Za-z]*\b", re.IGNORECASE),
     "institutional hostname - confirm it is not a research server"),
    # Bare internal hostnames carry no dot, so no generic pattern finds them.
    # List any deployment-specific internal hostnames here before scanning your
    # own tree; the names below are placeholders, not a real deployment.
    ("known_internal_host",
     re.compile(r"\b(?:ts-cluster|minikube-host)\b", re.IGNORECASE),
     "named research-server host - must not appear in the public artifact"),
]

# Author and institution names are NOT scrubbed for this venue. The MSR 2027
# Data and Tool Showcase is single-anonymous with the author block visible, so
# removing them would contradict the submission. Only infrastructure
# identifiers are a disclosure problem. This differs from the double-anonymous
# instructions in docs/DATA_AVAILABILITY_INSTRUCTIONS.md, which were written
# for a different venue.

# Benign literals that would otherwise flood the public_ipv4 and email reports.
ALLOW_SUBSTRINGS = (
    "0.0.0.0", "127.0.0.1", "255.255.255", "localhost",
    "evil.test",            # deliberate payload target, documented
    "example.com", "example.org",
    "apache.org", "creativecommons.org", "opentelemetry.io",
    "doi.org", "zenodo.org", "github.com",
)

SKIP_DIRS = {".git", ".venv", ".venv-clean", "__pycache__", "node_modules",
             ".idea", ".vscode", "review_package_anon"}
SKIP_SUFFIXES = {".pyc", ".pdf", ".png", ".jpg", ".jpeg", ".gif", ".zip",
                 ".tar", ".gz", ".tgz", ".whl", ".so", ".dll", ".docx", ".xlsx"}
MAX_BYTES = 64 * 1024 * 1024


def iter_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            p = Path(dirpath) / fn
            if p.suffix.lower() in SKIP_SUFFIXES:
                continue
            try:
                if p.stat().st_size > MAX_BYTES:
                    continue
            except OSError:
                continue
            yield p


def allowed(text: str) -> bool:
    return any(a in text for a in ALLOW_SUBSTRINGS)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".")
    ap.add_argument("--out", default="results/audit/sanitisation_findings.csv")
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args()

    root = Path(a.root).resolve()
    rows = []
    scanned = skipped = 0

    # The scanner's own source holds every pattern literal, and its output
    # holds every value it has ever matched. Scanning either reports the tool
    # rather than the corpus, so both are excluded by path.
    self_paths = {Path(__file__).resolve(), Path(a.out).resolve()}

    for path in iter_files(root):
        if path.resolve() in self_paths:
            skipped += 1
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="strict")
        except (UnicodeDecodeError, OSError):
            skipped += 1
            continue
        scanned += 1
        rel = path.relative_to(root).as_posix()
        for lineno, line in enumerate(text.splitlines(), 1):
            for name, rx, why in PATTERNS:
                for m in rx.finditer(line):
                    hit = m.group(0)
                    if allowed(hit) or allowed(line):
                        continue
                    rows.append({
                        "file": rel,
                        "line": lineno,
                        "pattern": name,
                        "match": hit[:200],
                        "why_it_matters": why,
                        "decision": "",      # filled in by hand
                        "transformation": "",
                    })

    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    cols = ["file", "line", "pattern", "match", "why_it_matters",
            "decision", "transformation"]
    with out.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)

    if not a.quiet:
        print("=" * 74)
        print("IDENTIFIER SCAN")
        print("=" * 74)
        print(f"  root            {root}")
        print(f"  files scanned   {scanned}")
        print(f"  files skipped   {skipped} (binary or unreadable)")
        print(f"  findings        {len(rows)}")
        print()
        by_pat = {}
        for r in rows:
            by_pat.setdefault(r["pattern"], []).append(r)
        if by_pat:
            print("  findings by pattern:")
            for name, group in sorted(by_pat.items(), key=lambda x: -len(x[1])):
                files = sorted({g["file"] for g in group})
                print(f"    {name:20s} {len(group):5d}  in {len(files)} file(s)")
            print()
            print("  distinct matched values by pattern:")
            for name, group in sorted(by_pat.items()):
                vals = sorted({g['match'] for g in group})
                print(f"    {name}:")
                for v in vals[:12]:
                    n = sum(1 for g in group if g['match'] == v)
                    print(f"      {v!r}  x{n}")
                if len(vals) > 12:
                    print(f"      ... {len(vals) - 12} more distinct values")
        else:
            print("  no findings")
        print()
        print(f"  wrote {out}")
        print("  Fill the decision and transformation columns before publishing.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
