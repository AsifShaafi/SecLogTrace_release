#!/usr/bin/env python3
"""
generate_baseline_traffic.py — repeatable normal-traffic generator for
SecLogTrace's Train-Ticket baseline (Week 1 Day 5/6, and reusable for the
"normal_load" scaling in Week 5).

**Extended 2026-08-20** to cover the endpoint inventory the 2026-08-18
coverage sweep found unscripted: assurance, food, consign, cancel, rebook,
execute (collect+check-in), and inside-payment. See `run_extended_flows()`
below and ts_client.py's "Extended flows" section for exactly what's
confirmed (paths, and two POST-body shapes, via
data/raw/session_data/session1/coverage_sweep.har) vs. inferred (response
field names — the HAR's response bodies were stripped in its sanitized
export). Run `--sessions 1` once and read the printed detail before
trusting a full collection built on these.

Design goals:
  - Real requests through the actual gateway (<research-host>:32677), not
    synthetic data — this generates real Jaeger traces.
  - Reproducible: every session and action is logged to a JSONL file with
    timestamps, so you can hand the exact start/end window to
    export_jaeger_traces.sh afterward and know what you're pulling.
  - Degrades gracefully: if the trip catalog is empty (checked via
    check_trip_catalog.py), it still runs realistic read-only browsing
    traffic (search, station/route lookups) rather than failing outright.
  - Human-like pacing: random short pauses between actions, varied station
    pairs and dates, mix of registered users vs. the demo account — avoids
    generating suspiciously uniform machine-gun traffic that wouldn't
    resemble real usage patterns in the resulting traces.

Usage:
    python3 generate_baseline_traffic.py --sessions 20
    python3 generate_baseline_traffic.py --sessions 50 --readonly-only
    python3 generate_baseline_traffic.py --sessions 10 --out-dir ../../data/raw/traffic
"""
import argparse
import itertools
import json
import random
import sys
import traceback
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from ts_client import (  # noqa: E402
    DEMO_USER, book_ticket, cancel_order, cancel_refund_preview,
    execute_ticket_collected, execute_ticket_execute, get_consign_by_order,
    get_consigns_by_account, get_or_create_contact, human_pause,
    list_assurance_types, list_foods, list_routes, list_stations, login,
    order_id_of, pay_inside, query_orders, rebook, rebook_preview,
    register_random_user, search_trips, trip_id_str,
)


class ActionLogger:
    def __init__(self, out_path: Path):
        self.out_path = out_path
        self.out_path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(self.out_path, "a", encoding="utf-8")
        self.window_start = datetime.now()
        self.window_end = self.window_start

    def log(self, session_id: str, action: str, ok: bool, detail: str = "", **extra) -> None:
        now = datetime.now()
        self.window_end = now
        record = {
            "timestamp": now.isoformat(),
            "session_id": session_id,
            "action": action,
            "ok": ok,
            "detail": detail,
            **extra,
        }
        self._fh.write(json.dumps(record) + "\n")
        self._fh.flush()
        status = "OK " if ok else "FAIL"
        print(f"[{status}] {session_id:>10} | {action:<28} | {detail}")

    def close(self):
        self._fh.close()


def get_station_pairs(n_pairs: int = 5) -> list[tuple[str, str]]:
    """Build station pairs from real route chains rather than random station
    combinations, so search queries are more likely to hit real trip data
    once the catalog is seeded."""
    routes = list_routes()
    pairs = set()
    for r in routes:
        stations = r.get("stations", [])
        for a, b in itertools.combinations(stations, 2):
            pairs.add((a, b))
    pairs = list(pairs)
    random.shuffle(pairs)
    return pairs[:n_pairs] if pairs else [("shanghai", "taiyuan")]


def run_session(session_id: str, logger: ActionLogger, station_pairs: list[tuple[str, str]],
                 readonly_only: bool, use_demo_user: bool, skip_extended_flows: bool) -> None:
    try:
        if use_demo_user:
            sess = login(DEMO_USER["username"], DEMO_USER["password"])
            logger.log(session_id, "login", True, f"user={DEMO_USER['username']} (demo)")
        else:
            sess = register_random_user()
            logger.log(session_id, "register+login", True, f"user={sess.username}")
    except Exception as e:
        logger.log(session_id, "login", False, str(e))
        return

    human_pause()

    # Browse stations / routes — always safe, always produces real traces.
    try:
        stations = list_stations()
        logger.log(session_id, "list_stations", True, f"count={len(stations)}")
    except Exception as e:
        logger.log(session_id, "list_stations", False, str(e))

    human_pause()

    try:
        routes = list_routes()
        logger.log(session_id, "list_routes", True, f"count={len(routes)}")
    except Exception as e:
        logger.log(session_id, "list_routes", False, str(e))

    human_pause()

    # Search a few station pairs with varied dates. Keep the first TWO
    # distinct trips found — the second is only used for rebook()'s
    # old-trip/new-trip pair below, so a session that books trip A can
    # plausibly rebook onto trip B rather than "rebooking" onto itself.
    found_trip = found_trip2 = None
    found_pair = found_pair2 = None
    found_date = found_date2 = None
    for start, end in station_pairs:
        offset = random.choice([-1, 0, 1, 2, 3, 7])
        date_str = (datetime.now() + timedelta(days=offset)).strftime("%Y-%m-%d 00:00:00")
        try:
            trips = search_trips(start, end, date_str)
            logger.log(session_id, "search_trips", True,
                       f"{start}->{end} @ {date_str}: {len(trips)} result(s)")
            if trips and not found_trip:
                found_trip, found_pair, found_date = trips[0], (start, end), date_str
            elif trips and not found_trip2 and trip_id_str(trips[0]) != trip_id_str(found_trip):
                found_trip2, found_pair2, found_date2 = trips[0], (start, end), date_str
        except Exception as e:
            logger.log(session_id, "search_trips", False, f"{start}->{end}: {e}")
        human_pause(0.3, 1.2)

    if readonly_only or not found_trip:
        if not found_trip:
            logger.log(session_id, "booking_skipped", True, "no trip data found in this session's searches")
        return

    # Booking flow — only reached if a real trip turned up.
    try:
        get_or_create_contact(sess)
        logger.log(session_id, "get_or_create_contact", True, f"contactsId={sess.contacts_id}")
    except Exception as e:
        logger.log(session_id, "get_or_create_contact", False, str(e))
        return

    human_pause()

    try:
        order = book_ticket(sess, found_trip, found_pair[0], found_pair[1], found_date)
        logger.log(session_id, "book_ticket", True, f"{found_pair[0]}->{found_pair[1]} @ {found_date}")
    except Exception as e:
        logger.log(session_id, "book_ticket", False, str(e))
        return

    human_pause()

    try:
        orders = query_orders(sess)
        logger.log(session_id, "query_orders", True, f"count={len(orders)}")
    except Exception as e:
        logger.log(session_id, "query_orders", False, str(e))
        orders = []

    if not skip_extended_flows:
        run_extended_flows(session_id, logger, sess, found_trip, found_pair, found_date,
                            found_trip2, found_pair2, found_date2, orders)


# ---------------------------------------------------------------------------
# Extended flows — assurance, food, consign, cancel, rebook, execute,
# inside-payment. Endpoint inventory from the 2026-08-18 coverage sweep
# (metadata/experiment_002_coverage_sweep.md); paths/POST-body shapes
# confirmed via that session's HAR capture (see ts_client.py's "Extended
# flows" section for exactly what is and isn't confirmed).
# ---------------------------------------------------------------------------

def run_extended_flows(session_id: str, logger: ActionLogger, sess, found_trip, found_pair,
                        found_date, found_trip2, found_pair2, found_date2, orders: list) -> None:
    # Browsing calls — always safe, no order/state dependency.
    try:
        types = list_assurance_types(sess)
        logger.log(session_id, "list_assurance_types", True, f"count={len(types)}")
    except Exception as e:
        logger.log(session_id, "list_assurance_types", False, str(e))

    human_pause(0.2, 0.8)

    try:
        food_date = found_date.split(" ")[0]  # foodservice wants 'YYYY-MM-DD', no time
        foods = list_foods(food_date, found_pair[0], found_pair[1], trip_id_str(found_trip), sess)
        logger.log(session_id, "list_foods", True,
                    f"{found_pair[0]}->{found_pair[1]} @ {food_date}: {len(foods)} option(s)")
    except Exception as e:
        logger.log(session_id, "list_foods", False, str(e))

    human_pause(0.2, 0.8)

    try:
        consigns = get_consigns_by_account(sess)
        logger.log(session_id, "get_consigns_by_account", True, f"count={len(consigns)}")
    except Exception as e:
        logger.log(session_id, "get_consigns_by_account", False, str(e))

    if not orders:
        return
    # Heuristic: the order this session just booked is most likely the last
    # entry for a freshly-registered user (whose order list contains only
    # this one order) and PROBABLY the most recent for the shared demo user
    # (whose list accumulates across sessions) — unconfirmed ordering, see
    # order_id_of()'s docstring in ts_client.py.
    order_id = order_id_of(orders[-1])
    if not order_id:
        logger.log(session_id, "extended_flows_skipped", True,
                    "could not extract an order id from query_orders() output")
        return

    human_pause(0.2, 0.8)

    try:
        get_consign_by_order(sess, order_id)
        logger.log(session_id, "get_consign_by_order", True, f"orderId={order_id}")
    except Exception as e:
        logger.log(session_id, "get_consign_by_order", False, str(e))

    # Exactly one mutating post-booking action per session, mirroring how a
    # real user would do at most one of pay/rebook/cancel to a given order
    # rather than chaining all three into invalid state transitions. Weighted
    # so most sessions leave the order untouched, like real usage.
    human_pause()
    action = random.choices(
        ["none", "pay_and_execute", "rebook", "cancel"],
        weights=[40, 20, 20, 20], k=1,
    )[0]

    if action == "pay_and_execute":
        try:
            pay_inside(sess, order_id, trip_id_str(found_trip))
            logger.log(session_id, "pay_inside", True, f"orderId={order_id}")
        except Exception as e:
            logger.log(session_id, "pay_inside", False, str(e))
            return
        human_pause(0.2, 0.8)
        try:
            execute_ticket_collected(sess, order_id)
            logger.log(session_id, "execute_ticket_collected", True, f"orderId={order_id}")
        except Exception as e:
            logger.log(session_id, "execute_ticket_collected", False, str(e))
        human_pause(0.2, 0.8)
        try:
            execute_ticket_execute(sess, order_id)
            logger.log(session_id, "execute_ticket_execute", True, f"orderId={order_id}")
        except Exception as e:
            logger.log(session_id, "execute_ticket_execute", False, str(e))

    elif action == "rebook" and found_trip2:
        rebook_date = found_date.split(" ")[0]
        old_tid, new_tid = trip_id_str(found_trip), trip_id_str(found_trip2)
        try:
            rebook_preview(sess, order_id, old_tid, new_tid, 2, rebook_date)
            logger.log(session_id, "rebook_preview", True, f"orderId={order_id} {old_tid}->{new_tid}")
        except Exception as e:
            logger.log(session_id, "rebook_preview", False, str(e))
        human_pause(0.2, 0.8)
        try:
            rebook(sess, order_id, old_tid, new_tid, 2, rebook_date)
            logger.log(session_id, "rebook", True, f"orderId={order_id} {old_tid}->{new_tid}")
        except Exception as e:
            logger.log(session_id, "rebook", False, str(e))

    elif action == "cancel":
        try:
            cancel_refund_preview(sess, order_id)
            logger.log(session_id, "cancel_refund_preview", True, f"orderId={order_id}")
        except Exception as e:
            logger.log(session_id, "cancel_refund_preview", False, str(e))
        human_pause(0.2, 0.8)
        try:
            cancel_order(sess, order_id)
            logger.log(session_id, "cancel_order", True, f"orderId={order_id}")
        except Exception as e:
            logger.log(session_id, "cancel_order", False, str(e))

    else:
        logger.log(session_id, "extended_flows_action", True, f"action={action} (no-op or no 2nd trip available)")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sessions", type=int, default=10, help="number of simulated user sessions")
    ap.add_argument("--readonly-only", action="store_true",
                     help="only browse (search/list) — skip booking even if trip data is found")
    ap.add_argument("--out-dir", type=str, default=".",
                     help="directory for the session log (e.g. ../../data/raw/traffic)")
    ap.add_argument("--demo-user-ratio", type=float, default=0.3,
                     help="fraction of sessions that reuse the demo account instead of registering fresh")
    ap.add_argument("--skip-extended-flows", action="store_true",
                     help="skip assurance/food/consign/cancel/rebook/execute/inside-payment "
                          "after booking — these use endpoints whose response schemas are "
                          "unconfirmed (see ts_client.py); use this if a real run behaves "
                          "unexpectedly and you want to isolate the core booking flow")
    args = ap.parse_args()

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = Path(args.out_dir) / f"traffic_session_log_{ts}.jsonl"
    logger = ActionLogger(out_path)

    print(f"Generating traffic: {args.sessions} sessions, readonly_only={args.readonly_only}")
    print(f"Logging to: {out_path}\n")

    station_pairs = get_station_pairs(n_pairs=6)
    print(f"Using station pairs: {station_pairs}\n")

    for i in range(args.sessions):
        session_id = f"sess_{i:04d}"
        use_demo = random.random() < args.demo_user_ratio
        run_session(session_id, logger, station_pairs, args.readonly_only, use_demo,
                    args.skip_extended_flows)
        human_pause(0.5, 2.5)

    logger.close()

    print("\nDone.")
    print(f"Window start: {logger.window_start.isoformat()}")
    print(f"Window end:   {logger.window_end.isoformat()}")
    duration_s = int((logger.window_end - logger.window_start).total_seconds())
    lookback = f"{max(duration_s // 60 + 2, 5)}m"
    print(f"Suggested export_jaeger_traces.sh lookback: {lookback}")
    print(f"Session log saved to: {out_path}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.")
    except Exception:
        traceback.print_exc()
