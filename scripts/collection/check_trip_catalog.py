#!/usr/bin/env python3
"""
check_trip_catalog.py — sweep station pairs + dates to see whether the
Train-Ticket trip catalog (ts-travel-service / ts-travel2-service) actually
has any bookable trips seeded.

Run this BEFORE generate_baseline_traffic.py. If it finds zero trips across
the sweep, the booking flow will not produce data yet — the trip catalog
needs seeding via the admin panel (Trip Management / admintravelservice)
first. Read-only traffic (search, station/route browsing) still works and
still generates real traces either way.

Usage:
    python3 check_trip_catalog.py
"""
import itertools
import sys
from datetime import datetime, timedelta

sys.path.insert(0, ".")
from ts_client import list_routes, search_trips  # noqa: E402


def all_route_stations() -> list[str]:
    routes = list_routes()
    stations = set()
    for r in routes:
        for s in r.get("stations", []):
            stations.add(s)
    return sorted(stations)


def main() -> None:
    print("Fetching route/station config...")
    stations = all_route_stations()
    print(f"Found {len(stations)} distinct stations across {len(stations)} route entries.")
    if not stations:
        print("No route/station data at all — check ts-routeservice directly.")
        return

    today = datetime.now()
    date_offsets = [-3, -1, 0, 1, 3, 7, 14, 30]
    pairs_tried = 0
    hits = []

    # Try a handful of station pairs (not all combinations — routeservice
    # data defines valid chains; pairs within the same chain are most likely
    # to be valid trip endpoints).
    sample_pairs = list(itertools.combinations(stations[:8], 2))[:15]

    for start, end in sample_pairs:
        for offset in date_offsets:
            date_str = (today + timedelta(days=offset)).strftime("%Y-%m-%d 00:00:00")
            pairs_tried += 1
            try:
                trips = search_trips(start, end, date_str)
            except Exception as e:
                print(f"  ERROR {start} -> {end} @ {date_str}: {e}")
                continue
            if trips:
                hits.append((start, end, date_str, len(trips)))
                print(f"  HIT: {start} -> {end} @ {date_str}: {len(trips)} trip(s)")

    print(f"\nChecked {pairs_tried} (station-pair, date) combinations.")
    if hits:
        print(f"{len(hits)} combination(s) returned trips. Booking flow can proceed.")
        print("Use one of these confirmed-good combinations in generate_baseline_traffic.py.")
    else:
        print("Zero trips found across the entire sweep.")
        print("The trip catalog is very likely unseeded. Before running the booking")
        print("flow, seed trips via the admin panel (Trip Management) or the")
        print("admintravelservice API, then re-run this check.")
        print("Read-only traffic (search calls, station/route browsing) still")
        print("produces real traces and can be run now via --readonly-only mode.")


if __name__ == "__main__":
    main()
