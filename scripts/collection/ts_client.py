"""
ts_client.py — Train-Ticket API client for SecLogTrace traffic generation.

Built from:
  - merged_openapi_spec.yaml (203 endpoints across 37 services, provided by user)
  - Endpoints/creds confirmed empirically via browser (2026-07-24 session):
      base path quirks, demo credentials, station/route data quality
  - Gateway NodePort: http://<research-host>:32677

This module wraps the confirmed booking-flow endpoints as plain Python
functions. It does NOT decide when trip data is available — that's checked
by scripts/collection/check_trip_catalog.py before running any traffic.
"""
from __future__ import annotations

import random
import string
import time
from dataclasses import dataclass, field
from typing import Any, Optional

import requests

GATEWAY = "http://<research-host>:32677"
DEFAULT_TIMEOUT = 10

# Demo credentials confirmed working 2026-07-24.
DEMO_USER = {"username": "fdse_microservice", "password": "111111"}
DEMO_ADMIN = {"username": "admin", "password": "222222"}

# Known-good station/route chains, pulled from GET /api/v1/routeservice/routes
# on 2026-07-24. Avoid the junk station entries present in this deployment's
# station table (e.g. "empirestatebuilding", "12345678901") — those are
# leftover test data, not real seed stations.
KNOWN_ROUTE_CHAINS = [
    ["shanghai", "nanjing", "shijiazhuang", "taiyuan"],
    ["nanjing", "xuzhou", "jinan"],  # confirm remaining stations via /routeservice/routes if used
]


class TrainTicketError(RuntimeError):
    pass


@dataclass
class Session:
    """One simulated user's session state."""
    username: str
    password: str
    token: Optional[str] = None
    account_id: Optional[str] = None
    contacts_id: Optional[str] = None
    session: requests.Session = field(default_factory=requests.Session)

    def auth_header(self) -> dict:
        return {"Authorization": f"Bearer {self.token}"} if self.token else {}


def _post(path: str, body: dict, sess: Optional[Session] = None, timeout: int = DEFAULT_TIMEOUT) -> dict:
    headers = {"Content-Type": "application/json"}
    s = sess.session if sess else requests
    if sess:
        headers.update(sess.auth_header())
    resp = s.post(f"{GATEWAY}{path}", json=body, headers=headers, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


def _get(path: str, sess: Optional[Session] = None, timeout: int = DEFAULT_TIMEOUT) -> dict:
    headers = {}
    s = sess.session if sess else requests
    if sess:
        headers.update(sess.auth_header())
    resp = s.get(f"{GATEWAY}{path}", headers=headers, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

def login(username: str, password: str) -> Session:
    """POST /api/v1/users/login — confirmed working 2026-07-24."""
    sess = Session(username=username, password=password)
    data = _post("/api/v1/users/login", {"username": username, "password": password}, sess)
    if data.get("status") != 1:
        raise TrainTicketError(f"Login failed for {username}: {data.get('msg')}")
    sess.token = data["data"]["token"]
    sess.account_id = data["data"]["userId"]
    return sess


def register_random_user() -> Session:
    """POST /api/v1/userservice/users/register — creates a fresh normal user
    so traffic isn't all funneled through one demo account."""
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    username = f"seclog_{suffix}"
    password = "Passw0rd!"
    body = {
        "userName": username,
        "password": password,
        "gender": random.choice([0, 1]),
        "documentType": 1,
        "documentNum": "".join(random.choices(string.digits, k=18)),
        "email": f"{username}@example.test",
    }
    resp = requests.post(f"{GATEWAY}/api/v1/userservice/users/register", json=body, timeout=DEFAULT_TIMEOUT)
    resp.raise_for_status()
    data = resp.json()
    if data.get("status") not in (1, 0):  # some deployments return 0 with a valid message on success
        raise TrainTicketError(f"Register failed: {data}")
    return login(username, password)


# ---------------------------------------------------------------------------
# Read-only / browsing endpoints — safe to call even if the trip catalog
# is empty. Use these for baseline traffic while that's unresolved.
# ---------------------------------------------------------------------------

def list_stations() -> list[dict]:
    return _get("/api/v1/stationservice/stations").get("data", [])


def list_routes() -> list[dict]:
    return _get("/api/v1/routeservice/routes").get("data", [])


def search_trips(start_place: str, end_place: str, date_str: str) -> list[dict]:
    """Searches BOTH trip endpoints and merges results.

    Train-Ticket splits high-speed trains (G/D prefix) into
    ts-travel-service (POST /api/v1/travelservice/trips/left) from
    everything else (Z/T/K prefix, e.g. ZhiDa/TeKuai/KuaiSu) which lives in
    ts-travel2-service (POST /api/v1/travel2service/trips/left). Querying
    only the first endpoint silently misses an entire class of trips —
    confirmed 2026-07-28 when Z1310/K1311 only showed up via travel2service.

    date_str format: 'YYYY-MM-DD 00:00:00'
    """
    body = {"startPlace": start_place, "endPlace": end_place, "departureTime": date_str}
    results = []
    for path in ("/api/v1/travelservice/trips/left", "/api/v1/travel2service/trips/left"):
        try:
            data = _post(path, body)
            results.extend(data.get("data", []))
        except Exception:
            # one endpoint being down/empty shouldn't block the other
            continue
    return results


# ---------------------------------------------------------------------------
# Booking flow — requires the trip catalog to actually contain trips.
# Schemas confirmed from merged_openapi_spec.yaml components:
#   ts-contacts-service_Contacts, ts-preserve-service_OrderTicketsInfo,
#   ts-order-other-service_QueryInfo
# ---------------------------------------------------------------------------

def get_or_create_contact(sess: Session) -> str:
    """GET existing contacts for the account; create one if none exist."""
    existing = _get(f"/api/v1/contactservice/contacts/account/{sess.account_id}", sess)
    contacts = existing.get("data") or []
    if contacts:
        sess.contacts_id = contacts[0]["id"]
        return sess.contacts_id

    body = {
        "accountId": sess.account_id,
        "name": f"Contact_{sess.username}",
        "documentType": 1,
        "documentNumber": "".join(random.choices(string.digits, k=18)),
        "phoneNumber": "".join(random.choices(string.digits, k=11)),
    }
    created = _post("/api/v1/contactservice/contacts", body, sess)
    sess.contacts_id = created["data"]["id"]
    return sess.contacts_id


def trip_id_str(trip: dict) -> str:
    """trips/left returns tripId as {"type": "G", "number": "1307"} (confirmed
    2026-07-28) — downstream endpoints (preserveservice, foodservice,
    rebookservice) expect the flat combined string "G1307"."""
    tid = trip.get("tripId")
    if isinstance(tid, dict):
        return f"{tid.get('type', '')}{tid.get('number', '')}"
    return tid or trip.get("id")


def order_id_of(order: dict) -> Optional[str]:
    """Order-id extraction from a query_orders() element. "id" confirmed
    live 2026-08-20 across three separate fresh bookings (the coverage-sweep
    HAR's response bodies were all stripped, so this couldn't be confirmed
    from it — see the "Extended flows" section below); "orderId" kept as a
    fallback in case a differently-configured deployment varies."""
    return order.get("id") or order.get("orderId")


def book_ticket(sess: Session, trip: dict, from_station: str, to_station: str,
                travel_date: str, seat_type: int = 2) -> dict:
    """POST /api/v1/preserveservice/preserve
    trip: one element from search_trips() results.
    """
    if not sess.contacts_id:
        get_or_create_contact(sess)

    body = {
        "accountId": sess.account_id,
        "contactsId": sess.contacts_id,
        "tripId": trip_id_str(trip),
        "seatType": seat_type,
        "date": travel_date,
        "from": from_station,
        "to": to_station,
        "assurance": 0,
        "foodType": 0,
        "stationName": "",
        "storeName": "",
        "loginToken": sess.token,
        "within": False,
    }
    return _post("/api/v1/preserveservice/preserve", body, sess)


# ---------------------------------------------------------------------------
# Extended flows (assurance, food, consign, cancel, rebook, execute,
# inside-payment) — added 2026-08-20 to close the gap the 2026-08-18
# coverage sweep found: these services are real endpoint surface exercised
# in a hand-clicked session but never scripted. Paths and (for the two POST
# bodies) request-body shapes below are CONFIRMED against real traffic in
# data/raw/session_data/session1/coverage_sweep.har. Response schemas are
# NOT confirmed by the HAR — its sanitized export stripped every API
# response body (only static assets like images/JS kept theirs). Every
# function below was instead live-verified directly against the real
# gateway on 2026-08-20 (one --sessions 1 run plus two targeted follow-up
# calls covering the pay/execute and cancel paths it didn't happen to
# trigger) and returned `status: 1` (success). That run is also how the
# per-function notes below (auth requirement, null `data` on empty results,
# order_id_of()'s "id" field guess) were confirmed correct rather than
# guessed. The one open anomaly: rebook_preview() (POST .../rebook/
# difference) returned HTTP 500 even though rebook() itself — same body
# shape, sibling endpoint — succeeded immediately after. Not chased further;
# may be a real backend quirk rather than a client-side bug, since the
# request body matches the HAR exactly.
# ---------------------------------------------------------------------------

def list_assurance_types(sess: Optional[Session] = None) -> list[dict]:
    """GET /api/v1/assuranceservice/assurances/types — path confirmed via
    HAR. Live-verified 2026-08-20: returns 403 without an auth header
    (unlike list_stations/list_routes, which are unauthenticated) — pass a
    logged-in `sess`."""
    return _get("/api/v1/assuranceservice/assurances/types", sess).get("data") or []


def list_foods(date_str: str, from_station: str, to_station: str, trip_id: str,
                sess: Optional[Session] = None) -> list[dict]:
    """GET /api/v1/foodservice/foods/{date}/{from}/{to}/{tripId} — path
    confirmed via HAR (.../foods/2026-08-20/shanghai/suzhou/D1345).
    date_str format: 'YYYY-MM-DD' (no time component, unlike search_trips'
    date_str — confirmed distinctly via the same HAR capture). Live-verified
    2026-08-20: `data` comes back JSON null (not `[]`) when there are no
    food options for that trip — use `.get("data") or []`, not
    `.get("data", [])`, or a null response silently crashes the caller."""
    path = f"/api/v1/foodservice/foods/{date_str}/{from_station}/{to_station}/{trip_id}"
    return _get(path, sess).get("data") or []


def get_consigns_by_account(sess: Session) -> list[dict]:
    """GET /api/v1/consignservice/consigns/account/{accountId} — path
    confirmed via HAR. Live-verified 2026-08-20: `data` is JSON null (not
    `[]`) for an account with no consigns — same null-vs-empty-list trap as
    list_foods() above."""
    return _get(f"/api/v1/consignservice/consigns/account/{sess.account_id}", sess).get("data") or []


def get_consign_by_order(sess: Session, order_id: str) -> dict:
    """GET /api/v1/consignservice/consigns/order/{orderId} — path confirmed via HAR."""
    return _get(f"/api/v1/consignservice/consigns/order/{order_id}", sess)


def cancel_refund_preview(sess: Session, order_id: str) -> dict:
    """GET /api/v1/cancelservice/cancel/refound/{orderId} — path confirmed
    via HAR. Note "refound", not "refund" — that's this deployment's actual
    route spelling, not a typo introduced here. Live-verified 2026-08-20:
    {"status": 1, "msg": "Success. Refoud 0", "data": "0"} on a fresh unpaid
    order (their spelling, not this codebase's)."""
    return _get(f"/api/v1/cancelservice/cancel/refound/{order_id}", sess)


def cancel_order(sess: Session, order_id: str) -> dict:
    """GET /api/v1/cancelservice/cancel/{orderId}/{loginId} — path confirmed
    via HAR. This is a GET that performs the actual cancellation (not just a
    preview) on this deployment — mutates order state. Live-verified
    2026-08-20: {"status": 1, "msg": "Success.", ...} on a fresh unpaid
    order."""
    return _get(f"/api/v1/cancelservice/cancel/{order_id}/{sess.account_id}", sess)


def rebook_preview(sess: Session, order_id: str, old_trip_id: str, new_trip_id: str,
                    seat_type: int, date_str: str) -> dict:
    """POST /api/v1/rebookservice/rebook/difference — request body confirmed
    via HAR (same shape as rebook() below). date_str format: 'YYYY-MM-DD'."""
    body = {"orderId": order_id, "oldTripId": old_trip_id, "tripId": new_trip_id,
            "seatType": seat_type, "date": date_str}
    return _post("/api/v1/rebookservice/rebook/difference", body, sess)


def rebook(sess: Session, order_id: str, old_trip_id: str, new_trip_id: str,
           seat_type: int, date_str: str) -> dict:
    """POST /api/v1/rebookservice/rebook — request body confirmed via HAR:
    {"orderId":...,"oldTripId":...,"tripId":...,"seatType":2,"date":"YYYY-MM-DD"}.
    Mutates the order's trip — a real state change, not read-only."""
    body = {"orderId": order_id, "oldTripId": old_trip_id, "tripId": new_trip_id,
            "seatType": seat_type, "date": date_str}
    return _post("/api/v1/rebookservice/rebook", body, sess)


def execute_ticket_collected(sess: Session, order_id: str) -> dict:
    """GET /api/v1/executeservice/execute/collected/{orderId} — path
    confirmed via HAR. Ticket-collection query/action. Live-verified
    2026-08-20 on a just-paid order: {"status": 1, "msg": "Success", "data": null}."""
    return _get(f"/api/v1/executeservice/execute/collected/{order_id}", sess)


def execute_ticket_execute(sess: Session, order_id: str) -> dict:
    """GET /api/v1/executeservice/execute/execute/{orderId} — path confirmed
    via HAR. Check-in query/action. Live-verified 2026-08-20:
    {"status": 1, "msg": "Success.", "data": null}."""
    return _get(f"/api/v1/executeservice/execute/execute/{order_id}", sess)


def pay_inside(sess: Session, order_id: str, trip_id: str) -> dict:
    """POST /api/v1/inside_pay_service/inside_payment — request body
    confirmed via HAR: {"orderId":...,"tripId":...,"userId":...}.
    Live-verified 2026-08-20 on a fresh order:
    {"status": 1, "msg": "Payment Success Pay Success", "data": null}."""
    body = {"orderId": order_id, "tripId": trip_id, "userId": sess.account_id}
    return _post("/api/v1/inside_pay_service/inside_payment", body, sess)


def query_orders(sess: Session, enable_travel_date_query: bool = False) -> list[dict]:
    """POST /api/v1/orderservice/order/query"""
    body = {
        "loginId": sess.account_id,
        "enableStateQuery": False,
        "enableTravelDateQuery": enable_travel_date_query,
        "enableBoughtDateQuery": False,
        "state": 0,
    }
    data = _post("/api/v1/orderservice/order/query", body, sess)
    return data.get("data", [])


def human_pause(min_s: float = 0.4, max_s: float = 2.0) -> None:
    """Sleep a random short interval to avoid machine-gun request patterns
    that would look nothing like real user browsing in the resulting traces."""
    time.sleep(random.uniform(min_s, max_s))
