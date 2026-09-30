#!/usr/bin/env python3
"""Module 9 lab: object-level authorization.

Part 1 of this course established who is calling. Every mechanism in it can
work perfectly and still hand one customer another customer's booking, because
none of them ever looks at the object being asked for. This module is that
check.

Part A is an API with correct authentication and no ownership check. Part B
adds the check. Part C is the more interesting half: five ways the check is
present in the codebase and absent in effect. Part D is what an ownership
check does not decide.

Needs nothing beyond Python 3.

Exit codes: 0 all checks matched, 1 a check did not match.
"""
import sys

# ExampleAir's booking service. Company names are fictional. acct-77 is the
# caller in every request below; acct-91 is another customer.
BOOKINGS = {
    "bkg-1001": dict(owner="acct-77", route="DFW-LHR", invoice="inv-5001", status="confirmed"),
    "bkg-1002": dict(owner="acct-91", route="SFO-NRT", invoice="inv-5002", status="confirmed"),
    "bkg-1003": dict(owner="acct-77", route="DFW-AMS", invoice="inv-5003", status="confirmed"),
    "bkg-1004": dict(owner="acct-91", route="LHR-JFK", invoice="inv-5004", status="confirmed"),
    "bkg-1005": dict(owner="acct-12", route="AMS-SIN", invoice="inv-5005", status="confirmed"),
}
INVOICES = {
    "inv-5001": dict(owner="acct-77", total="420.00"),
    "inv-5002": dict(owner="acct-91", total="1180.00"),
    "inv-5003": dict(owner="acct-77", total="390.00"),
    "inv-5004": dict(owner="acct-91", total="770.00"),
    "inv-5005": dict(owner="acct-12", total="905.00"),
}

CALLER = "acct-77"          # authenticated correctly in every request below
RESULTS = []


def check(label, expected, actual):
    RESULTS.append((label, expected, actual))
    print("%2d. %-52s %s" % (len(RESULTS), label, actual))


def fresh():
    """A clean copy, so a cancellation in one check does not leak into another."""
    return {k: dict(v) for k, v in BOOKINGS.items()}


# ---------------------------------------------------------------- Part A and B

def get_booking(store, booking_id, caller=None):
    """caller=None is the version with no ownership check at all."""
    booking = store.get(booking_id)
    if booking is None:
        return "404 not found"
    if caller is not None and booking["owner"] != caller:
        # Hiding existence is a deliberate choice. Part D has the trade-off.
        return "404 not found"
    return "200 %s" % booking["route"]


def cancel_booking(store, booking_id, caller=None):
    booking = store.get(booking_id)
    if booking is None:
        return "404 not found"
    if caller is not None and booking["owner"] != caller:
        return "404 not found"
    booking["status"] = "cancelled"
    return "200 cancelled"


# ------------------------------------------------------------------- Part C

def get_trusting_owner(store, booking_id, caller, owner_param):
    """Trap 1: the owner comes from the request, so the caller picks it."""
    booking = store.get(booking_id)
    if booking is None:
        return "404 not found"
    if owner_param != caller:
        return "404 not found"
    return "200 %s" % booking["route"]


def list_bookings_unfiltered(store, caller):
    """Trap 2: the query returns everything and the client hides the rest."""
    return sorted(store)


def list_bookings_filtered(store, caller):
    return sorted(k for k, v in store.items() if v["owner"] == caller)


def get_invoice(store, invoice_id, caller=None):
    """Trap 3: the booking is checked, the object it points to is not."""
    invoice = INVOICES.get(invoice_id)
    if invoice is None:
        return "404 not found"
    if caller is not None and invoice["owner"] != caller:
        return "404 not found"
    return "200 %s" % invoice["total"]


def get_guarded_check(store, booking_id, caller):
    """Trap 4: the check is guarded by the thing it is checking.

    Written as "if caller and ...", so any path that reaches this handler
    without a caller skips the comparison instead of failing.
    """
    booking = store.get(booking_id)
    if booking is None:
        return "404 not found"
    if caller and booking["owner"] != caller:
        return "404 not found"
    return "200 %s" % booking["route"]


# ------------------------------------------------------------------- Part D

def get_strict(store, booking_id, caller):
    """The same handler with no guard: a missing caller can never match."""
    booking = store.get(booking_id)
    if booking is None:
        return "404 not found"
    if booking["owner"] != caller:
        return "404 not found"
    return "200 %s" % booking["route"]


def refund(store, booking_id, caller, role=None):
    """Ownership is settled here. Whether this caller may refund is not.

    role=None is the handler with no function-level check, which is module 10.
    """
    booking = store.get(booking_id)
    if booking is None or booking["owner"] != caller:
        return "404 not found"
    if role is not None and role != "staff":
        return "403 staff only"
    return "200 refunded"


def probe(store, booking_id, caller, hide_existence):
    """What the response tells an attacker about ids they do not own."""
    booking = store.get(booking_id)
    if booking is None:
        return "404 not found"
    if booking["owner"] != caller:
        return "404 not found" if hide_existence else "403 forbidden"
    return "200 %s" % booking["route"]


def main():
    print("caller: %s, authenticated correctly in every request below" % CALLER)
    print()
    print("Part A: authentication only. No ownership check anywhere.")

    store = fresh()
    check("reads its own booking", "200 DFW-LHR", get_booking(store, "bkg-1001"))
    check("reads another customer's booking", "200 SFO-NRT",
          get_booking(store, "bkg-1002"))
    check("cancels another customer's booking", "200 cancelled",
          cancel_booking(store, "bkg-1002"))

    print()
    print("Part B: the owner is read from the stored object and compared.")

    store = fresh()
    check("reads its own booking", "200 DFW-LHR",
          get_booking(store, "bkg-1001", CALLER))
    check("reads another customer's booking", "404 not found",
          get_booking(store, "bkg-1002", CALLER))
    check("cancels another customer's booking", "404 not found",
          cancel_booking(store, "bkg-1002", CALLER))
    check("the other booking is untouched", "confirmed", store["bkg-1002"]["status"])

    print()
    print("Part C: the check is in the code and absent in effect.")

    store = fresh()
    # 1. The owner is taken from the request instead of the object.
    check("owner read from the request, caller supplies its own",
          "200 SFO-NRT", get_trusting_owner(store, "bkg-1002", CALLER, CALLER))
    check("the same request, owner read from the object", "404 not found",
          get_booking(store, "bkg-1002", CALLER))

    # 2. The check is on the item endpoint and the list is filtered client-side.
    check("list endpoint, filtered in the client", "5 bookings returned",
          "%d bookings returned" % len(list_bookings_unfiltered(store, CALLER)))
    check("list endpoint, filtered in the query", "2 bookings returned",
          "%d bookings returned" % len(list_bookings_filtered(store, CALLER)))

    # 3. The booking is checked, the invoice it points to is not.
    check("invoice of another customer, no check on the invoice",
          "200 1180.00", get_invoice(store, "inv-5002"))
    check("the same invoice, checked in its own handler", "404 not found",
          get_invoice(store, "inv-5002", CALLER))

    # 4. The check is guarded by the value it is meant to check.
    check("a path that reaches the handler with no caller",
          "200 SFO-NRT", get_guarded_check(store, "bkg-1002", None))
    check("the same path, unguarded comparison", "404 not found",
          get_strict(store, "bkg-1002", None))

    # 5. Sequential identifiers make discovery a loop, not an exploit.
    found = [b for b in ("bkg-100%d" % n for n in range(1, 6))
             if get_booking(fresh(), b).startswith("200")]
    check("walking bkg-1001 to bkg-1005 with no check", "5 of 5 reachable",
          "%d of 5 reachable" % len(found))
    owned = [b for b in ("bkg-100%d" % n for n in range(1, 6))
             if get_booking(fresh(), b, CALLER).startswith("200")]
    check("the same walk with the check in place", "2 of 5 reachable",
          "%d of 5 reachable" % len(owned))

    print()
    print("Part D: what an ownership check does not decide.")

    store = fresh()
    check("the caller refunds a booking it owns", "200 refunded",
          refund(store, "bkg-1001", CALLER))
    check("the same request, with a function-level check", "403 staff only",
          refund(store, "bkg-1001", CALLER, role="customer"))
    # 403 tells the attacker the id exists. 404 does not.
    forbidden = probe(store, "bkg-1002", CALLER, hide_existence=False)
    absent = probe(store, "bkg-9999", CALLER, hide_existence=False)
    check("403 for an id that exists, 404 for one that does not",
          "existence disclosed", "existence disclosed" if forbidden != absent
          else "indistinguishable")
    hidden = probe(store, "bkg-1002", CALLER, hide_existence=True)
    absent = probe(store, "bkg-9999", CALLER, hide_existence=True)
    check("404 for both", "indistinguishable",
          "indistinguishable" if hidden == absent else "existence disclosed")

    failures = [r for r in RESULTS if r[2] != r[1]]
    print()
    if failures:
        print("%d check(s) did not match the expected outcome:" % len(failures))
        for label, expected, actual in failures:
            print("  %s: expected %s, got %s" % (label, expected, actual))
        return 1
    print("all lab checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
