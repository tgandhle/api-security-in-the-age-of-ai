#!/usr/bin/env python3
"""Module 10 lab: property and function authorization.

Module 9 settled which objects a caller may reach. This module is the two
questions that remain about each one: which of its properties they may read
and write, and which operations they may invoke at all.

Part A is the read side, an endpoint that serialises the whole record. Part B
is the write side, an endpoint that merges the request body into it. Part C is
function-level authorization, where the route table is the control and the
path prefix is the mistake. Part D is what none of this settles.

Needs nothing beyond Python 3.

Exit codes: 0 all checks matched, 1 a check did not match.
"""
import sys

# ExampleAir customer profiles. Company names are fictional and no real
# personal data appears here.
def seed():
    return {
        "acct-77": dict(owner="acct-77", display_name="T. Okafor",
                        email="t.okafor@mail.example", phone="+1-555-0100",
                        loyalty_tier="silver", points=12400,
                        fraud_score=17, internal_notes="manual review 2025-11",
                        is_staff=False, referred_by="acct-12"),
        "acct-91": dict(owner="acct-91", display_name="R. Blum",
                        email="r.blum@mail.example", phone="+1-555-0111",
                        loyalty_tier="gold", points=88100,
                        fraud_score=4, internal_notes="",
                        is_staff=False, referred_by=None),
    }


# What a customer may see, and what a customer may set. Two different lists,
# because readable and writable are two different questions.
READABLE = ("display_name", "email", "phone", "loyalty_tier", "points")
WRITABLE = ("display_name", "email", "phone")

CALLER = "acct-77"
RESULTS = []


def check(label, expected, actual):
    RESULTS.append((label, expected, actual))
    print("%2d. %-50s %s" % (len(RESULTS), label, actual))


# ------------------------------------------------------------------ Part A

def serialize_all(record):
    """What to_json() on the model gives you."""
    return sorted(record)


def serialize_allowed(record):
    """An explicit list of what leaves the service."""
    return sorted(f for f in record if f in READABLE)


# ------------------------------------------------------------------ Part B

def update_merge(record, body):
    """What binding the request body to the model gives you."""
    record.update(body)
    return "200 updated"


def update_allowed(record, body):
    """Only the properties the client is allowed to set."""
    ignored = sorted(k for k in body if k not in WRITABLE)
    for key, value in body.items():
        if key in WRITABLE:
            record[key] = value
    return "200 updated, ignored %s" % (ignored if ignored else "nothing")


# ------------------------------------------------------------------ Part C

ROUTES = {
    ("GET", "/api/profile"): ("customer", "staff"),
    ("PATCH", "/api/profile"): ("customer", "staff"),
    ("DELETE", "/api/profile"): ("staff",),
    ("GET", "/api/admin/reports"): ("staff",),
    ("POST", "/api/users/promote"): ("staff",),
}


def dispatch_by_prefix(method, path, role):
    """The common mistake: administrative means whatever lives under /admin."""
    if path.startswith("/api/admin/") and role != "staff":
        return "403 forbidden"
    return "200 ok"


def dispatch_by_table(method, path, role, table=None):
    """Deny by default. A route with no rule is refused, not allowed."""
    allowed = (ROUTES if table is None else table).get((method, path))
    if allowed is None:
        return "403 no rule for this route"
    if role not in allowed:
        return "403 forbidden"
    return "200 ok"


def main():
    print("caller: %s, role customer, authenticated and authorized for its own" % CALLER)
    print("        profile object. Module 9's check passes on every request below except check 22.")
    print()
    print("Part A: which properties leave the service.")

    profiles = seed()
    everything = serialize_all(profiles[CALLER])
    check("fields returned by the whole-record serializer", "10 fields",
          "%d fields" % len(everything))
    check("fraud_score in that response", "present",
          "present" if "fraud_score" in everything else "absent")
    allowed = serialize_allowed(profiles[CALLER])
    check("fields returned by the allowlist", "5 fields", "%d fields" % len(allowed))
    check("fraud_score in that response", "absent",
          "present" if "fraud_score" in allowed else "absent")
    check("internal_notes and is_staff in that response", "absent",
          "present" if {"internal_notes", "is_staff"} & set(allowed) else "absent")

    print()
    print("Part B: which properties the client may set.")

    body = {"email": "new@mail.example", "loyalty_tier": "platinum",
            "points": 999999, "is_staff": True, "fraud_score": 0}
    profiles = seed()
    update_merge(profiles[CALLER], body)
    check("after a merge, loyalty_tier", "platinum", profiles[CALLER]["loyalty_tier"])
    check("after a merge, points", "999999", str(profiles[CALLER]["points"]))
    check("after a merge, is_staff", "True", str(profiles[CALLER]["is_staff"]))
    check("after a merge, fraud_score", "0", str(profiles[CALLER]["fraud_score"]))

    profiles = seed()
    result = update_allowed(profiles[CALLER], body)
    check("the same body against the writable list",
          "200 updated, ignored "
          "['fraud_score', 'is_staff', 'loyalty_tier', 'points']", result)
    check("email did change", "new@mail.example", profiles[CALLER]["email"])
    check("loyalty_tier did not", "silver", profiles[CALLER]["loyalty_tier"])
    check("is_staff did not", "False", str(profiles[CALLER]["is_staff"]))

    print()
    print("Part C: which functions the caller may invoke.")

    check("customer, GET /api/admin/reports, prefix rule", "403 forbidden",
          dispatch_by_prefix("GET", "/api/admin/reports", "customer"))
    check("customer, POST /api/users/promote, prefix rule", "200 ok",
          dispatch_by_prefix("POST", "/api/users/promote", "customer"))
    check("the same request, route table", "403 forbidden",
          dispatch_by_table("POST", "/api/users/promote", "customer"))
    check("customer, DELETE /api/profile, prefix rule", "200 ok",
          dispatch_by_prefix("DELETE", "/api/profile", "customer"))
    check("the same request, route table", "403 forbidden",
          dispatch_by_table("DELETE", "/api/profile", "customer"))
    check("customer, GET /api/internal/export, prefix rule", "200 ok",
          dispatch_by_prefix("GET", "/api/internal/export", "customer"))
    check("the same request, route table", "403 no rule for this route",
          dispatch_by_table("GET", "/api/internal/export", "customer"))
    check("staff, POST /api/users/promote, route table", "200 ok",
          dispatch_by_table("POST", "/api/users/promote", "staff"))

    print()
    print("Part D: what property and function checks do not settle.")

    # The writable list is per property, not per object. It has no opinion
    # about whose record this is: that was module 9.
    profiles = seed()
    update_allowed(profiles["acct-91"], {"email": "attacker@mail.example"})
    check("an allowed property, on another customer's record",
          "attacker@mail.example", profiles["acct-91"]["email"])
    owner_ok = profiles["acct-91"]["owner"] == CALLER
    check("module 9's check on that same request", "would refuse",
          "would allow" if owner_ok else "would refuse")
    # Deny by default protects routes nobody listed. It cannot protect a route
    # someone listed with the wrong role.
    wrong = dict(ROUTES)
    wrong[("GET", "/api/admin/reports")] = ("customer", "staff")
    check("an admin route listed with the wrong role", "200 ok",
          dispatch_by_table("GET", "/api/admin/reports", "customer", wrong))
    check("the same route in the correct table", "403 forbidden",
          dispatch_by_table("GET", "/api/admin/reports", "customer"))

    failures = [(n, r) for n, r in enumerate(RESULTS, 1) if r[2] != r[1]]
    print()
    if failures:
        print("%d check(s) did not match the expected outcome:" % len(failures))
        for n, (label, expected, actual) in failures:
            print("  check %d, %s: expected %s, got %s" % (n, label, expected, actual))
        return 1
    print("all lab checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
