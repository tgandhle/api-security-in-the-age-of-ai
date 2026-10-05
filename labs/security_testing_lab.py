#!/usr/bin/env python3
"""Module 34 lab: testing API security.

Python 3, standard library only. On Windows use `py -3` wherever the page
shows `python3`.

Every other lab in this course builds one control and attacks it. This lab is
the test harness. It takes an API it did not write, a machine-readable
description of that API and three test identities, and works out what to send
and what answer to expect.

Nothing here opens a socket, starts a thread or a process, writes a file or
reads a clock. The API is a Python object and a request is a method call.
Every test case runs against a fresh copy of the API with the same test data,
and every generated input comes from a fixed list, so the output is the same
bytes on every run. Nothing leaves this process: the only target is the API
defined in this file.

The target is a small ExampleAir API (a fictional company) in three builds:

  v1  what shipped. Six planted flaws: no ownership check on cancelling a
      booking, no role check on the refund operation, a profile update that
      binds the whole request body, a comparison that raises on a non-numeric
      miles value together with an error handler that returns the detail, no
      length limit on the booking note, and a debug route left reachable.
      Its description also lists a receipt operation that was never built.
  v2  the six fixed, and the description corrected. One business rule is
      still missing: a booking can be refunded more than once.
  v3  v2 with that rule enforced.

  Part A  the description, and the functional test suite passing on v1.
  Part B  an authorization matrix generated from the description: every
          operation, every identity, own object and someone else's, with the
          expected status written down before the run.
  Part C  negative inputs derived from each operation's schema: missing,
          wrong type, null, out of range, over length, oversized, undeclared
          and read-only properties, with a few valid boundary values as a
          control. Every answer's body is also read for a file path or a
          trace.
  Part D  inventory: a fixed list of candidate paths and methods probed and
          compared with the description.
  Part E  the same harness on v2, a flaw it cannot find, and v3.
  Part F  every finding as a regression record, replayed on all three builds.

The description is a Python dict shaped like a cut-down OpenAPI 3.2.1
document: paths, operations, operationId, security requirement objects,
request bodies with a schema and an example. This project found no field in
OpenAPI 3.2.1 for "a customer may only touch their own objects", so the
description carries that in specification extensions, which OpenAPI requires
to begin with `x-`:
x-ownership, x-object, x-object-field and x-denials. Those four names are this
lab's own.

Deliberate simplifications:

  * An identity name such as "cust-a" stands in for a credential. No token is
    issued or checked. Modules 4 to 7 do that.
  * The schema validator handles only the keywords this description uses.
  * The error detail in v1 is a fixed string made up for this lab. A real
    traceback differs between Python versions.
  * A fresh API per test case stands in for resetting a test environment.

Exit codes: 0 every check matched, 1 at least one did not.
"""

import copy
import sys

RESULTS = []
CHECKS = 0


def section(title):
    RESULTS.append((None, title, None))


def record(label, expected, actual):
    """Numbers are assigned here in call order. Adding a check renumbers
    every check after it, and the page cites checks by number."""
    global CHECKS
    CHECKS += 1
    RESULTS.append(("%2d. %s" % (CHECKS, label), expected, actual))


# ---------------------------------------------------------------------------
# The description. The harness reads this and nothing else about the API.
# ---------------------------------------------------------------------------

CUSTOMER = {"bearer": ["customer"]}
AGENT = {"bearer": ["agent"]}

BOOKING_UPDATE = {
    "type": "object", "additionalProperties": False,
    "properties": {
        "seat": {"type": "string", "maxLength": 4},
        "note": {"type": "string", "maxLength": 120}}}

TRANSFER = {
    "type": "object", "additionalProperties": False,
    "required": ["from_account", "to_account", "miles"],
    "properties": {
        "from_account": {"type": "string", "format": "account-id",
                         "maxLength": 16},
        "to_account": {"type": "string", "format": "account-id",
                       "maxLength": 16},
        "miles": {"type": "integer", "minimum": 1, "maximum": 50000}}}

PROFILE = {
    "type": "object", "additionalProperties": False,
    "properties": {
        "email": {"type": "string", "format": "email", "maxLength": 64},
        "display_name": {"type": "string", "maxLength": 40},
        "tier": {"type": "string", "readOnly": True, "maxLength": 16},
        "miles": {"type": "integer", "readOnly": True,
                  "minimum": 0, "maximum": 10000000}}}

REFUND = {
    "type": "object", "additionalProperties": False,
    "required": ["booking_id", "amount"],
    "properties": {
        "booking_id": {"type": "string", "format": "booking-id",
                       "maxLength": 16},
        "amount": {"type": "integer", "minimum": 1, "maximum": 2000}}}


def json_body(schema, example):
    return {"content": {"application/json": {"schema": schema,
                                             "example": example}}}


DESCRIPTION = {
    "openapi": "3.2.1",
    "info": {"title": "ExampleAir customer API", "version": "1.4.0"},
    "components": {"securitySchemes": {
        "bearer": {"type": "http", "scheme": "bearer"}}},
    "x-denials": {"no credentials": 401, "role": 403, "object": 404},
    "paths": {
        "/bookings/{id}": {
            "get": {"operationId": "getBooking",
                    "security": [CUSTOMER, AGENT],
                    "x-ownership": ["customer"], "x-object": "booking"},
            "patch": {"operationId": "updateBooking",
                      "security": [CUSTOMER, AGENT],
                      "x-ownership": ["customer"], "x-object": "booking",
                      "requestBody": json_body(
                          BOOKING_UPDATE,
                          {"seat": "14C", "note": "window if possible"})},
            "delete": {"operationId": "cancelBooking",
                       "security": [CUSTOMER, AGENT],
                       "x-ownership": ["customer"], "x-object": "booking"}},
        "/bookings/{id}/receipt": {
            "get": {"operationId": "getReceipt",
                    "security": [CUSTOMER, AGENT],
                    "x-ownership": ["customer"], "x-object": "booking"}},
        "/miles/transfer": {
            "post": {"operationId": "transferMiles",
                     "security": [CUSTOMER],
                     "x-ownership": ["customer"], "x-object": "account",
                     "x-object-field": "from_account",
                     "requestBody": json_body(
                         TRANSFER, {"from_account": "acct-a",
                                    "to_account": "acct-c", "miles": 500})}},
        "/profiles/{id}": {
            "get": {"operationId": "getProfile",
                    "security": [CUSTOMER, AGENT],
                    "x-ownership": ["customer"], "x-object": "account"},
            "patch": {"operationId": "updateProfile",
                      "security": [CUSTOMER],
                      "x-ownership": ["customer"], "x-object": "account",
                      "requestBody": json_body(
                          PROFILE, {"display_name": "A. Customer"})}},
        "/admin/refunds": {
            "post": {"operationId": "refundBooking",
                     "security": [AGENT],
                     "x-object": "booking", "x-object-field": "booking_id",
                     "requestBody": json_body(
                         REFUND, {"booking_id": "bkg-1001", "amount": 300})}},
    },
}


# ---------------------------------------------------------------------------
# The target. Three builds of one API. The harness never reads this code.
# ---------------------------------------------------------------------------

class Build:
    def __init__(self, name, flaws):
        self.name = name
        self.flaws = frozenset(flaws)

    def has(self, flaw):
        return flaw in self.flaws


V1 = Build("v1", ("cancel-without-owner-check", "refund-without-role-check",
                  "profile-binds-body", "miles-type-unchecked",
                  "errors-show-detail", "note-unbounded", "debug-route",
                  "receipt-documented-not-built", "refund-twice"))
V2 = Build("v2", ("refund-twice",))
V3 = Build("v3", ())

# What each identity name resolves to on the server.
CALLERS = {"cust-a": {"role": "customer", "account": "acct-a"},
           "cust-b": {"role": "customer", "account": "acct-b"},
           "agent-1": {"role": "agent", "account": None}}


def describe(build):
    """The description published with a build. v1 still lists the receipt
    operation that was planned and never built."""
    desc = copy.deepcopy(DESCRIPTION)
    if not build.has("receipt-documented-not-built"):
        del desc["paths"]["/bookings/{id}/receipt"]
    return desc


def violation(schema, body, unchecked=(), unbounded=(), bind_all=False):
    """The first rule the body breaks, as "property: rule", or None. The three
    keyword arguments are how v1 weakens the check."""
    if not isinstance(body, dict):
        return "body: not an object"
    properties = schema["properties"]
    for name in schema.get("required", ()):
        if name not in body:
            return "%s: required" % name
    for name, value in body.items():
        if name not in properties:
            if bind_all or schema.get("additionalProperties") is not False:
                continue
            return "%s: not a declared property" % name
        rule = properties[name]
        if rule.get("readOnly") and not bind_all:
            return "%s: read only" % name
        if name in unchecked:
            continue
        if rule["type"] == "string":
            if not isinstance(value, str):
                return "%s: not a string" % name
            if name not in unbounded and len(value) > rule["maxLength"]:
                return "%s: longer than maxLength" % name
        else:
            if isinstance(value, bool) or not isinstance(value, int):
                return "%s: not an integer" % name
            if value < rule["minimum"] or value > rule["maximum"]:
                return "%s: out of range" % name
    return None


class Api:
    def __init__(self, build, events=None):
        self.build = build
        self.events = events if events is not None else []
        self.accounts = {
            "acct-a": {"email": "a@customer.example", "display_name": "A",
                       "tier": "basic", "miles": 60000},
            "acct-b": {"email": "b@customer.example", "display_name": "B",
                       "tier": "basic", "miles": 60000},
            "acct-c": {"email": "c@customer.example", "display_name": "C",
                       "tier": "basic", "miles": 0}}
        self.bookings = {
            "bkg-1001": {"owner": "acct-a", "status": "confirmed",
                         "seat": "12A", "note": "", "refunded": 0},
            "bkg-2001": {"owner": "acct-b", "status": "confirmed",
                         "seat": "30F", "note": "", "refunded": 0}}
        both = ("customer", "agent")
        refund_roles = both if build.has("refund-without-role-check") \
            else ("agent",)
        self.routes = [
            ("GET", "/bookings/{id}", both, self.get_booking),
            ("PATCH", "/bookings/{id}", both, self.update_booking),
            ("DELETE", "/bookings/{id}", both, self.cancel_booking),
            ("POST", "/miles/transfer", ("customer",), self.transfer_miles),
            ("GET", "/profiles/{id}", both, self.get_profile),
            ("PATCH", "/profiles/{id}", ("customer",), self.update_profile),
            ("POST", "/admin/refunds", refund_roles, self.refund_booking)]
        if build.has("debug-route"):
            self.routes.append(("GET", "/debug/config", both, self.debug))

    # --- plumbing ---
    def log(self, event, who, status, reason):
        self.events.append((event, who, status))
        return status, {"error": reason}

    def find(self, method, path):
        parts = path.split("/")
        path_known = False
        for verb, template, roles, handler in self.routes:
            pattern = template.split("/")
            if len(pattern) != len(parts):
                continue
            if all(p == "{id}" or p == q for p, q in zip(pattern, parts)):
                path_known = True
                if verb == method:
                    pid = parts[pattern.index("{id}")] \
                        if "{id}" in pattern else None
                    return roles, handler, pid
        return 405 if path_known else 404

    def call(self, identity, method, path, body=None):
        who = CALLERS.get(identity)
        if who is None:
            return self.log("authn_fail", identity, 401,
                            "authentication required")
        found = self.find(method, path)
        if found == 404:
            return 404, {"error": "not found"}
        if found == 405:
            return 405, {"error": "method not allowed"}
        roles, handler, pid = found
        if who["role"] not in roles:
            return self.log("authz_fail", identity, 403, "forbidden")
        try:
            return handler(identity, who, pid, body)
        except Exception as exc:
            if self.build.has("errors-show-detail"):
                # Fixed text standing in for a traceback.
                return 500, {"error": type(exc).__name__,
                             "trace": 'File "/srv/exampleair/handlers/'
                                      'miles.py", line 88, in transfer_miles'}
            return 500, {"error": "internal error"}

    def invalid(self, identity, rule):
        self.events.append(("input_validation_fail", identity, 400))
        return 400, {"error": "invalid request", "rule": rule}

    def not_owner(self, identity):
        """The same answer as for an object that does not exist."""
        return self.log("authz_fail", identity, 404, "not found")

    @staticmethod
    def may_touch(who, owner):
        return who["role"] == "agent" or who["account"] == owner

    # --- handlers ---
    def get_booking(self, identity, who, pid, body):
        booking = self.bookings.get(pid)
        if booking is None:
            return 404, {"error": "not found"}
        if not self.may_touch(who, booking["owner"]):
            return self.not_owner(identity)
        return 200, {"id": pid, "status": booking["status"],
                     "seat": booking["seat"], "note": booking["note"]}

    def update_booking(self, identity, who, pid, body):
        unbounded = ("note",) if self.build.has("note-unbounded") else ()
        rule = violation(BOOKING_UPDATE, body, unbounded=unbounded)
        if rule:
            return self.invalid(identity, rule)
        booking = self.bookings.get(pid)
        if booking is None:
            return 404, {"error": "not found"}
        if not self.may_touch(who, booking["owner"]):
            return self.not_owner(identity)
        booking.update(body)
        return 200, {"id": pid, "seat": booking["seat"]}

    def cancel_booking(self, identity, who, pid, body):
        booking = self.bookings.get(pid)
        if booking is None:
            return 404, {"error": "not found"}
        if not self.build.has("cancel-without-owner-check") \
                and not self.may_touch(who, booking["owner"]):
            return self.not_owner(identity)
        booking["status"] = "cancelled"
        return 200, {"id": pid, "status": "cancelled"}

    def transfer_miles(self, identity, who, pid, body):
        if self.build.has("miles-type-unchecked"):
            rule = violation(TRANSFER, body, unchecked=("miles",))
            if rule is None and (body["miles"] < 1 or body["miles"] > 50000):
                rule = "miles: out of range"
        else:
            rule = violation(TRANSFER, body)
        if rule:
            return self.invalid(identity, rule)
        source = self.accounts.get(body["from_account"])
        target = self.accounts.get(body["to_account"])
        if source is None or target is None:
            return 404, {"error": "not found"}
        if not self.may_touch(who, body["from_account"]):
            return self.not_owner(identity)
        if source["miles"] < body["miles"]:
            return 409, {"error": "insufficient miles"}
        source["miles"] -= body["miles"]
        target["miles"] += body["miles"]
        return 200, {"from_account": body["from_account"],
                     "miles": source["miles"]}

    def get_profile(self, identity, who, pid, body):
        account = self.accounts.get(pid)
        if account is None:
            return 404, {"error": "not found"}
        if not self.may_touch(who, pid):
            return self.not_owner(identity)
        return 200, {name: account[name] for name in PROFILE["properties"]}

    def update_profile(self, identity, who, pid, body):
        bind_all = self.build.has("profile-binds-body")
        rule = violation(PROFILE, body, bind_all=bind_all)
        if rule:
            return self.invalid(identity, rule)
        account = self.accounts.get(pid)
        if account is None:
            return 404, {"error": "not found"}
        if not self.may_touch(who, pid):
            return self.not_owner(identity)
        for name, value in body.items():
            if bind_all or name in ("email", "display_name"):
                account[name] = value
        return 200, {"id": pid, "display_name": account["display_name"]}

    def refund_booking(self, identity, who, pid, body):
        rule = violation(REFUND, body)
        if rule:
            return self.invalid(identity, rule)
        booking = self.bookings.get(body["booking_id"])
        if booking is None:
            return 404, {"error": "not found"}
        if booking["refunded"] and not self.build.has("refund-twice"):
            return 409, {"error": "already refunded"}
        booking["refunded"] += body["amount"]
        return 200, {"booking_id": body["booking_id"],
                     "refunded": booking["refunded"]}

    def debug(self, identity, who, pid, body):
        return 200, {"build": self.build.name,
                     "db_host": "db.internal.example",
                     "routes": [verb + " " + template
                                for verb, template, _, _ in self.routes]}


def maker(build, events=None):
    """A function that returns a fresh API with the same test data."""
    return lambda: Api(build, events)


# ---------------------------------------------------------------------------
# The functional suite the team already had. Positive tests only.
# ---------------------------------------------------------------------------

FUNCTIONAL = (
    ("a customer reads their booking",
     lambda api: api.call("cust-a", "GET", "/bookings/bkg-1001")[0] == 200),
    ("a customer changes their seat",
     lambda api: api.call("cust-a", "PATCH", "/bookings/bkg-1001",
                          {"seat": "14C"})[0] == 200
     and api.bookings["bkg-1001"]["seat"] == "14C"),
    ("a customer cancels their booking",
     lambda api: api.call("cust-a", "DELETE", "/bookings/bkg-1001")[0] == 200
     and api.bookings["bkg-1001"]["status"] == "cancelled"),
    ("a customer transfers miles",
     lambda api: api.call("cust-a", "POST", "/miles/transfer",
                          {"from_account": "acct-a", "to_account": "acct-c",
                           "miles": 500})[0] == 200
     and api.accounts["acct-c"]["miles"] == 500),
    ("a customer reads their profile",
     lambda api: api.call("cust-a", "GET", "/profiles/acct-a")[1].get("tier")
     == "basic"),
    ("a customer changes their display name",
     lambda api: api.call("cust-a", "PATCH", "/profiles/acct-a",
                          {"display_name": "Ana"})[0] == 200
     and api.accounts["acct-a"]["display_name"] == "Ana"),
    ("an agent reads any booking",
     lambda api: api.call("agent-1", "GET", "/bookings/bkg-2001")[0] == 200),
    ("an agent refunds a booking",
     lambda api: api.call("agent-1", "POST", "/admin/refunds",
                          {"booking_id": "bkg-1001", "amount": 300})[0] == 200
     and api.bookings["bkg-1001"]["refunded"] == 300),
)


def run_functional(make):
    return sum(1 for _, test in FUNCTIONAL if test(make()))


def functional_statuses(make):
    """The status of every request the functional suite sends."""
    seen = []
    for _, test in FUNCTIONAL:
        api = make()
        send = api.call

        def spy(*args, send=send):
            answer = send(*args)
            seen.append(answer[0])
            return answer

        api.call = spy
        test(api)
    return seen


# ---------------------------------------------------------------------------
# The harness. It learns about the API from the description and reaches it
# only through call(). (The functional suite above and the hand-written test
# in Part E also read the API's stored data, as a team's own tests can.)
# ---------------------------------------------------------------------------

# The test accounts the harness was given: name, role, account. Two customers,
# so that one can be pointed at the other's objects.
IDENTITIES = (("cust-a", "customer", "acct-a"),
              ("cust-b", "customer", "acct-b"),
              ("agent-1", "agent", None))

# The object each test account owns, by the kind the description names.
OBJECT_IDS = {"booking": {"acct-a": "bkg-1001", "acct-b": "bkg-2001"},
              "account": {"acct-a": "acct-a", "acct-b": "acct-b"}}

PATH_ITEM_METHODS = ("get", "put", "post", "delete", "options", "head",
                     "patch", "trace", "query")


def operations(desc):
    """Every operation in the description, flattened."""
    found = []
    for path, item in desc["paths"].items():
        for method in PATH_ITEM_METHODS:
            if method not in item:
                continue
            op = item[method]
            media = None
            if "requestBody" in op:
                media = op["requestBody"]["content"]["application/json"]
            found.append({
                "id": op["operationId"], "method": method.upper(),
                "path": path,
                # Each security requirement object is one alternative.
                "roles": [role for requirement in op["security"]
                          for roles in requirement.values() for role in roles],
                "owned": op.get("x-ownership", []),
                "object": op["x-object"],
                "field": op.get("x-object-field"),
                "schema": media["schema"] if media else None,
                "example": media["example"] if media else None})
    return found


def request_for(op, owner):
    """A valid request for this operation aimed at the object owner owns."""
    object_id = OBJECT_IDS[op["object"]][owner]
    body = dict(op["example"]) if op["example"] else None
    if op["field"]:
        body[op["field"]] = object_id
    return op["method"], op["path"].replace("{id}", object_id), body


def owners():
    return [account for _, _, account in IDENTITIES if account]


# --- Part B: the authorization matrix ---

def build_matrix(desc):
    """One cell per operation, identity and object owner, plus one cell per
    operation with no credentials. The expected status is decided here, from
    the description, before anything is sent."""
    denial = desc["x-denials"]
    cells = []
    for op in operations(desc):
        cells.append((op, None, owners()[0], denial["no credentials"]))
        for name, role, account in IDENTITIES:
            for owner in owners():
                if role not in op["roles"]:
                    expected = denial["role"]
                elif role in op["owned"] and account != owner:
                    expected = denial["object"]
                else:
                    expected = 200
                cells.append((op, name, owner, expected))
    return cells


def run_matrix(make, cells):
    """Each cell with the status it got and how that compares."""
    out = []
    for op, name, owner, expected in cells:
        method, path, body = request_for(op, owner)
        got = make().call(name, method, path, body)[0]
        if got == expected:
            verdict = "match"
        elif got < 300 and expected >= 400:
            verdict = "allowed"
        elif expected < 300 and got in (401, 403, 404, 405):
            verdict = "refused"
        else:
            verdict = "other"
        out.append({"op": op["id"], "who": name, "owner": owner,
                    "expected": expected, "got": got, "verdict": verdict})
    return out


def count_by_op(rows, verdict):
    counts = {}
    for row in rows:
        if row["verdict"] == verdict:
            counts[row["op"]] = counts.get(row["op"], 0) + 1
    return ["%s x%d" % pair for pair in counts.items()]


LEVEL = {401: "no authentication", 403: "function-level", 404: "object-level"}


def matrix_findings(rows):
    """One finding per operation and kind of check that failed."""
    found = []
    for row in rows:
        if row["verdict"] == "allowed":
            finding = "%s: %s" % (row["op"], LEVEL[row["expected"]])
            if finding not in found:
                found.append(finding)
    return found


# --- Part C: inputs derived from the schema ---

OVERSIZE = 100000
LEAK_MARKERS = ("Traceback", 'File "', ".py")


def caller_for(op):
    """The first test identity the description allows to call it."""
    for name, role, account in IDENTITIES:
        if role in op["roles"]:
            return name, account or owners()[0]
    raise ValueError("no test identity may call " + op["id"])


def cases_for(op):
    """(kind, property, positive, path id or None, body) for one operation.
    A positive case is valid input and must be accepted."""
    cases = []
    if "{id}" in op["path"]:
        cases.append(("malformed id", "id", False, "not-an-id", "valid"))
        cases.append(("oversized", "id", False, "b" * OVERSIZE, "valid"))
    schema = op["schema"]
    if schema is None:
        return cases
    base = request_for(op, caller_for(op)[1])[2]

    def add(kind, name, value, positive=False):
        cases.append((kind, name, positive, None, dict(base, **{name: value})))

    cases.append(("no body", "body", False, None, None))
    cases.append(("not an object", "body", False, None, []))
    for name, rule in schema["properties"].items():
        is_string = rule["type"] == "string"
        if rule.get("readOnly"):
            add("read-only property", name,
                "platinum" if is_string else 999999)
            continue
        if name in schema.get("required", ()):
            cases.append(("missing", name, False, None,
                          {k: v for k, v in base.items() if k != name}))
        add("wrong type", name, 7 if is_string else "7")
        add("null", name, None)
        if is_string:
            if "format" not in rule:
                # The generator cannot invent a valid identifier or address,
                # so only free-text properties get a valid boundary value.
                add("at the limit", name, "a" * rule["maxLength"], True)
            add("over the limit", name, "a" * (rule["maxLength"] + 1))
            add("oversized", name, "a" * OVERSIZE)
        else:
            add("at the limit", name, rule["minimum"], True)
            add("at the limit", name, rule["maximum"], True)
            add("over the limit", name, rule["minimum"] - 1)
            add("over the limit", name, rule["maximum"] + 1)
            add("oversized", name, 10 ** 12)
    if schema.get("additionalProperties") is False:
        add("undeclared property", "x_unknown", 1)
    return cases


def reader_for(desc, op):
    """The GET operation on the same path, to read an object back."""
    for other in operations(desc):
        if other["path"] == op["path"] and other["method"] == "GET":
            return other
    return None


PROBLEM = {"over the limit": "limit not enforced",
           "oversized": "limit not enforced",
           "undeclared property": "property outside the contract accepted",
           "read-only property": "property outside the contract accepted"}


def run_cases(make, desc):
    """Send every generated case and classify the answer."""
    out = []
    for op in operations(desc):
        name, owner = caller_for(op)
        method, path, valid = request_for(op, owner)
        reader = reader_for(desc, op)
        for kind, prop, positive, path_id, body in cases_for(op):
            api = make()
            target = path if path_id is None \
                else op["path"].replace("{id}", path_id)
            before = after = None
            # Read back through the operation the description gives for it.
            read_back = kind == "read-only property" and reader is not None
            if read_back:
                before = api.call(name, reader["method"], path)[1].get(prop)
            status, answer = api.call(name, method, target,
                                      valid if body == "valid" else body)
            if read_back:
                after = api.call(name, reader["method"], path)[1].get(prop)
            leak = any(marker in str(value) for value in answer.values()
                       for marker in LEAK_MARKERS)
            refused = 400 <= status < 500
            if positive:
                problem = None if status < 300 else "valid input refused"
            elif refused:
                problem = None
            elif status >= 500:
                problem = "5xx on malformed input"
            elif read_back and before == after:
                # Accepted and not stored. The JSON Schema rule that OpenAPI
                # cites lets the receiver ignore a read-only property.
                problem = None
            else:
                problem = PROBLEM.get(kind, "invalid value accepted")
            if problem is None and leak:
                # A body that shows internals is a finding whatever the
                # status, when nothing else is already reported for the case.
                problem = "internal detail in the response"
            out.append({"op": op["id"], "kind": kind, "property": prop,
                        "positive": positive, "status": status, "leak": leak,
                        "problem": problem, "before": before, "after": after})
    return out


def schema_findings(rows):
    """One finding per operation and problem, naming the properties."""
    grouped = {}
    for row in rows:
        if row["problem"]:
            names = grouped.setdefault((row["op"], row["problem"]), [])
            if row["property"] not in names:
                names.append(row["property"])
    return ["%s: %s (%s)" % (op, problem, ", ".join(sorted(names)))
            for (op, problem), names in grouped.items()]


# --- Part D: inventory ---

GUESSED_PATHS = ("/bookings", "/profiles", "/admin", "/admin/users",
                 "/debug", "/debug/config", "/internal/health", "/metrics",
                 "/v0/bookings/{id}")
PROBE_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")


def inventory(make, desc):
    """Probe every documented and guessed path with five methods, as the
    agent, and compare what answers with what the description lists."""
    documented = [op["method"] + " " + op["path"] for op in operations(desc)]
    paths = list(desc["paths"]) + [p for p in GUESSED_PATHS
                                   if p not in desc["paths"]]
    deployed = []
    probes = 0
    for path in paths:
        object_id = "bkg-1001" if "bookings" in path else "acct-a"
        for method in PROBE_METHODS:
            probes += 1
            status = make().call("agent-1", method,
                                 path.replace("{id}", object_id), {})[0]
            if status not in (404, 405):
                deployed.append(method + " " + path)
    return {"probes": probes, "deployed": deployed,
            "undocumented": [d for d in deployed if d not in documented],
            "not deployed": [d for d in documented if d not in deployed]}


def harness(build):
    """Parts B, C and D against one build: the security findings."""
    desc = describe(build)
    make = maker(build)
    found = matrix_findings(run_matrix(make, build_matrix(desc)))
    found += schema_findings(run_cases(make, desc))
    found += [route + ": not in the description"
              for route in inventory(make, desc)["undocumented"]]
    return found


# --- Part F: regression records ---

NOTE_121 = "a" * 121
REFUND_300 = {"booking_id": "bkg-1001", "amount": 300}

# Each record: the finding it came from, the checklist item of the control
# that failed, the requests to send in order, and what the last one must
# answer. "field" names a value the last answer must also carry.
REGRESSION = (
    {"id": "REG-01", "finding": "cancelBooking: object-level",
     "control": "bola-02",
     "steps": (("cust-b", "DELETE", "/bookings/bkg-1001", None),),
     "expect": 404},
    {"id": "REG-02", "finding": "refundBooking: function-level",
     "control": "prop-02",
     "steps": (("cust-a", "POST", "/admin/refunds", REFUND_300),),
     "expect": 403},
    {"id": "REG-03", "finding": "updateBooking: limit not enforced (note)",
     "control": "ctr-07",
     "steps": (("cust-a", "PATCH", "/bookings/bkg-1001",
                {"seat": "14C", "note": NOTE_121}),),
     "expect": 400},
    {"id": "REG-04",
     "finding": "transferMiles: 5xx on malformed input (miles)",
     "control": "cfg-01",
     "steps": (("cust-a", "POST", "/miles/transfer",
                {"from_account": "acct-a", "to_account": "acct-c",
                 "miles": "7"}),),
     "expect": 400},
    {"id": "REG-05",
     "finding": "updateProfile: property outside the contract accepted "
                "(miles, tier, x_unknown)",
     "control": "prop-01",
     "steps": (("cust-a", "PATCH", "/profiles/acct-a",
                {"display_name": "A. Customer", "tier": "platinum"}),
               ("cust-a", "GET", "/profiles/acct-a", None)),
     "expect": 200, "field": ("tier", "basic")},
    {"id": "REG-06", "finding": "GET /debug/config: not in the description",
     "control": "cfg-06",
     "steps": (("agent-1", "GET", "/debug/config", None),),
     "expect": 404},
    {"id": "REG-07", "finding": "refundBooking: second refund accepted",
     "control": "flow-03",
     "steps": (("agent-1", "POST", "/admin/refunds", REFUND_300),
               ("agent-1", "POST", "/admin/refunds", REFUND_300)),
     "expect": 409},
)


def replay(make, rec):
    """Run one record against a fresh API. "pass" means the flaw is absent."""
    api = make()
    status, answer = None, {}
    for identity, method, path, body in rec["steps"]:
        status, answer = api.call(identity, method, path, body)
        if any(m in str(v) for v in answer.values() for m in LEAK_MARKERS):
            return "fail"
    if status != rec["expect"]:
        return "fail"
    if "field" in rec and answer.get(rec["field"][0]) != rec["field"][1]:
        return "fail"
    return "pass"


def refund_twice(build):
    """The hand-written test for one business rule: a booking is refunded at
    most once. Nothing in the description states it."""
    api = Api(build)
    statuses = [api.call("agent-1", "POST", "/admin/refunds", REFUND_300)[0]
                for _ in range(2)]
    return statuses, api.bookings["bkg-1001"]["refunded"]


# The six flaws planted in v1, as the harness should report them.
PLANTED = ["cancelBooking: object-level",
           "refundBooking: function-level",
           "updateBooking: limit not enforced (note)",
           "transferMiles: 5xx on malformed input (miles)",
           "updateProfile: property outside the contract accepted "
           "(miles, tier, x_unknown)",
           "GET /debug/config: not in the description"]


def main():
    print("ExampleAir is fictional. Every request in this lab is a method "
          "call on an object in this file.")
    v1 = maker(V1)
    desc1 = describe(V1)

    # ---------------- Part A -------------------------------------------
    section("Part A: the API that shipped, and the tests it passed.")
    record("operations in the description", 8, len(operations(desc1)))
    record("  of which take a request body", 4,
           sum(1 for op in operations(desc1) if op["schema"]))
    record("functional tests the team already runs", 8, len(FUNCTIONAL))
    record("  passed on v1", 8, run_functional(v1))
    sent = functional_statuses(v1)
    record("  requests those tests send", 8, len(sent))
    record("  of which answered with a refusal", 0,
           sum(1 for status in sent if status >= 400))
    api = Api(V1)
    record("cust-b cancels a booking that belongs to acct-a", 200,
           api.call("cust-b", "DELETE", "/bookings/bkg-1001")[0])
    record("  status of that booking afterwards", "cancelled",
           api.bookings["bkg-1001"]["status"])
    record("cust-a calls the agent-only refund operation", 200,
           api.call("cust-a", "POST", "/admin/refunds", REFUND_300)[0])

    # ---------------- Part B -------------------------------------------
    section("Part B: an authorization matrix generated from the description.")
    cells = build_matrix(desc1)
    record("cells: 8 operations x (3 identities x 2 owners + no credentials)",
           56, len(cells))
    record("  expected status, counted before anything is sent",
           ["200 x26", "401 x8", "403 x8", "404 x14"],
           ["%d x%d" % (code, sum(1 for c in cells if c[3] == code))
            for code in (200, 401, 403, 404)])
    rows = run_matrix(v1, cells)
    record("v1: cells where the status is the expected one", 46,
           sum(1 for r in rows if r["verdict"] == "match"))
    record("  allowed where a refusal was expected", 6,
           sum(1 for r in rows if r["verdict"] == "allowed"))
    record("    by operation", ["cancelBooking x2", "refundBooking x4"],
           count_by_op(rows, "allowed"))
    record("    who reached whose object in cancelBooking",
           ["cust-a -> acct-b", "cust-b -> acct-a"],
           ["%s -> %s" % (r["who"], r["owner"]) for r in rows
            if r["verdict"] == "allowed" and r["op"] == "cancelBooking"])
    record("  refused where 200 was expected", ["getReceipt x4"],
           count_by_op(rows, "refused"))
    record("  any other difference, such as a 5xx", 0,
           sum(1 for r in rows if r["verdict"] == "other"))
    found_b = matrix_findings(rows)
    record("authorization findings", PLANTED[0:2], found_b)

    # ---------------- Part C -------------------------------------------
    section("Part C: inputs derived from each operation's schema.")
    results = run_cases(v1, desc1)
    negative = [r for r in results if not r["positive"]]
    positive = [r for r in results if r["positive"]]
    record("generated cases that must be refused", 69, len(negative))
    record("  by kind",
           ["malformed id x6", "oversized x15", "no body x4",
            "not an object x4", "wrong type x9", "null x9",
            "over the limit x11", "undeclared property x4", "missing x5",
            "read-only property x2"],
           count_kinds(negative))
    record("generated valid boundary cases that must be accepted", 7,
           len(positive))
    record("v1: cases that must be refused, answered 4xx", 62,
           sum(1 for r in negative if 400 <= r["status"] < 500))
    record("  answered 2xx", 5,
           sum(1 for r in negative if r["status"] < 300))
    record("  answered 5xx", 2,
           sum(1 for r in negative if r["status"] >= 500))
    record("  responses, of all 76, that show a file path or a trace", 2,
           sum(1 for r in results if r["leak"]))
    record("  valid boundary cases accepted", 7,
           sum(1 for r in positive if r["status"] < 300))
    found_c = schema_findings(results)
    record("schema findings", PLANTED[2:5], found_c)
    tier = [r for r in results if r["property"] == "tier"][0]
    record("  tier read back before and after the update that carried it",
           ["basic", "platinum"], [tier["before"], tier["after"]])

    # ---------------- Part D -------------------------------------------
    section("Part D: what is deployed, compared with what is described.")
    inv = inventory(v1, desc1)
    record("requests sent: 14 paths x 5 methods", 70, inv["probes"])
    record("v1: answered with something other than 404 or 405", 8,
           len(inv["deployed"]))
    record("  deployed and not in the description", ["GET /debug/config"],
           inv["undocumented"])
    record("  in the description and not deployed",
           ["GET /bookings/{id}/receipt"], inv["not deployed"])
    found_d = [r + ": not in the description" for r in inv["undocumented"]]
    record("security findings from Parts B, C and D", 6,
           len(found_b + found_c + found_d))
    record("  they are the six planted flaws and nothing else", True,
           found_b + found_c + found_d == PLANTED)

    # ---------------- Part E -------------------------------------------
    section("Part E: the fixed build, and what the harness cannot see.")
    record("v2: functional tests passed, of 8", 8, run_functional(maker(V2)))
    record("v2: security findings from the same harness", [], harness(V2))
    events = []
    rows2 = run_matrix(maker(V2, events), build_matrix(describe(V2)))
    record("  matrix cells on v2, one operation fewer in the description",
           49, len(rows2))
    record("  cells refused with 401, 403 or 404", 27,
           sum(1 for r in rows2 if r["got"] in (401, 403, 404)))
    record("  authn_fail and authz_fail events the API logged in that run",
           27, sum(1 for e in events if e[0] in ("authn_fail", "authz_fail")))
    statuses, total = refund_twice(V2)
    record("v2: an agent refunds one booking twice, 300 each", [200, 200],
           statuses)
    record("  total refunded on that booking", 600, total)
    statuses, total = refund_twice(V3)
    record("v3: the same two requests", [200, 409], statuses)
    record("  total refunded on that booking", 300, total)
    record("v3: security findings from the harness", [], harness(V3))
    record("v3: functional tests passed, of 8", 8, run_functional(maker(V3)))

    # ---------------- Part F -------------------------------------------
    section("Part F: every finding as a regression record, on v1, v2, v3.")
    outcomes = {}
    expected = {"REG-07": ["fail", "fail", "pass"]}
    for rec in REGRESSION:
        outcomes[rec["id"]] = [replay(maker(b), rec) for b in (V1, V2, V3)]
        record("%s %s, %d request%s, expect %d" % (
            rec["id"], rec["control"], len(rec["steps"]),
            "" if len(rec["steps"]) == 1 else "s", rec["expect"]),
            expected.get(rec["id"], ["fail", "pass", "pass"]),
            outcomes[rec["id"]])
    record("records that fail on v1, v2, v3", [7, 1, 0],
           [sum(1 for o in outcomes.values() if o[i] == "fail")
            for i in range(3)])
    record("every finding above has a record", True,
           [rec["finding"] for rec in REGRESSION]
           == found_b + found_c + found_d
           + ["refundBooking: second refund accepted"])

    width = max(len(label) for label, _, _ in RESULTS if label is not None)
    for label, expected, actual in RESULTS:
        if label is None:
            print()
            print(expected)
            continue
        print("%-*s %s" % (width + 1, label, actual))

    failures = [r for r in RESULTS
                if r[0] is not None and r[2] != r[1]]
    print()
    if failures:
        for label, expected, actual in failures:
            print("FAILED %s: expected %r, got %r" % (label, expected, actual))
        return 1
    print("all %d lab checks passed" % CHECKS)
    return 0


def count_kinds(rows):
    counts = {}
    for row in rows:
        counts[row["kind"]] = counts.get(row["kind"], 0) + 1
    return ["%s x%d" % pair for pair in counts.items()]


if __name__ == "__main__":
    sys.exit(main())
