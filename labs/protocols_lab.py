#!/usr/bin/env python3
"""Module 33 lab: GraphQL, gRPC and WebSocket APIs.

Every other lab in the course uses one HTTP request per operation with a JSON
body. This lab changes the protocol three times and shows, each time, a
control from an earlier module that stops applying by default, the attack
that follows, and the protocol-specific control.

  Part A  GraphQL. One HTTP request carries 50 login attempts past a
          per-request rate limit; a nested query multiplies work; a check
          at the endpoint or on the root field does not cover a nested
          field; introspection and field suggestions describe the schema;
          a mutation arrives as a GET or a form post.
  Part B  gRPC. An edge filter written for JSON routes cannot read the
          message; an interceptor that only authenticates lets a customer
          call an admin method; reflection lists that method; a call with
          no deadline runs to the lab's cap; an oversized message and a
          long stream; a monitor that reads HTTP status sees only 200.
  Part C  WebSocket. A page on another site opens a socket with the
          victim's cookie; a message asks for another customer's booking;
          a revoked session keeps working; a flood of messages passes a
          handshake limit; oversized, fragmented and compressed frames.

Nothing here opens a socket, and no GraphQL, gRPC or WebSocket library is
used. Each protocol is a small model in plain Python.

Deliberate simplifications:

  * GraphQL: the parser accepts a subset of the language: one operation, the
    query and mutation keywords, fields, aliases, string and integer
    arguments and nested selection sets. No fragments, variables or
    directives. Validation checks only that a field exists, that object
    fields have a selection set and that a "first" argument is a whole
    number, zero or more. Introspection is one field, __schema, that
    returns a flat list of "Type.field" names. The decoded request
    parameters are passed in as Python objects; no JSON text or URL is
    parsed. A result with errors is answered with HTTP 200.
  * gRPC: a call is a path, a metadata dict and one or more length-prefixed
    messages. The message encoding is a tag, a length and a value per field,
    which is binary but is not protobuf. HTTP/2 framing, flow control and
    TLS are not modelled. Reflection is one lab method that returns method
    paths; the real protocol is a streaming service that returns file
    descriptors. Time is a counter of 100 ms work steps, not a clock.
  * WebSocket: the handshake is an object with headers, and a frame is a
    declared length, a payload and three flags. The browser attaches a
    cookie by host, and by site when the cookie is marked SameSite=Lax,
    where "site" is the last two labels of the host. Module 28's lab models
    cookies properly. A page on another origin cannot read the ticket
    endpoint's reply; the lab states that as a rule and does not model CORS.
  * Passwords, session ids, tokens and tickets are random per run and are
    never printed.

Python 3, standard library only. Exit codes: 0 all checks matched, 1 a check
did not match.
"""

import difflib
import hmac
import json
import re
import secrets
import sys
import zlib

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
# Shared data: ExampleAir customers and bookings. Three group bookings carry
# all four customers, which gives the data the cycle Part A needs.
# ---------------------------------------------------------------------------

def fresh_data():
    customers = {
        "c-ana": {"id": "c-ana", "name": "Ana Rivera", "miles": 42000, "role": "customer"},
        "c-ben": {"id": "c-ben", "name": "Ben Okafor", "miles": 97000, "role": "customer"},
        "c-cai": {"id": "c-cai", "name": "Cai Lindqvist", "miles": 1200, "role": "customer"},
        "c-dee": {"id": "c-dee", "name": "Dee Marchetti", "miles": 800, "role": "customer"},
        "ops-1": {"id": "ops-1", "name": "Operations", "miles": 0, "role": "admin"},
    }
    family = ["c-ana", "c-ben", "c-cai", "c-dee"]
    bookings = {
        "BK1001": {"id": "BK1001", "flight": "EA100", "passenger": "Ana Rivera", "travellers": ["c-ana"]},
        "BK2001": {"id": "BK2001", "flight": "EA731", "passenger": "Ben Okafor", "travellers": ["c-ben"]},
        "BK3001": {"id": "BK3001", "flight": "EA210", "passenger": "Ana Rivera", "travellers": family},
        "BK3002": {"id": "BK3002", "flight": "EA211", "passenger": "Ana Rivera", "travellers": family},
        "BK3003": {"id": "BK3003", "flight": "EA450", "passenger": "Ana Rivera", "travellers": family},
    }
    return customers, bookings


# ===========================================================================
# Part A model: GraphQL
# ===========================================================================

class Field:
    def __init__(self, alias, name, args, selections):
        self.alias, self.name, self.args, self.selections = alias, name, args, selections


class Operation:
    def __init__(self, kind, selections):
        self.kind, self.selections = kind, selections


TOKEN = re.compile(r'\s*(?:([{}():])|([_A-Za-z][_0-9A-Za-z]*)|(-?\d+)|"([^"\\]*)")')


def parse(text):
    """Parse the subset of GraphQL described in the docstring. Commas are
    removed first: the specification calls them insignificant."""
    text = text.replace(",", " ")
    tokens, pos = [], 0
    while pos < len(text.rstrip()):
        m = TOKEN.match(text, pos)
        if not m:
            raise ValueError("syntax error")
        punct, name, number, string = m.groups()
        tokens.append(("punct", punct) if punct else ("name", name) if name
                      else ("int", int(number)) if number else ("str", string))
        pos = m.end()
    state = {"i": 0}

    def peek():
        return tokens[state["i"]] if state["i"] < len(tokens) else (None, None)

    def take(kind=None, value=None):
        tok = peek()
        if (kind and tok[0] != kind) or (value and tok[1] != value):
            raise ValueError("syntax error")
        state["i"] += 1
        return tok[1]

    def selection_set():
        take("punct", "{")
        fields = []
        while peek() != ("punct", "}"):
            alias, name = None, take("name")
            if peek() == ("punct", ":"):
                take()
                alias, name = name, take("name")
            args = {}
            if peek() == ("punct", "("):
                take()
                while peek() != ("punct", ")"):
                    key = take("name")
                    take("punct", ":")
                    if peek()[0] not in ("int", "str"):
                        raise ValueError("syntax error")
                    args[key] = take()
                take()
            sub = selection_set() if peek() == ("punct", "{") else []
            fields.append(Field(alias, name, args, sub))
        take()
        if not fields:
            raise ValueError("syntax error")
        return fields

    kind = "query"
    if peek()[0] == "name":
        kind = take("name")
        if kind not in ("query", "mutation"):
            raise ValueError("syntax error")
        if peek()[0] == "name":
            take()                                  # an operation name
    op = Operation(kind, selection_set())
    if state["i"] != len(tokens):
        raise ValueError("syntax error")
    return op


# type -> field -> (return type, is it a list)
SCHEMA = {
    "Query": {"me": ("Customer", False), "booking": ("Booking", False)},
    "Mutation": {"login": ("String", False), "transferMiles": ("Int", False),
                 "adjustMiles": ("Int", False)},
    "Customer": {"id": ("String", False), "name": ("String", False),
                 "miles": ("Int", False), "bookings": ("Booking", True)},
    "Booking": {"id": ("String", False), "flight": ("String", False),
                "passenger": ("String", False), "travellers": ("Customer", True)},
}
SENSITIVE_FIELDS = ("login",)          # at most one of these per HTTP request
ASSUMED_PAGE = 10                      # list size the cost estimate assumes
SIMPLE_CONTENT_TYPES = ("application/x-www-form-urlencoded", "multipart/form-data", "text/plain")


def sent_without_preflight(method, content_type):
    """True when a browser sends this cross-origin request with no preflight.
    Module 17 has the full rule; these are the cases this lab needs."""
    return method == "GET" or (method == "POST" and content_type in SIMPLE_CONTENT_TYPES)


def all_fields(selections):
    for f in selections:
        yield f
        yield from all_fields(f.selections)


def depth(selections):
    """A root field has depth 1, as in the OWASP GraphQL Cheat Sheet."""
    return max((1 + depth(f.selections) for f in selections), default=0)


def estimated_cost(type_name, selections, multiplier=1):
    """One unit per field resolution, assuming each list returns the number
    of items its first argument asks for, or ASSUMED_PAGE items."""
    total = 0
    for f in selections:
        total += multiplier
        if f.name in SCHEMA.get(type_name, {}):
            ret, is_list = SCHEMA[type_name][f.name]
            inner = multiplier * (f.args.get("first", ASSUMED_PAGE) if is_list else 1)
            total += estimated_cost(ret, f.selections, inner)
    return total


class Denied(Exception):
    """A refusal raised by a resolver or a handler. In Part A it carries the
    message for the errors list; in Part B it carries a grpc-status number."""


class Reply:
    def __init__(self, status, body=None, headers=None):
        self.status, self.body, self.headers = status, body, headers or {}

    def data(self, index=0):
        return self.body[index]["data"]

    def errors(self, index=0):
        return self.body[index]["errors"]


class GraphQLServer:
    DEFAULTS = {
        "edge_limit": 5,             # HTTP requests per client per window, at the edge
        "max_batch": None,           # operations in one array body
        "limit_sensitive": False,    # at most one SENSITIVE_FIELDS field per request
        "login_attempt_limit": None,  # failed logins per account, counted in the resolver
        "max_depth": None,
        "max_cost": None,
        "max_page": None,
        "authz": "endpoint",         # endpoint | root | resolver
        "introspection": True,
        "suggestions": True,
        "strict_http": False,        # mutations only by POST with application/json
    }

    def __init__(self, **config):
        self.config = dict(self.DEFAULTS, **config)
        self.customers, self.bookings = fresh_data()
        self.sessions = {}
        self.passwords = {cid: secrets.token_hex(8) for cid in self.customers}
        self.edge_seen = {}
        self.login_attempts = 0
        self.failed_logins = {}
        self.calls = 0               # field resolutions, all requests

    def sign_in(self, customer_id):
        sid = secrets.token_hex(16)
        self.sessions[sid] = customer_id
        return sid

    # ---- the HTTP layer --------------------------------------------------
    def handle(self, method, content_type, payload, session=None, client="198.51.100.7"):
        cfg = self.config
        self.edge_seen[client] = self.edge_seen.get(client, 0) + 1
        if self.edge_seen[client] > cfg["edge_limit"]:
            return Reply(429)
        if method not in ("GET", "POST"):
            return Reply(405, headers={"Allow": "GET, POST"})
        if cfg["strict_http"] and method == "POST" and content_type != "application/json":
            return Reply(415)
        batch = payload if isinstance(payload, list) else [payload]
        if cfg["max_batch"] is not None and len(batch) > cfg["max_batch"]:
            return Reply(422, "batch of %d is over the limit" % len(batch))
        try:
            ops = [parse(item["query"]) for item in batch]
        except (ValueError, KeyError, TypeError):
            return Reply(400, "the document could not be parsed")
        if method == "GET" and cfg["strict_http"] and any(op.kind == "mutation" for op in ops):
            return Reply(405, headers={"Allow": "POST"})
        caller = self.sessions.get(session)
        public = all(op.kind == "mutation" and all(f.name == "login" for f in op.selections)
                     for op in ops)
        if caller is None and not public:
            return Reply(401)
        # Rules that run before any resolver does.
        for op in ops:
            problem = self.validate(op)
            if problem:
                return Reply(422, problem)
        if cfg["limit_sensitive"]:
            count = sum(1 for op in ops for f in all_fields(op.selections)
                        if f.name in SENSITIVE_FIELDS)
            if count > 1:
                return Reply(422, "%d sensitive fields in one request" % count)
        request_cost = 0                 # the budget is for the request, so a batch shares it
        for op in ops:
            if cfg["max_depth"] is not None and depth(op.selections) > cfg["max_depth"]:
                return Reply(422, "depth %d is over the limit" % depth(op.selections))
            if cfg["max_page"] is not None and any(
                    f.args.get("first", 0) > cfg["max_page"] for f in all_fields(op.selections)):
                return Reply(422, "first is over the page limit")
            root = "Mutation" if op.kind == "mutation" else "Query"
            request_cost += estimated_cost(root, op.selections)
            if cfg["max_cost"] is not None and request_cost > cfg["max_cost"]:
                return Reply(422, "estimated cost is over the budget")
        results = []
        for op in ops:
            errors = []
            root = "Mutation" if op.kind == "mutation" else "Query"
            data = self.select(root, None, op.selections, caller, errors, ())
            results.append({"data": data, "errors": errors})
        return Reply(200, results)

    def validate(self, op):
        def walk(type_name, selections):
            for f in selections:
                if type_name == "Query" and f.name == "__schema":
                    if not self.config["introspection"]:
                        return "introspection is disabled"
                    continue
                if f.name not in SCHEMA[type_name]:
                    message = 'Cannot query field "%s" on type "%s".' % (f.name, type_name)
                    near = difflib.get_close_matches(f.name, sorted(SCHEMA[type_name]), 1)
                    if near and self.config["suggestions"]:
                        message += ' Did you mean "%s"?' % near[0]
                    return message
                ret, _ = SCHEMA[type_name][f.name]
                first = f.args.get("first", 0)
                if not isinstance(first, int) or first < 0:
                    # A negative size would also make the cost estimate negative.
                    return 'Argument "first" must be a whole number, zero or more.'
                if (ret in SCHEMA) != bool(f.selections):
                    return 'Field "%s" has the wrong kind of selection.' % f.name
                problem = walk(ret, f.selections) if ret in SCHEMA else None
                if problem:
                    return problem
            return None
        return walk("Mutation" if op.kind == "mutation" else "Query", op.selections)

    # ---- execution ---------------------------------------------------------
    def select(self, type_name, parent, selections, caller, errors, path):
        out = {}
        for f in selections:
            self.calls += 1
            key = f.alias or f.name
            try:
                value = self.resolve(type_name, f.name, parent, f.args, caller)
            except Denied as reason:
                errors.append("%s: %s" % (".".join(path + (key,)), reason))
                out[key] = None
                continue
            if not f.selections or value is None or f.name == "__schema":
                out[key] = value
                continue
            ret, is_list = SCHEMA[type_name][f.name]
            here = path + (key,)
            if is_list:
                out[key] = [self.select(ret, v, f.selections, caller, errors, here) for v in value]
            else:
                out[key] = self.select(ret, value, f.selections, caller, errors, here)
        return out

    def resolve(self, type_name, name, parent, args, caller):
        """One resolver per field. `authz` decides which of them check."""
        authz = self.config["authz"]
        if type_name == "Query":
            if name == "__schema":
                return ["%s.%s" % (t, f) for t in SCHEMA for f in SCHEMA[t]]
            if name == "me":
                return self.customers[caller]
            booking = self.bookings.get(args.get("id"))
            if booking is None or (authz != "endpoint" and caller not in booking["travellers"]):
                raise Denied("booking not found")
            return booking
        if type_name == "Customer":
            if name in ("miles", "bookings") and authz == "resolver" and parent["id"] != caller:
                raise Denied("not authorized")
            if name == "bookings":
                mine = [b for b in self.bookings.values() if parent["id"] in b["travellers"]]
                return mine[:args.get("first", len(mine))]
            return parent[name]
        if type_name == "Booking":
            if authz == "resolver" and caller not in parent["travellers"]:
                raise Denied("not authorized")
            if name == "travellers":
                people = [self.customers[c] for c in parent["travellers"]]
                return people[:args.get("first", len(people))]
            return parent[name]
        return self.mutate(name, args, caller)

    def mutate(self, name, args, caller):
        if name == "login":
            account = args.get("username")
            limit = self.config["login_attempt_limit"]
            if limit is not None and self.failed_logins.get(account, 0) >= limit:
                raise Denied("too many attempts")
            self.login_attempts += 1
            known = self.passwords.get(account, "")
            if account in self.passwords and hmac.compare_digest(
                    str(args.get("password", "")).encode(), known.encode()):
                return self.sign_in(account)
            self.failed_logins[account] = self.failed_logins.get(account, 0) + 1
            raise Denied("invalid credentials")
        if name == "adjustMiles":
            # Function-level rule (Module 10). It is here in every configuration.
            if self.customers[caller]["role"] != "admin":
                raise Denied("not authorized")
            self.customers[args["customer"]]["miles"] += args["miles"]
            return self.customers[args["customer"]]["miles"]
        miles = args["miles"]                       # transferMiles
        if args["to"] not in self.customers or not 0 < miles <= self.customers[caller]["miles"]:
            raise Denied("transfer refused")
        self.customers[caller]["miles"] -= miles
        self.customers[args["to"]]["miles"] += miles
        return self.customers[caller]["miles"]


def nested_query(levels):
    """me { bookings { travellers { bookings { ... id } } } } with `levels`
    list fields below me. Depth is levels + 2."""
    names = ["bookings" if i % 2 == 0 else "travellers" for i in range(levels)]
    return "{ me { " + " { ".join(names) + " { id } " + "} " * levels + "}"


# ===========================================================================
# Part B model: gRPC
# ===========================================================================

GRPC_STATUS = {0: "OK", 4: "DEADLINE_EXCEEDED", 7: "PERMISSION_DENIED",
               8: "RESOURCE_EXHAUSTED", 12: "UNIMPLEMENTED", 16: "UNAUTHENTICATED"}
FIELD_NUMBERS = {"booking_id": 1, "customer_id": 2, "miles": 3, "query": 4, "document": 5}
FIELD_NAMES = {number: name for name, number in FIELD_NUMBERS.items()}
SVC = "/exampleair.bookings.v1.BookingService/"
ADMIN = "/exampleair.bookings.v1.BookingAdmin/"
REFLECTION = "/exampleair.lab.v1.Reflection/ListMethods"
METHOD_ROLES = {                    # methods missing from this table are refused
    SVC + "GetBooking": ("customer", "admin"),
    SVC + "SearchFlights": ("customer", "admin"),
    SVC + "UploadDocument": ("customer", "admin"),
    SVC + "ImportBookings": ("customer", "admin"),
    ADMIN + "AdjustMiles": ("admin",),
}
PUBLIC_METHODS = tuple(p for p in METHOD_ROLES if p.startswith(SVC))
STEP_MS = 100                       # one unit of handler work
LAB_CAP_STEPS = 600                 # the slow search needs 60 seconds of work
GRPC_LOG = []                       # (http status, grpc-status) of every call in Part B


def encode(message):
    """Tag, 4-byte length, value for each field, then the gRPC prefix: one
    byte for the compressed flag and a 4-byte big-endian message length."""
    body = b""
    for name, value in message.items():
        raw = value if isinstance(value, bytes) else str(value).encode()
        body += bytes([FIELD_NUMBERS[name]]) + len(raw).to_bytes(4, "big") + raw
    return b"\x00" + len(body).to_bytes(4, "big") + body


def decode(frame):
    body, out, pos = frame[5:], {}, 0
    while pos < len(body):
        size = int.from_bytes(body[pos + 1:pos + 5], "big")
        out[FIELD_NAMES[body[pos]]] = body[pos + 5:pos + 5 + size]
        pos += 5 + size
    return out


def json_edge(method, path, content_type, body, grpc_methods=None):
    """An edge filter written for the REST API. It allows listed routes and
    applies one body rule to JSON. To let gRPC through, an operator either
    added a prefix route (grpc_methods=None) or lists each method path."""
    if grpc_methods is None:
        routed = (method, path) == ("POST", "/v1/transfers") or path.startswith("/exampleair.")
    else:
        routed = (method, path) == ("POST", "/v1/transfers") or path in grpc_methods
    if not routed:
        return "block: no route"
    try:
        parsed = json.loads(body)
    except ValueError:
        return "pass: body is not JSON, not inspected"
    if isinstance(parsed, dict) and parsed.get("miles", 0) > 100000:
        return "block: body rule, miles over 100000"
    return "pass"


class GrpcReply:
    def __init__(self, code, message=None):
        self.http_status = 200          # HTTP-Status is ":status 200" for every reply
        self.trailers = {"grpc-status": str(code)}
        self.code, self.name, self.message = code, GRPC_STATUS[code], message
        GRPC_LOG.append((self.http_status, code))


class GrpcServer:
    DEFAULTS = {
        "authz": "none",               # none | method
        "object_check": False,
        "reflection": True,
        "honour_cancel": True,         # the handler checks whether its call was cancelled
        "default_deadline_ms": None,   # used when the caller sends no grpc-timeout, and a cap when it does
        "max_recv_bytes": None,
        "max_stream_messages": None,
    }

    def __init__(self, **config):
        self.config = dict(self.DEFAULTS, **config)
        self.customers, self.bookings = fresh_data()
        self.tokens = {}
        self.work_steps = 0
        self.accepted_messages = 0
        self.handlers = {
            SVC + "GetBooking": self.get_booking,
            SVC + "SearchFlights": self.search_flights,
            SVC + "UploadDocument": lambda *a: {"stored": True},
            SVC + "ImportBookings": lambda *a: {"imported": self.accepted_messages},
            ADMIN + "AdjustMiles": self.adjust_miles,
            ADMIN + "ExportCustomers": lambda *a: {"rows": len(self.customers)},
        }

    def token_for(self, customer_id):
        token = secrets.token_hex(16)
        self.tokens[token] = customer_id
        return token

    def call(self, path, metadata, frames):
        cfg = self.config
        frames = frames if isinstance(frames, list) else [frames]
        if path == REFLECTION and cfg["reflection"]:
            return GrpcReply(0, sorted(self.handlers))
        if path not in self.handlers:
            return GrpcReply(12)
        # Size and count limits run on the length prefix, before any decoding.
        self.accepted_messages = 0
        for frame in frames:
            if cfg["max_recv_bytes"] is not None and \
                    int.from_bytes(frame[1:5], "big") > cfg["max_recv_bytes"]:
                return GrpcReply(8)
            if cfg["max_stream_messages"] is not None and \
                    self.accepted_messages >= cfg["max_stream_messages"]:
                return GrpcReply(8)
            self.accepted_messages += 1
        # Interceptor 1: authentication, from call credentials in metadata.
        scheme, _, token = metadata.get("authorization", "").partition(" ")
        caller = self.tokens.get(token) if scheme == "Bearer" else None
        if caller is None:
            return GrpcReply(16)
        # Interceptor 2: authorization per method, deny by default.
        if cfg["authz"] == "method" and \
                self.customers[caller]["role"] not in METHOD_ROLES.get(path, ()):
            return GrpcReply(7)
        deadline_ms = cfg["default_deadline_ms"]
        if "grpc-timeout" in metadata:                  # for example "1S" or "500m"
            value, unit = int(metadata["grpc-timeout"][:-1]), metadata["grpc-timeout"][-1]
            asked_ms = value * {"S": 1000, "m": 1}[unit]
            # A caller cannot ask for longer than the server's own maximum.
            deadline_ms = asked_ms if deadline_ms is None else min(asked_ms, deadline_ms)
        try:
            return GrpcReply(0, self.handlers[path](decode(frames[0]), caller, deadline_ms))
        except Denied as status:
            return GrpcReply(int(str(status)))

    def get_booking(self, message, caller, deadline_ms):
        booking = self.bookings.get(message["booking_id"].decode())
        if booking is None or (self.config["object_check"] and caller not in booking["travellers"]):
            raise Denied(7)
        return {"passenger": booking["passenger"]}

    def adjust_miles(self, message, caller, deadline_ms):
        target = message["customer_id"].decode()
        self.customers[target]["miles"] += int(message["miles"])
        return {"miles": self.customers[target]["miles"]}

    def search_flights(self, message, caller, deadline_ms):
        """Needs LAB_CAP_STEPS steps. The caller stops waiting at the
        deadline whatever the handler does; the handler stops only if it
        looks."""
        self.work_steps = 0
        for step in range(LAB_CAP_STEPS):
            if self.config["honour_cancel"] and deadline_ms is not None \
                    and step * STEP_MS >= deadline_ms:
                break
            self.work_steps += 1
        if deadline_ms is not None and LAB_CAP_STEPS * STEP_MS > deadline_ms:
            raise Denied(4)
        return {"flights": 3}


# ===========================================================================
# Part C model: WebSocket
# ===========================================================================

APP_ORIGIN = "https://app.exampleair.example"
WS_HOST = "api.exampleair.example"
WS_URL = "wss://" + WS_HOST + "/live"


def site_of(host):
    return ".".join(host.split(".")[-2:])


def mask(payload, key):
    """RFC 6455 section 5.3: octet i is XORed with octet i mod 4 of the key.
    The same steps mask and unmask."""
    return bytes(b ^ key[i % 4] for i, b in enumerate(payload))


class Handshake:
    def __init__(self, url, headers, client):
        self.scheme, _, rest = url.partition("://")
        self.host, _, path = rest.partition("/")
        self.path, self.headers, self.client = "/" + path, headers, client


class Browser:
    """Attaches the cookie for a host to a WebSocket handshake to that host,
    whichever page opened it. A SameSite=Lax cookie is left out when the
    page is on another site."""

    def __init__(self, client="203.0.113.20"):
        self.jar, self.client = {}, client

    def set_cookie(self, host, value, samesite="None"):
        self.jar[host] = (value, samesite)

    def handshake(self, page_origin, url):
        hs = Handshake(url, {"Upgrade": "websocket", "Connection": "Upgrade",
                             "Sec-WebSocket-Version": "13", "Origin": page_origin}, self.client)
        hs.headers["Host"] = hs.host
        if hs.host in self.jar:
            value, samesite = self.jar[hs.host]
            page_host = page_origin.partition("://")[2]
            if samesite == "None" or site_of(page_host) == site_of(hs.host):
                hs.headers["Cookie"] = "sid=" + value
        return hs

    def fetch_ticket(self, page_origin, server):
        """The app's page asks an HTTPS endpoint for a one-time ticket. A
        page on another origin can make the browser send that request, but
        cannot read the reply (Module 17), so it gets nothing."""
        if page_origin != APP_ORIGIN or WS_HOST not in self.jar:
            return None
        return server.issue_ticket(self.jar[WS_HOST][0])


class Connection:
    def __init__(self, sid, customer, now):
        self.sid, self.customer, self.last_check = sid, customer, now
        self.open, self.close_code, self.ticket_ok = True, None, False
        self.times, self.fragments, self.buffered = [], 0, 0
        self.mid_message = False         # True between a first fragment and the final one

    def close(self, code):
        self.open, self.close_code = False, code
        return None


class WsServer:
    DEFAULTS = {
        "origins": None,               # tuple of allowed Origin values, or None for no check
        "ticket": False,               # first message must carry a one-time ticket
        "authz": "handshake",          # handshake | message
        "recheck": None,               # None | "message" | seconds between session checks
        "handshake_limit": 5,          # handshakes per client per window
        "message_limit": None,         # messages per connection per 60 seconds
        "max_frame": None,
        "max_message": None,
        "bound_inflate": False,        # apply max_message while decompressing
        "log_messages": False,
        "plain_listener": True,        # answer ws:// as well as wss://
    }

    def __init__(self, **config):
        self.config = dict(self.DEFAULTS, **config)
        self.customers, self.bookings = fresh_data()
        self.sessions, self.tickets, self.handshakes = {}, {}, {}
        self.access_log, self.event_log = [], []
        self.processed = 0

    def sign_in(self, customer_id):
        sid = secrets.token_hex(16)
        self.sessions[sid] = customer_id
        return sid

    def issue_ticket(self, sid):
        if sid not in self.sessions:
            return None
        ticket = secrets.token_hex(16)
        self.tickets[ticket] = sid
        return ticket

    def handshake(self, hs, now=0):
        cfg = self.config
        if hs.scheme != "wss" and not cfg["plain_listener"]:
            return "connection refused", None
        self.access_log.append("GET %s Upgrade" % hs.path)
        self.handshakes[hs.client] = self.handshakes.get(hs.client, 0) + 1
        if self.handshakes[hs.client] > cfg["handshake_limit"]:
            return 429, None
        if hs.headers.get("Upgrade", "").lower() != "websocket":
            return 400, None
        if cfg["origins"] is not None and hs.headers.get("Origin") not in cfg["origins"]:
            return 403, None
        sid = hs.headers.get("Cookie", "").partition("sid=")[2]
        if sid not in self.sessions:
            return 401, None
        return 101, Connection(sid, self.sessions[sid], now)

    def frame(self, conn, declared, payload, fin=True, compressed=False):
        """Size rules read the declared length before the payload is kept."""
        cfg = self.config
        if not conn.open:
            return None
        if not conn.mid_message:         # the counts are per message, not per connection
            conn.fragments, conn.buffered = 0, 0
        if cfg["max_frame"] is not None and declared > cfg["max_frame"]:
            return conn.close(1009)
        conn.buffered += declared
        conn.fragments += 1
        if cfg["max_message"] is not None and conn.buffered > cfg["max_message"]:
            return conn.close(1009)
        conn.mid_message = not fin
        if not fin:
            return "buffering"
        if compressed:
            inflater = zlib.decompressobj(wbits=-15)
            if cfg["bound_inflate"]:
                payload = inflater.decompress(payload, cfg["max_message"] + 1)
                conn.buffered = len(payload)
                if len(payload) > cfg["max_message"]:
                    return conn.close(1009)
            else:
                payload = inflater.decompress(payload)
                conn.buffered = len(payload)
        return "accepted"

    def message(self, conn, text, now=0):
        cfg = self.config
        if not conn.open:
            return None
        if cfg["recheck"] == "message" or (
                cfg["recheck"] is not None and now - conn.last_check >= cfg["recheck"]):
            conn.last_check = now
            if conn.sid not in self.sessions:
                return conn.close(1008)
        conn.times = [t for t in conn.times if now - t < 60] + [now]
        if cfg["message_limit"] is not None and len(conn.times) > cfg["message_limit"]:
            return conn.close(1008)
        try:
            msg = json.loads(text)
            action = msg["action"]
        except (ValueError, KeyError, TypeError):
            return conn.close(1008)
        if cfg["ticket"] and not conn.ticket_ok:
            # Until the ticket is verified, only the auth message is accepted.
            if action == "auth" and self.tickets.pop(msg.get("ticket"), None) == conn.sid:
                conn.ticket_ok = True
                return {"ok": True}
            return conn.close(1008)
        self.processed += 1
        if cfg["log_messages"]:
            self.event_log.append((conn.customer, action))
        if action == "get_booking":
            booking = self.bookings.get(msg.get("id"))
            if booking is None or (cfg["authz"] == "message"
                                   and conn.customer not in booking["travellers"]):
                return {"error": "not found"}
            return {"passenger": booking["passenger"]}
        if action == "ping":
            return {"pong": True}
        return {"error": "unknown action"}


# ===========================================================================
# The run
# ===========================================================================

def main():
    print("hosts use the reserved .example domain; no request leaves this process")

    # ---------------- Part A: GraphQL -------------------------------------
    section("Part A: GraphQL. One endpoint, one method, many operations in a request.")
    guesses = [secrets.token_hex(8) for _ in range(50)]

    def victim_server(**config):
        server = GraphQLServer(**config)
        server.passwords["c-ben"] = guesses[36]          # the 37th guess is right
        return server

    def aliased(batch):
        return "mutation { " + " ".join(
            'a%d: login(username: "c-ben", password: "%s")' % (i, g)
            for i, g in enumerate(batch)) + " }"

    def got_session(reply):
        return reply.status == 200 and any(
            v is not None for item in reply.body for v in item["data"].values())

    def post(server, payload, session=None):
        return server.handle("POST", "application/json", payload, session=session)

    gql = victim_server()
    replies = [post(gql, {"query": aliased([g])}) for g in guesses]
    record("50 login guesses as 50 requests: requests past the edge limiter, attempts run",
           (5, 5), (sum(1 for r in replies if r.status != 429), gql.login_attempts))
    gql = victim_server()
    reply = post(gql, {"query": aliased(guesses)})
    record("the same guesses as 50 aliases in one request: status, requests the edge counted",
           (200, 1), (reply.status, gql.edge_seen["198.51.100.7"]))
    record("  login attempts run, and whether the attacker got the victim's session",
           (50, True), (gql.login_attempts, got_session(reply)))
    gql = victim_server()
    post(gql, [{"query": aliased([g])} for g in guesses])
    record("the same guesses as an array of 50 operations: requests counted, attempts run",
           (1, 50), (gql.edge_seen["198.51.100.7"], gql.login_attempts))
    gql = victim_server(limit_sensitive=True)
    reply = post(gql, {"query": aliased(guesses)})
    record("with at most one login field per request: status, attempts run",
           (422, 0), (reply.status, gql.login_attempts))
    gql = victim_server(max_batch=10)                # this limit alone, on a fresh server
    reply = post(gql, [{"query": aliased([g])} for g in guesses])
    record("  and the array of 50 against a batch limit of 10: status, attempts run",
           (422, 0), (reply.status, gql.login_attempts))
    gql = victim_server(login_attempt_limit=5)
    reply = post(gql, {"query": aliased(guesses)})
    record("with failed logins counted per account in the resolver: attempts run, session",
           (5, False), (gql.login_attempts, got_session(reply)))

    def as_ana(query, **config):
        server = GraphQLServer(**config)
        reply = post(server, {"query": query}, server.sign_in("c-ana"))
        reply.calls = server.calls
        return reply

    record("field resolutions for a query nested 2, 4, 6 and 8 levels below me",
           [19, 228, 2843, 35584], [as_ana(nested_query(n)).calls for n in (2, 4, 6, 8)])
    deep = parse(nested_query(8))
    record("  the 8-level query: depth, and estimated cost at 10 items per list",
           (10, 111111112), (depth(deep.selections), estimated_cost("Query", deep.selections)))
    reply = as_ana(nested_query(8), max_depth=5)
    record("  with a depth limit of 5: status, field resolutions",
           (422, 0), (reply.status, reply.calls))
    reply = as_ana(nested_query(8), max_cost=1000)
    record("  with a cost budget of 1000 and no depth limit: status, field resolutions",
           (422, 0), (reply.status, reply.calls))
    reply = as_ana(nested_query(2), max_depth=5, max_cost=1000)
    record("  the 2-level query under both limits: status, field resolutions",
           (200, 19), (reply.status, reply.calls))
    wide = "{ me { bookings(first: 1000000) { id } } }"
    record("a depth 3 query with first: 1000000: under the depth limit, under a page limit of 50",
           (200, 422), (as_ana(wide, max_depth=5).status,
                        as_ana(wide, max_depth=5, max_page=50).status))

    direct = '{ booking(id: "BK2001") { passenger } }'
    walk = "{ me { bookings(first: 2) { id travellers { name miles bookings { id } } } } }"

    def ben_in(reply):
        """What the reply shows of Ben through the group booking BK3001."""
        ben = reply.data()["me"]["bookings"][1]["travellers"][1]
        return ben["name"], ben["miles"], ben["bookings"] and [b["id"] for b in ben["bookings"]]

    record("no session, any query: HTTP status", 401, post(GraphQLServer(), {"query": direct}).status)
    record("Ana asks for Ben's booking by id, check at the endpoint only",
           {"booking": {"passenger": "Ben Okafor"}}, as_ana(direct).data())
    reply = as_ana(direct, authz="root")
    record("  with an ownership check in the root resolver: HTTP status, data, errors",
           (200, {"booking": None}, ["booking: booking not found"]),
           (reply.status, reply.data(), reply.errors()))
    record("Ana walks from her group booking to Ben, root check only: name, miles, bookings",
           ("Ben Okafor", 97000, ["BK2001", "BK3001", "BK3002", "BK3003"]),
           ben_in(as_ana(walk, authz="root")))
    reply = as_ana(walk, authz="resolver")
    record("  with checks in the Customer and Booking resolvers, and the errors in the reply",
           (("Ben Okafor", None, None), 6), (ben_in(reply), len(reply.errors())))

    reply = as_ana("{ __schema }")
    record("introspection on: Mutation fields in the reply",
           ["Mutation.login", "Mutation.transferMiles", "Mutation.adjustMiles"],
           [n for n in reply.data()["__schema"] if n.startswith("Mutation.")])
    reply = as_ana("{ __schema }", introspection=False)
    record("introspection off: status and message",
           (422, "introspection is disabled"), (reply.status, reply.body))
    typo = 'mutation { adjustMile(customer: "c-ana", miles: 5) }'
    record("  a misspelled field, introspection off, suggestions on",
           'Cannot query field "adjustMile" on type "Mutation". Did you mean "adjustMiles"?',
           as_ana(typo, introspection=False).body)
    record("  suggestions off", 'Cannot query field "adjustMile" on type "Mutation".',
           as_ana(typo, introspection=False, suggestions=False).body)
    reply = as_ana('mutation { adjustMiles(customer: "c-ana", miles: 5) }',
                   introspection=False, suggestions=False)
    record("  the hidden field called by its exact name, by a customer",
           ["adjustMiles: not authorized"], reply.errors())

    transfer = 'mutation { transferMiles(to: "c-ben", miles: 40000) }'

    def forged(method, content_type, **config):
        """A request a page on another site makes the victim's browser send.
        The browser attaches Ana's session cookie. Returns the status and
        Ana's miles afterwards."""
        server = GraphQLServer(**config)
        sid = server.sign_in("c-ana")
        if not sent_without_preflight(method, content_type):
            return "preflight first", server.customers["c-ana"]["miles"]
        reply = server.handle(method, content_type, {"query": transfer}, session=sid)
        return reply.status, server.customers["c-ana"]["miles"]

    form = "application/x-www-form-urlencoded"
    record("a cross-site GET, then a cross-site form post, that carry a mutation",
           [(200, 2000), (200, 2000)], [forged("GET", None), forged("POST", form)])
    record("  with mutations only by POST and only as application/json",
           [(405, 42000), (415, 42000)],
           [forged("GET", None, strict_http=True), forged("POST", form, strict_http=True)])
    record("  a cross-site POST with application/json",
           ("preflight first", 42000), forged("POST", "application/json", strict_http=True))
    server = GraphQLServer(strict_http=True)
    reply = post(server, {"query": transfer}, server.sign_in("c-ana"))
    record("  the app's own POST with application/json still works",
           (200, 2000), (reply.status, server.customers["c-ana"]["miles"]))

    # ---------------- Part B: gRPC ----------------------------------------
    section("Part B: gRPC. One POST path per method, a binary body, status in a trailer.")
    rest_body = json.dumps({"to": "c-ben", "miles": 900000}).encode()
    grpc_body = encode({"customer_id": "c-ben", "miles": 900000})
    grpc_type = "application/grpc+proto"
    record("edge filter, REST transfer of 900000 miles",
           "block: body rule, miles over 100000",
           json_edge("POST", "/v1/transfers", "application/json", rest_body))
    record("  the same change as a gRPC call to BookingAdmin/AdjustMiles",
           "pass: body is not JSON, not inspected",
           json_edge("POST", ADMIN + "AdjustMiles", grpc_type, grpc_body))
    record("  with the public methods listed one by one: AdjustMiles, then GetBooking",
           ["block: no route", "pass: body is not JSON, not inspected"],
           [json_edge("POST", ADMIN + "AdjustMiles", grpc_type, grpc_body, PUBLIC_METHODS),
            json_edge("POST", SVC + "GetBooking", grpc_type, encode({"booking_id": "BK1001"}),
                      PUBLIC_METHODS)])

    def grpc_as(customer, path, message, metadata=None, **config):
        server = GrpcServer(**config)
        meta = dict(metadata or {}, authorization="Bearer " + server.token_for(customer))
        return server, server.call(path, meta, encode(message))

    reply = GrpcServer().call(SVC + "GetBooking", {}, encode({"booking_id": "BK1001"}))
    record("a call with no token in metadata: HTTP status, grpc-status",
           (200, "UNAUTHENTICATED"), (reply.http_status, reply.name))
    adjust = {"customer_id": "c-ana", "miles": 500000}
    server, reply = grpc_as("c-ana", ADMIN + "AdjustMiles", adjust)
    record("a customer calls BookingAdmin/AdjustMiles, interceptor authenticates only",
           ("OK", 542000), (reply.name, server.customers["c-ana"]["miles"]))
    server, reply = grpc_as("c-ana", ADMIN + "AdjustMiles", adjust, authz="method")
    record("  with per-method authorization: the customer, her miles, then an operator",
           ("PERMISSION_DENIED", 42000, "OK"),
           (reply.name, server.customers["c-ana"]["miles"],
            grpc_as("ops-1", ADMIN + "AdjustMiles", adjust, authz="method")[1].name))
    record("  a method missing from the authorization table, called by an operator",
           "PERMISSION_DENIED",
           grpc_as("ops-1", ADMIN + "ExportCustomers", {}, authz="method")[1].name)
    server, reply = grpc_as("c-ana", SVC + "GetBooking", {"booking_id": "BK2001"}, authz="method")
    record("Ana calls GetBooking for Ben's booking, method rule only",
           ("OK", {"passenger": "Ben Okafor"}), (reply.name, reply.message))
    record("  with the ownership check in the handler", "PERMISSION_DENIED",
           grpc_as("c-ana", SVC + "GetBooking", {"booking_id": "BK2001"},
                   authz="method", object_check=True)[1].name)

    reply = GrpcServer().call(REFLECTION, {}, encode({}))
    record("reflection on, no token: admin methods in the list",
           ["AdjustMiles", "ExportCustomers"],
           [p.rpartition("/")[2] for p in reply.message if p.startswith(ADMIN)])
    record("reflection off: the list, then AdjustMiles called by path with no authorization",
           ("UNIMPLEMENTED", "OK"),
           (GrpcServer(reflection=False).call(REFLECTION, {}, encode({})).name,
            grpc_as("c-ana", ADMIN + "AdjustMiles", adjust, reflection=False)[1].name))

    def search(metadata=None, **config):
        server, reply = grpc_as("c-ana", SVC + "SearchFlights", {"query": "LIS"}, metadata,
                                authz="method", **config)
        return reply.name, server.work_steps

    record("slow search, no deadline: grpc-status, work steps of 100 ms",
           ("OK", 600), search())
    record("  grpc-timeout 1S, handler checks for cancellation",
           ("DEADLINE_EXCEEDED", 10), search({"grpc-timeout": "1S"}))
    record("  grpc-timeout 1S, handler never checks",
           ("DEADLINE_EXCEEDED", 600), search({"grpc-timeout": "1S"}, honour_cancel=False))
    record("  no grpc-timeout, server default of 5 seconds",
           ("DEADLINE_EXCEEDED", 50), search(default_deadline_ms=5000))

    four_mib = 4 * 1024 * 1024
    big = {"document": b"\x00" * four_mib}
    record("a message over 4 MiB: no receive limit, then a 4 MiB receive limit",
           ("OK", "RESOURCE_EXHAUSTED"),
           (grpc_as("c-ana", SVC + "UploadDocument", big, authz="method")[1].name,
            grpc_as("c-ana", SVC + "UploadDocument", big, authz="method",
                    max_recv_bytes=four_mib)[1].name))

    def stream(**config):
        server = GrpcServer(authz="method", max_recv_bytes=four_mib, **config)
        meta = {"authorization": "Bearer " + server.token_for("c-ana")}
        reply = server.call(SVC + "ImportBookings", meta,
                            [encode({"booking_id": "BK%04d" % i}) for i in range(1000)])
        return reply.name, server.accepted_messages

    record("a stream of 1000 small messages under that limit: status, messages accepted",
           ("OK", 1000), stream())
    record("  with at most 100 messages per stream",
           ("RESOURCE_EXHAUSTED", 100), stream(max_stream_messages=100))

    record("calls made in Part B, and how many had an HTTP status of 400 or above",
           (18, 0), (len(GRPC_LOG), sum(1 for http, _ in GRPC_LOG if http >= 400)))
    failed = [code for _, code in GRPC_LOG if code != 0]
    record("  the same calls counted by grpc-status",
           ["DEADLINE_EXCEEDED x3", "PERMISSION_DENIED x3", "RESOURCE_EXHAUSTED x2",
            "UNIMPLEMENTED x1", "UNAUTHENTICATED x1"],
           ["%s x%d" % (GRPC_STATUS[c], failed.count(c)) for c in sorted(set(failed))])

    # ---------------- Part C: WebSocket -----------------------------------
    section("Part C: WebSocket. One HTTP handshake, then messages that are not requests.")
    evil = "https://offers.evil.example"

    def ws_setup(samesite="None", **config):
        server = WsServer(**config)
        browser = Browser()
        browser.set_cookie(WS_HOST, server.sign_in("c-ana"), samesite)
        return server, browser

    def status_from(server, browser, page_origin):
        return server.handshake(browser.handshake(page_origin, WS_URL))[0]

    get_own = json.dumps({"action": "get_booking", "id": "BK1001"})
    get_ben = json.dumps({"action": "get_booking", "id": "BK2001"})

    server, browser = ws_setup()
    record("the app's page opens the socket: handshake status", 101,
           status_from(server, browser, APP_ORIGIN))
    hs = browser.handshake(evil, WS_URL)
    status, conn = server.handshake(hs)
    record("a page on another site opens it: Origin sent, cookie attached, status",
           (evil, True, 101), (hs.headers["Origin"], "Cookie" in hs.headers, status))
    record("  what that page reads from Ana's socket",
           {"passenger": "Ana Rivera"}, server.message(conn, get_own))
    server, browser = ws_setup(origins=(APP_ORIGIN,))
    bare = browser.handshake(APP_ORIGIN, WS_URL)
    del bare.headers["Origin"]                       # the cookie is attached, the header is not
    record("  with an Origin allowlist: the other site, a lookalike, no Origin, the app's page",
           (403, 403, 403, 101),
           (status_from(server, browser, evil),
            status_from(server, browser, APP_ORIGIN + ".evil.example"),
            server.handshake(bare)[0], status_from(server, browser, APP_ORIGIN)))
    script = Handshake(WS_URL, {"Upgrade": "websocket", "Origin": APP_ORIGIN, "Host": WS_HOST},
                       "198.51.100.7")
    record("  a script that forges the Origin header and has no cookie", 401,
           server.handshake(script)[0])
    server, browser = ws_setup(ticket=True)
    status, conn = server.handshake(browser.handshake(evil, WS_URL))
    record("no Origin check, ticket required: other site's handshake, ticket it could read",
           (101, None), (status, browser.fetch_ticket(evil, server)))
    guess = server.handshake(browser.handshake(evil, WS_URL))[1]
    server.message(guess, json.dumps({"action": "auth", "ticket": secrets.token_hex(16)}))
    record("  its first message asks for data, or carries a made-up ticket: reply, close codes",
           (None, 1008, 1008), (server.message(conn, get_own), conn.close_code, guess.close_code))
    status, conn = server.handshake(browser.handshake(APP_ORIGIN, WS_URL))
    ticket = browser.fetch_ticket(APP_ORIGIN, server)
    first = server.message(conn, json.dumps({"action": "auth", "ticket": ticket}))
    record("  the app's page sends its ticket, then asks",
           ({"ok": True}, {"passenger": "Ana Rivera"}), (first, server.message(conn, get_own)))
    server, browser = ws_setup(samesite="Lax")
    record("cookie-only server, SameSite=Lax cookie: another site, then a sibling host",
           (401, 101), (status_from(server, browser, evil),
                        status_from(server, browser, "https://promo.exampleair.example")))

    def ana_socket(**config):
        server, browser = ws_setup(origins=(APP_ORIGIN,), **config)
        return server, server.handshake(browser.handshake(APP_ORIGIN, WS_URL))[1]

    server, conn = ana_socket()
    record("Ana's own socket asks for Ben's booking, authorized at the handshake only",
           {"passenger": "Ben Okafor"}, server.message(conn, get_ben))
    server, conn = ana_socket(authz="message")
    record("  with an ownership check on every message: reply, socket still open",
           ({"error": "not found"}, True), (server.message(conn, get_ben), conn.open))

    def after_logout(recheck, asked_at):
        server, conn = ana_socket(authz="message", recheck=recheck)
        del server.sessions[conn.sid]                # Ana logs out at t = 100
        reply = server.message(conn, get_own, now=asked_at)
        return reply, conn.close_code

    record("Ana logs out at t=100. A message at t=160, session never checked again",
           ({"passenger": "Ana Rivera"}, None), after_logout(None, 160))
    record("  session checked on every message", (None, 1008), after_logout("message", 160))
    record("  session checked every 1800 seconds: close code at t=160, at t=1900",
           (None, 1008), (after_logout(1800, 160)[1], after_logout(1800, 1900)[1]))

    def flood(**config):
        server, conn = ana_socket(authz="message", **config)
        for _ in range(1000):
            server.message(conn, json.dumps({"action": "ping"}), now=10)
        return server.handshakes["203.0.113.20"], server.processed, conn.close_code

    record("1000 messages on one socket: handshakes counted, messages processed, close code",
           (1, 1000, None), flood())
    record("  with 100 messages per minute per connection",
           (1, 100, 1008), flood(message_limit=100))
    server, conn = ana_socket(authz="message", log_messages=True)
    for _ in range(3):
        server.message(conn, get_ben)
    record("a socket that sent 3 messages: HTTP access log lines, application message events",
           (1, 3), (len(server.access_log), len(server.event_log)))

    kib = 1024
    limits = {"max_frame": 64 * kib, "max_message": 64 * kib}

    def one_frame(declared, **config):
        server, conn = ana_socket(**config)
        return server.frame(conn, declared, b""), conn.buffered, conn.close_code

    record("a frame that declares 1 MiB, no limit: result, bytes buffered, close code",
           ("accepted", 1048576, None), one_frame(1024 * kib))
    record("  with a 64 KiB frame limit", (None, 0, 1009), one_frame(1024 * kib, **limits))

    def fragments(**config):
        server, conn = ana_socket(**config)
        for i in range(100):
            server.frame(conn, kib, b"", fin=(i == 99))
        return conn.fragments, conn.close_code

    record("100 fragments of 1 KiB under the frame limit alone: fragments taken, close code",
           (100, None), fragments(max_frame=64 * kib))
    record("  with a 64 KiB message limit as well", (65, 1009), fragments(**limits))
    deflater = zlib.compressobj(wbits=-15)
    squeezed = deflater.compress(b"\x00" * (1024 * kib)) + deflater.flush()
    server, conn = ana_socket(**limits)
    result = server.frame(conn, len(squeezed), squeezed, compressed=True)
    record("a compressed frame under both limits: result, bytes after inflating",
           (True, "accepted", 1048576), (len(squeezed) < 64 * kib, result, conn.buffered))
    server, conn = ana_socket(bound_inflate=True, **limits)
    server.frame(conn, len(squeezed), squeezed, compressed=True)
    record("  with the message limit applied while inflating: bytes inflated, close code",
           (65537, 1009), (conn.buffered, conn.close_code))

    server, browser = ws_setup(origins=(APP_ORIGIN,), plain_listener=False)
    record("a handshake to the ws:// URL when only wss:// is served", "connection refused",
           server.handshake(browser.handshake(APP_ORIGIN, WS_URL.replace("wss", "ws", 1)))[0])
    key, payload = secrets.token_bytes(4), get_own.encode()
    captured = (key, mask(payload, key))             # the key travels in the frame
    differs = captured[1] != payload or not any(key)     # an all-zero key masks nothing
    record("a captured masked frame, unmasked with the key it carries, is the message",
           True, differs and mask(captured[1], captured[0]) == payload)

    width = max(len(label) for label, _, _ in RESULTS if label is not None)
    for label, expected, actual in RESULTS:
        if label is None:
            print()
            print(expected)
            continue
        print("%-*s %s" % (width + 1, label, actual))

    failures = [r for r in RESULTS if r[0] is not None and r[2] != r[1]]
    print()
    if failures:
        for label, expected, actual in failures:
            print("FAILED %s: expected %r, got %r" % (label, expected, actual))
        return 1
    print("all %d lab checks passed" % CHECKS)
    return 0


if __name__ == "__main__":
    sys.exit(main())
