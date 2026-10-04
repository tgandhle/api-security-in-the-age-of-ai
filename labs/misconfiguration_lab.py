#!/usr/bin/env python3
"""Module 29 lab: security misconfiguration.

The same application code runs in every part of this lab. Only the
configuration dict changes, and that is the point: the code can be correct
and the deployment still wrong.

  Part A  a default install. An auditor probes it and every probe finds
          something: an error page with a stack trace, a method nobody
          needs, a debug endpoint, a default account, a cacheable response
          with personal data, a plain HTTP listener, old TLS versions, an
          unpatched component, and an error that fails open.
  Part B  the hardened configuration. The same probes find nothing, and
          legitimate requests still work.
  Part C  drift. Two environments built from the same baseline, one manual
          change, and why comparing two environments is not an audit.
  Part D  what a redirect and HSTS do for a client that is not a browser.
  Part E  two servers in a chain that disagree about what a path is.

Nothing here opens a socket. The API is a Python object, the listeners are
strings, and "TLS" is a tuple of version names and a tuple of cipher suite
names compared against what the RFCs say. No handshake is performed.

Deliberate simplifications:

  * The leaked error page is built from fixed strings so that it is the same
    on every machine. It is not a real traceback.
  * Correlation ids are a counter (req-0001). A real service uses a random id.
  * Tokens and the operator's secret are random per run and never printed.
    The vendor's default account is a placeholder pair, not a real default.
  * Responses carry only the headers this module is about. A real 401 also
    carries WWW-Authenticate (RFC 9110 section 15.5.2); the lab's does not.
  * BrowserLikeAgent implements two behaviours from RFC 6797: noting a host
    from a header received over secure transport (section 8.1) and rewriting
    http to https for a noted host (section 8.3). It does not follow
    redirects. includeSubDomains, max-age=0, preloaded lists and
    certificate errors are not modelled.
  * The cipher suite rules match on name prefixes, which covers the suites
    used here. RFC 10015 lists the affected suites one by one in section 5.

Python 3, standard library only. Exit codes: 0 all checks matched, 1 a check
did not match.
"""

import hmac
import json
import re
import secrets
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
# Configuration. Every security decision the API makes is read from here.
# ---------------------------------------------------------------------------

DEFAULT_INSTALL = {
    "hostname": "api.examplehotels.example",
    "debug_errors": True,              # error pages show the debug text
    "server_banner": "full",           # Server: product/version
    "method_policy": "framework",      # every method the framework implements
    "route_methods": {},
    "trace_enabled": True,
    "debug_endpoints": True,
    "sample_content": True,
    "default_account_enabled": True,
    "management_listener": "public-https",
    "cache_control": None,
    "nosniff": False,
    "http_listener": "serve",          # serve, redirect or off
    "hsts_max_age": None,
    "tls_versions": ("TLS1.0", "TLS1.1", "TLS1.2"),
    "tls12_cipher_suites": ("TLS_RSA_WITH_AES_128_CBC_SHA",
                            "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
                            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
    "on_auth_error": "allow",          # allow or deny
    "components": {"ExampleServe": "4.2.1"},
}

HARDENED = {
    "hostname": "api.examplehotels.example",
    "debug_errors": False,
    "server_banner": "none",
    "method_policy": "allowlist",
    "route_methods": {"/v1/bookings/{id}": ("GET", "HEAD")},
    "trace_enabled": False,
    "debug_endpoints": False,
    "sample_content": False,
    "default_account_enabled": False,
    "management_listener": "internal-mgmt",
    "cache_control": "no-store",
    "nosniff": True,
    "http_listener": "off",
    "hsts_max_age": 31536000,
    "tls_versions": ("TLS1.2", "TLS1.3"),
    "tls12_cipher_suites": ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"),
    "on_auth_error": "deny",
    "components": {"ExampleServe": "4.2.7"},
}

# Settings that are meant to differ between environments. Everything else is
# meant to be identical.
PER_ENVIRONMENT_KEYS = ("hostname",)

# The account the fictional product ships with. It is in the vendor's public
# documentation, which is what makes it a finding and not a secret. The pair
# is a placeholder: this lab does not print or use any real product's default.
DEFAULT_ACCOUNT = ("<vendor-default-user>", "<vendor-default-password>")

# What this framework implements: the methods RFC 9110 section 9.1 lists,
# less CONNECT, plus PATCH, which RFC 9110 does not define.
KNOWN_METHODS = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS",
                 "TRACE")

TLS_ORDER = ("SSLv2", "SSLv3", "TLS1.0", "TLS1.1", "TLS1.2", "TLS1.3")

# RFC 9325 section 3.1.1: implementations MUST NOT negotiate these four.
# RFC 8996 sections 4 and 5 say the same of TLS 1.0 and TLS 1.1.
FORBIDDEN_TLS_VERSIONS = ("SSLv2", "SSLv3", "TLS1.0", "TLS1.1")

# TLS 1.2 key exchanges RFC 10015 forbids: static RSA (section 4), ephemeral
# finite field DH (section 3) and non-ephemeral finite field DH (section 2).
# NULL and RC4 are forbidden by RFC 9325 section 4.1.
FORBIDDEN_SUITE_PREFIXES = ("TLS_RSA_WITH_", "TLS_DHE_", "TLS_DH_")
FORBIDDEN_SUITE_PARTS = ("_NULL_", "_RC4_")

# First fixed version of each component, from the fictional vendor advisory.
ADVISORIES = {"ExampleServe": "4.2.7"}


class Response:
    def __init__(self, status, headers=None, body=""):
        self.status = status
        self.headers = dict(headers or {})
        self.body = body

    def header(self, name):
        return self.headers.get(name)


# What a client gets when nothing is listening. No request is ever sent.
REFUSED = Response("connection refused")


def collapse_slashes(path):
    return re.sub(r"/{2,}", "/", path)


class Api:
    """ExampleHotels' booking API. The company is fictional."""

    def __init__(self, config):
        self.cfg = dict(config)
        self.bookings = {
            1001: {"guest": "A. Guest", "email": "a.guest@mail.example",
                   "room": 412},
            1002: {"guest": "B. Guest", "email": "b.guest@mail.example",
                   "room": 118},
        }
        self.guest_token = secrets.token_urlsafe(16)
        self.tokens = {self.guest_token: "guest-7"}
        self.ops_secret = secrets.token_urlsafe(16)
        self.accounts = {"ops": self.ops_secret}
        if self.cfg["default_account_enabled"]:
            self.accounts[DEFAULT_ACCOUNT[0]] = DEFAULT_ACCOUNT[1]
        self.server_log = []        # (correlation id, what happened)
        self.cleartext_seen = 0     # requests with credentials on plain HTTP
        self.requests = 0

    # -- the edge of the process -------------------------------------------

    def handle(self, listener, method, path, headers=None, login=None):
        headers = dict(headers or {})
        if listener == "public-http":
            mode = self.cfg["http_listener"]
            if mode == "off":
                return REFUSED
            # The listener answered, so the request has already crossed the
            # network unencrypted, whatever the answer turns out to be.
            if "Authorization" in headers:
                self.cleartext_seen += 1
            if mode == "redirect":
                location = "https://%s%s" % (self.cfg["hostname"], path)
                return self._finish(Response(301, {"Location": location}),
                                    listener)
        self.requests += 1
        rid = "req-%04d" % self.requests
        try:
            response = self._route(listener, method, path, headers, login, rid)
        except Exception as exc:        # the one global exception handler
            response = self._global_error(rid, exc, path)
        return self._finish(response, listener)

    def _finish(self, response, listener):
        """Headers every response gets, decided by configuration."""
        h = response.headers
        if self.cfg["server_banner"] == "full":
            h["Server"] = "ExampleServe/" + self.cfg["components"]["ExampleServe"]
        if self.cfg["cache_control"]:
            h["Cache-Control"] = self.cfg["cache_control"]
        if self.cfg["nosniff"]:
            h["X-Content-Type-Options"] = "nosniff"
        # RFC 6797 section 7.2: an HSTS Host MUST NOT include the field in
        # responses conveyed over non-secure transport.
        if self.cfg["hsts_max_age"] is not None and listener != "public-http":
            h["Strict-Transport-Security"] = "max-age=%d" % self.cfg["hsts_max_age"]
        return response

    def _global_error(self, rid, exc, path):
        self.server_log.append((rid, "%s while handling %s"
                                % (type(exc).__name__, path)))
        if self.cfg["debug_errors"]:
            # Fixed strings, so the output does not vary by machine.
            body = "\n".join([
                "Traceback (most recent call last):",
                '  File "/srv/examplehotels/app/bookings.py", line 88, in get_booking',
                '    row = db.execute("SELECT * FROM bookings WHERE id = " + booking_id)',
                "%s: could not handle %s" % (type(exc).__name__, path),
                "ExampleServe/%s" % self.cfg["components"]["ExampleServe"],
            ])
            return Response(500, {"Content-Type": "text/html"}, body)
        # RFC 9457 problem details. about:blank means the problem has no
        # semantics beyond the status code, and instance identifies this
        # occurrence. The detail stays in the server log.
        problem = {"type": "about:blank", "title": "Internal Server Error",
                   "status": 500, "instance": "/errors/" + rid}
        return Response(500, {"Content-Type": "application/problem+json"},
                        json.dumps(problem, sort_keys=True))

    # -- routing -----------------------------------------------------------

    def _allowed(self, route):
        if self.cfg["method_policy"] == "framework":
            return tuple(m for m in KNOWN_METHODS if m != "TRACE")
        return self.cfg["route_methods"].get(route, ())

    def _not_allowed(self, route):
        # RFC 9110 section 15.5.6: a 405 response MUST carry Allow.
        return Response(405, {"Allow": ", ".join(self._allowed(route))})

    def _caller(self, headers, rid):
        value = headers.get("Authorization")
        if value is None:
            return None
        try:
            scheme, token = value.split(" ")
        except ValueError:
            # A header the parser did not expect. What happens next is a
            # configuration decision.
            if self.cfg["on_auth_error"] == "allow":
                self.server_log.append((rid, "auth error ignored"))
                return "unverified"         # fails open
            raise                           # fails closed, via the handler
        if scheme != "Bearer":
            return None
        return self.tokens.get(token)

    def _route(self, listener, method, path, headers, login, rid):
        if method not in KNOWN_METHODS:
            # RFC 9110 section 9.1: an unrecognized method SHOULD get 501.
            return Response(501)
        path = collapse_slashes(path)   # this framework always does this
        route = "/v1/bookings/{id}"
        if method == "TRACE":
            if not self.cfg["trace_enabled"]:
                return self._not_allowed(route)
            echo = "TRACE %s\n" % path + "".join(
                "%s: %s\n" % pair for pair in sorted(headers.items()))
            return Response(200, {"Content-Type": "message/http"}, echo)
        if path == "/debug/config":
            if not self.cfg["debug_endpoints"]:
                return Response(404)
            return Response(200, {"Content-Type": "application/json"},
                            json.dumps(sorted(self.cfg)))
        if path.startswith("/samples/"):
            if not self.cfg["sample_content"]:
                return Response(404)
            return Response(200, {"Content-Type": "text/html"},
                            "<h1>It works</h1>")
        if path == "/admin/login":
            if listener != self.cfg["management_listener"]:
                return Response(404)
            if login is not None and login[0] in self.accounts and \
                    hmac.compare_digest(self.accounts[login[0]].encode(),
                                        login[1].encode()):
                return Response(200, {"Content-Type": "application/json"},
                                '{"role": "admin"}')
            return Response(401)
        match = re.fullmatch(r"/v1/bookings/([^/]+)", path)
        if match is None:
            return Response(404)
        if method not in self._allowed(route):
            return self._not_allowed(route)
        if self._caller(headers, rid) is None:
            return Response(401)
        booking_id = int(match.group(1))    # raises on "abc": never handled
        if booking_id not in self.bookings:
            return Response(404)
        if method == "DELETE":
            del self.bookings[booking_id]
            return Response(204)
        body = json.dumps(self.bookings[booking_id], sort_keys=True)
        return Response(200, {"Content-Type": "application/json"},
                        "" if method == "HEAD" else body)


# ---------------------------------------------------------------------------
# TLS and patch levels: configuration compared with a rule. No handshakes.
# ---------------------------------------------------------------------------

def forbidden_tls_versions(cfg):
    return [v for v in TLS_ORDER
            if v in cfg["tls_versions"] and v in FORBIDDEN_TLS_VERSIONS]


def negotiate(client_versions, cfg):
    """The highest version both sides have, or the alert a server sends when
    there is none."""
    common = [v for v in TLS_ORDER
              if v in client_versions and v in cfg["tls_versions"]]
    return common[-1] if common else "protocol_version alert"


def forbidden_cipher_suites(cfg):
    return [s for s in cfg["tls12_cipher_suites"]
            if s.startswith(FORBIDDEN_SUITE_PREFIXES)
            or any(part in s for part in FORBIDDEN_SUITE_PARTS)]


def version_tuple(text):
    return tuple(int(part) for part in text.split("."))


def unpatched(cfg):
    return ["%s %s < %s" % (name, have, ADVISORIES[name])
            for name, have in sorted(cfg["components"].items())
            if name in ADVISORIES
            and version_tuple(have) < version_tuple(ADVISORIES[name])]


def diff_configs(a, b, ignore=()):
    """Keys whose values differ between two configurations."""
    return sorted(k for k in set(a) | set(b)
                  if k not in ignore and a.get(k) != b.get(k))


# ---------------------------------------------------------------------------
# The auditor. It holds an ordinary guest token and nothing else.
# ---------------------------------------------------------------------------

LEAK_MARKERS = (("stack trace", r"Traceback"), ("file path", r'File "/'),
                ("SQL", r"SELECT "), ("version", r"\d+\.\d+\.\d+"))


def last_log(api):
    """The newest server log entry, or None when nothing was logged, so that
    a variant of this lab fails a check and does not stop with a traceback."""
    return api.server_log[-1] if api.server_log else None


def leak_markers(body):
    return [name for name, pattern in LEAK_MARKERS if re.search(pattern, body)]


class Auditor:
    def __init__(self, api):
        self.api = api
        self.bearer = {"Authorization": "Bearer " + api.guest_token}

    def call(self, method, path, listener="public-https", headers=None,
             login=None):
        if headers is None:
            headers = self.bearer
        return self.api.handle(listener, method, path, headers, login)

    def findings(self):
        """Finding ids, in a fixed order. Each line is one probe."""
        api, cfg, call = self.api, self.api.cfg, self.call
        booking = call("GET", "/v1/bookings/1001")
        probes = [
            ("error-detail", bool(leak_markers(call("GET", "/v1/bookings/abc").body))),
            ("server-banner", booking.header("Server") is not None),
            ("unused-method", call("DELETE", "/v1/bookings/1002").status == 204),
            ("trace", api.guest_token in call("TRACE", "/v1/bookings/1001").body),
            ("debug-endpoint", call("GET", "/debug/config").status == 200),
            ("sample-content", call("GET", "/samples/hello").status == 200),
            ("default-account", call("POST", "/admin/login",
                                     login=DEFAULT_ACCOUNT).status == 200),
            ("no-store", booking.header("Cache-Control") != "no-store"),
            ("nosniff", booking.header("X-Content-Type-Options") != "nosniff"),
            ("plain-http", call("GET", "/v1/bookings/1001",
                                listener="public-http").status == 200),
            ("hsts", booking.header("Strict-Transport-Security") is None),
            ("tls-versions", bool(forbidden_tls_versions(cfg))
             or "TLS1.3" not in cfg["tls_versions"]),
            ("tls-ciphers", bool(forbidden_cipher_suites(cfg))),
            ("unpatched", bool(unpatched(cfg))),
            ("fail-open", call("GET", "/v1/bookings/1001",
                               headers={"Authorization": "Bearer"}).status == 200),
        ]
        return [name for name, found in probes if found]


# ---------------------------------------------------------------------------
# Clients used in Part D, and the edge proxy used in Part E.
# ---------------------------------------------------------------------------

class BrowserLikeAgent:
    """A user agent that implements HSTS. See the simplifications above."""

    def __init__(self):
        self.known_hsts_hosts = {}      # host -> time the policy expires


def fetch(api, url, token, now, agent=None):
    """GET a URL. Returns the scheme actually used and the response. A plain
    API client (agent=None) uses the URL exactly as it was configured."""
    scheme, rest = url.split("://")
    host, _, path = rest.partition("/")
    if agent is not None and scheme == "http" \
            and agent.known_hsts_hosts.get(host, 0) > now:
        scheme = "https"                                    # RFC 6797 8.3
    response = api.handle("public-" + scheme, "GET", "/" + path,
                          {"Authorization": "Bearer " + token})
    policy = re.fullmatch(r"max-age=(\d+)",
                          response.header("Strict-Transport-Security") or "")
    if agent is not None and scheme == "https" and policy:  # RFC 6797 8.1
        agent.known_hsts_hosts[host] = now + int(policy.group(1))
    return scheme, response


def edge(api, path, login, edge_normalizes):
    """A reverse proxy with one rule: nothing under /admin gets through."""
    seen = collapse_slashes(path) if edge_normalizes else path
    if seen == "/admin" or seen.startswith("/admin/"):
        return Response(403)
    return api.handle("public-https", "POST", path, login=login)


# ===========================================================================


def main():
    print("hosts use the reserved .example domain; no request leaves this process")

    # ---------------- Part A -------------------------------------------
    section("Part A: a default install, probed by an auditor with a guest token.")
    api = Api(DEFAULT_INSTALL)
    audit = Auditor(api)

    error = audit.call("GET", "/v1/bookings/abc")
    record("GET /v1/bookings/abc, an id the code never expected", 500, error.status)
    record("  what the error body gives away",
           ["stack trace", "file path", "SQL", "version"], leak_markers(error.body))
    record("  its Content-Type", "text/html", error.header("Content-Type"))
    record("  the Server header", "ExampleServe/4.2.1", error.header("Server"))
    record("DELETE /v1/bookings/1002, a method the API has no use for", 204,
           audit.call("DELETE", "/v1/bookings/1002").status)
    record("  booking 1002 still exists", False, 1002 in api.bookings)
    trace = audit.call("TRACE", "/v1/bookings/1001")
    record("TRACE /v1/bookings/1001", 200, trace.status)
    record("  the reply repeats the caller's Authorization header", True,
           api.guest_token in trace.body)
    record("GET /debug/config", 200, audit.call("GET", "/debug/config").status)
    record("GET /samples/hello", 200, audit.call("GET", "/samples/hello").status)
    record("the vendor's default account, on the public listener", 200,
           audit.call("POST", "/admin/login", login=DEFAULT_ACCOUNT).status)
    booking = audit.call("GET", "/v1/bookings/1001")
    record("GET /v1/bookings/1001, which carries a guest's email", 200, booking.status)
    record("  Cache-Control", None, booking.header("Cache-Control"))
    record("  X-Content-Type-Options", None, booking.header("X-Content-Type-Options"))
    record("the same request on the plain HTTP listener", 200,
           audit.call("GET", "/v1/bookings/1001", listener="public-http").status)
    record("  requests with credentials that crossed in clear text", 1,
           api.cleartext_seen)
    record("TLS versions enabled that must not be negotiated", ["TLS1.0", "TLS1.1"],
           forbidden_tls_versions(api.cfg))
    record("  a client offering only TLS1.0 negotiates", "TLS1.0",
           negotiate(("TLS1.0",), api.cfg))
    record("  a client offering TLS1.2 and TLS1.3 negotiates", "TLS1.2",
           negotiate(("TLS1.2", "TLS1.3"), api.cfg))
    record("TLS 1.2 cipher suites that must not be selected",
           ["TLS_RSA_WITH_AES_128_CBC_SHA", "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"],
           forbidden_cipher_suites(api.cfg))
    record("components behind their first fixed version",
           ["ExampleServe 4.2.1 < 4.2.7"], unpatched(api.cfg))
    broken = audit.call("GET", "/v1/bookings/1001",
                        headers={"Authorization": "Bearer"})
    record("GET /v1/bookings/1001 with a malformed Authorization header", 200,
           broken.status)
    record("  what the server logged about it", "auth error ignored",
           (last_log(api) or (None, None))[1])
    record("  and with no Authorization header at all", 401,
           audit.call("GET", "/v1/bookings/1001", headers={}).status)
    record("findings from the full audit of a fresh default install", 15,
           len(Auditor(Api(DEFAULT_INSTALL)).findings()))

    # ---------------- Part B -------------------------------------------
    section("Part B: the hardened configuration. Same code, same probes.")
    api = Api(HARDENED)
    audit = Auditor(api)

    error = audit.call("GET", "/v1/bookings/abc")
    record("GET /v1/bookings/abc", 500, error.status)
    record("  what the error body gives away", [], leak_markers(error.body))
    record("  its Content-Type", "application/problem+json",
           error.header("Content-Type"))
    record("  the body",
           '{"instance": "/errors/req-0001", "status": 500, '
           '"title": "Internal Server Error", "type": "about:blank"}', error.body)
    record("  the server log, under the same id",
           ("req-0001", "ValueError while handling /v1/bookings/abc"),
           last_log(api))
    record("  the Server header", None, error.header("Server"))
    delete = audit.call("DELETE", "/v1/bookings/1002")
    record("DELETE /v1/bookings/1002", 405, delete.status)
    record("  Allow", "GET, HEAD", delete.header("Allow"))
    record("  booking 1002 still exists", True, 1002 in api.bookings)
    record("TRACE /v1/bookings/1001", 405,
           audit.call("TRACE", "/v1/bookings/1001").status)
    record("FROB /v1/bookings/1001, a method that does not exist", 501,
           audit.call("FROB", "/v1/bookings/1001").status)
    record("GET /debug/config", 404, audit.call("GET", "/debug/config").status)
    record("GET /samples/hello", 404, audit.call("GET", "/samples/hello").status)
    record("the default account, on the public listener", 404,
           audit.call("POST", "/admin/login", login=DEFAULT_ACCOUNT).status)
    record("  the default account, on the internal management listener", 401,
           audit.call("POST", "/admin/login", listener="internal-mgmt",
                      login=DEFAULT_ACCOUNT).status)
    record("  the operator's own account, on the management listener", 200,
           audit.call("POST", "/admin/login", listener="internal-mgmt",
                      login=("ops", api.ops_secret)).status)
    booking = audit.call("GET", "/v1/bookings/1001")
    record("GET /v1/bookings/1001 with the guest token still works", 200,
           booking.status)
    record("  the guest in the body", "A. Guest",
           json.loads(booking.body or "{}").get("guest"))
    record("  Cache-Control", "no-store", booking.header("Cache-Control"))
    record("  X-Content-Type-Options", "nosniff",
           booking.header("X-Content-Type-Options"))
    record("  Content-Type", "application/json", booking.header("Content-Type"))
    record("  Strict-Transport-Security", "max-age=31536000",
           booking.header("Strict-Transport-Security"))
    record("HEAD /v1/bookings/1001 still works", 200,
           audit.call("HEAD", "/v1/bookings/1001").status)
    record("the same GET on the plain HTTP listener", "connection refused",
           audit.call("GET", "/v1/bookings/1001", listener="public-http").status)
    record("  requests with credentials that crossed in clear text", 0,
           api.cleartext_seen)
    record("TLS versions enabled that must not be negotiated", [],
           forbidden_tls_versions(api.cfg))
    record("  a client offering only TLS1.0 gets", "protocol_version alert",
           negotiate(("TLS1.0",), api.cfg))
    record("  a client offering TLS1.2 and TLS1.3 negotiates", "TLS1.3",
           negotiate(("TLS1.2", "TLS1.3"), api.cfg))
    record("TLS 1.2 cipher suites that must not be selected", [],
           forbidden_cipher_suites(api.cfg))
    record("components behind their first fixed version", [], unpatched(api.cfg))
    broken = audit.call("GET", "/v1/bookings/1001",
                        headers={"Authorization": "Bearer"})
    record("GET /v1/bookings/1001 with a malformed Authorization header", 500,
           broken.status)
    record("  the body holds the booking", False, "A. Guest" in broken.body)
    record("findings from the full audit of a fresh hardened install", [],
           Auditor(Api(HARDENED)).findings())

    # ---------------- Part C -------------------------------------------
    section("Part C: drift between two environments built from one baseline.")
    staging = dict(HARDENED, hostname="api.staging.examplehotels.example")
    production = dict(HARDENED, debug_errors=True)   # an incident, never undone

    record("settings that differ, staging against production",
           ["debug_errors", "hostname"], diff_configs(staging, production))
    record("  leaving out the ones meant to differ", ["debug_errors"],
           diff_configs(staging, production, ignore=PER_ENVIRONMENT_KEYS))
    record("audit of staging", [], Auditor(Api(staging)).findings())
    record("audit of production", ["error-detail"],
           Auditor(Api(production)).findings())
    record("two default installs compared with each other differ in", [],
           diff_configs(DEFAULT_INSTALL, dict(DEFAULT_INSTALL)))
    record("  settings where a default install differs from the baseline", 17,
           len(diff_configs(DEFAULT_INSTALL, HARDENED)))

    # ---------------- Part D -------------------------------------------
    section("Part D: a redirect and HSTS, seen by a client that is not a browser.")
    api = Api(dict(HARDENED, http_listener="redirect"))
    http_url = "http://api.examplehotels.example/v1/bookings/1001"
    https_url = "https://api.examplehotels.example/v1/bookings/1001"

    scheme, reply = fetch(api, http_url, api.guest_token, now=0)
    record("a plain API client configured with an http URL gets", 301, reply.status)
    record("  Location", https_url, reply.header("Location"))
    record("  Strict-Transport-Security on that plain HTTP reply", None,
           reply.header("Strict-Transport-Security"))
    record("  tokens that have crossed in clear text so far", 1, api.cleartext_seen)
    fresh = BrowserLikeAgent()
    record("an HSTS agent that has never seen the host loads the http URL over",
           "http", fetch(api, http_url, api.guest_token, 0, fresh)[0])
    record("  tokens in clear text so far", 2, api.cleartext_seen)
    browser = BrowserLikeAgent()
    fetch(api, https_url, api.guest_token, 0, browser)
    record("an HSTS agent that loaded https once then loads the http URL over",
           "https", fetch(api, http_url, api.guest_token, 100, browser)[0])
    record("  tokens in clear text so far", 2, api.cleartext_seen)
    # The https load at time 100 renewed the policy, so it runs to 31536100.
    record("  and once max-age has run out it loads it over", "http",
           fetch(api, http_url, api.guest_token, 31536100, browser)[0])
    fetch(api, http_url, api.guest_token, now=200)
    record("the plain API client again: tokens in clear text so far", 4,
           api.cleartext_seen)
    closed = Api(HARDENED)
    record("with the listener off, the plain API client gets",
           "connection refused",
           fetch(closed, http_url, closed.guest_token, now=0)[1].status)
    record("  tokens in clear text", 0, closed.cleartext_seen)

    # ---------------- Part E -------------------------------------------
    section("Part E: an edge proxy and a backend that disagree about a path.")
    api = Api(dict(HARDENED, management_listener="public-https"))
    guess = ("ops", "a wrong guess")

    record("POST /admin/login through the edge", 403,
           edge(api, "/admin/login", guess, edge_normalizes=False).status)
    record("POST //admin/login through the same edge", 401,
           edge(api, "//admin/login", guess, edge_normalizes=False).status)
    record("  when the edge reads paths the way the backend does", 403,
           edge(api, "//admin/login", guess, edge_normalizes=True).status)
    record("  when the login is not on the public listener at all", 404,
           edge(Api(HARDENED), "//admin/login", guess,
                edge_normalizes=False).status)

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
