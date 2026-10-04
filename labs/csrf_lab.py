#!/usr/bin/env python3
"""Module 28 lab: browser sessions, cookies and cross-site request forgery.

Python 3, standard library only. On Windows use `py -3` wherever this page
shows `python3`.

Nothing here opens a socket. The browser is a Python object with a cookie
jar, the API is a Python class, and a request is a function call. Session
identifiers and tokens are random on every run and are never printed, so the
output is identical on every run and every platform. Time is a counter.

What is modelled, and from where:

  Browser.store_cookie   the storage model in section 5.7 of
                         draft-ietf-httpbis-rfc6265bis-22 (an Internet-Draft):
                         Domain, Path, Secure, HttpOnly, SameSite and the
                         __Secure- and __Host- prefixes.
  Browser.cookies_for    the retrieval algorithm in section 5.8.3 of the same
                         draft, including the SameSite rule.
  Browser.send           which requests carry an Origin header (Fetch
                         Standard, commit snapshot 357bd98, section 3.2), when
                         a preflight is needed (sections 2.2.1, 2.2.2 and
                         4.1), and the Sec-Fetch-Site value (Fetch Metadata
                         Request Headers, W3C Working Draft, 21 September
                         2026, section 2.3).
  Api                    a miles API that authenticates with a session
                         cookie, with each defence behind a switch.

Deliberate simplifications, so nothing here is mistaken for a browser:

  * The registrable domain is the last two labels of the host. A browser
    uses the public suffix list. Every host here ends in `.example`.
  * "Same-site" means the same scheme and the same registrable domain.
    Section 5.2 of the draft takes its definition from the HTML Standard.
  * A request is one hop. Redirects, frames, workers and reloads are not
    modelled.
  * A cookie with no SameSite attribute is treated exactly as Lax, which is
    the draft's base rule. Section 5.6.7.2 of the draft also allows a
    "Lax-allowing-unsafe" mode that sends such a cookie with a cross-site
    top-level POST while the cookie is new (it gives 2 minutes or less as
    a reasonable limit). That mode is not modelled. Every cookie in this
    lab is new, so a browser that uses the mode would print "sent" in the
    unset column of check 24.
  * The browser has no cookie policy. Section 5.8.1 of the draft allows a
    user agent to leave the Cookie header out of third-party requests, and
    this one never does.
  * Set-Cookie handling covers what the lab sends: no Expires or Max-Age,
    no size limits, no rules for control characters or nameless cookies,
    and no rule that stops a connection that is not secure from overlaying
    a Secure cookie.
  * The preflight test keeps the method rule and the Content-Type rule and
    leaves out the other value rules that the module 17 lab covers (the
    byte limits, the unsafe bytes and the Range header). The API sends no
    CORS headers, so it refuses every preflight and no cross-origin
    response is readable.
  * The Origin header is never rewritten to `null` by a referrer policy.
  * Cookies never expire in the jar. Session lifetime is enforced by the
    API, which is where the lesson says it belongs.
  * Login takes a user name and no password. Module 27 covers login.
"""

import hashlib
import hmac
import json
import secrets
import sys
from urllib.parse import parse_qsl, urlsplit

APP = "https://app.exampleair.example"       # the page and the API, one origin
EVIL = "https://evil.example"                # another site
PROMO = "https://promo.exampleair.example"   # a sibling subdomain, same site
PARTNER = "https://www.examplehotels.example"
LOOKALIKE = "https://app.exampleair.example.evil.example"   # another site

SAFE_METHODS = ("GET", "HEAD", "OPTIONS", "TRACE")          # RFC 9110, 9.2.1
SAFELISTED_METHODS = ("GET", "HEAD", "POST")                # Fetch, 2.2.1
SAFELISTED_TYPES = ("application/x-www-form-urlencoded",
                    "multipart/form-data", "text/plain")    # Fetch, 2.2.2
FORM = {"content-type": "application/x-www-form-urlencoded"}

IDLE_TIMEOUT = 15 * 60          # project baseline, in seconds
ABSOLUTE_TIMEOUT = 8 * 60 * 60  # project baseline, in seconds

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
# Origins and sites.
# ---------------------------------------------------------------------------

def origin_of(url):
    u = urlsplit(url)
    return "%s://%s" % (u.scheme, u.hostname)


def registrable_domain(host):
    return ".".join(host.split(".")[-2:])


def same_origin(a, b):
    return origin_of(a) == origin_of(b)


def same_site(a, b):
    ua, ub = urlsplit(a), urlsplit(b)
    return (ua.scheme == ub.scheme and
            registrable_domain(ua.hostname) == registrable_domain(ub.hostname))


def unsafe_header_names(headers):
    """Header names that take a request off the CORS safelist."""
    names = []
    for name, value in headers.items():
        if name in ("accept", "accept-language", "content-language"):
            continue
        if name == "content-type" and \
                value.split(";")[0].strip().lower() in SAFELISTED_TYPES:
            continue
        names.append(name)
    return sorted(names)


# ---------------------------------------------------------------------------
# The browser.
# ---------------------------------------------------------------------------

class Cookie:
    def __init__(self, name, value, domain, host_only, path, secure,
                 http_only, same_site_flag, created):
        self.name, self.value, self.domain = name, value, domain
        self.host_only, self.path, self.secure = host_only, path, secure
        self.http_only, self.same_site = http_only, same_site_flag
        self.created = created


def domain_matches(host, domain):
    return host == domain or host.endswith("." + domain)


def path_matches(request_path, cookie_path):
    if request_path == cookie_path:
        return True
    if request_path.startswith(cookie_path):
        return cookie_path.endswith("/") or \
            request_path[len(cookie_path)] == "/"
    return False


class Result:
    def __init__(self, outcome, sent, cookies=(), headers=None, readable=False,
                 body=None):
        self.outcome, self.sent = outcome, sent
        self.cookies, self.headers = list(cookies), headers or {}
        self.readable, self.body = readable, body or {}


class Browser:
    def __init__(self, enforce_samesite=True, fetch_metadata=True):
        self.jar = []
        self.ticks = 0
        self.storage = {}                 # origin -> script-readable storage
        self.enforce_samesite = enforce_samesite
        self.fetch_metadata = fetch_metadata

    def store_cookie(self, text, url, cross_site=False, top_level=True,
                     http=True):
        """Receive one Set-Cookie value from `url`. Returns what happened."""
        first, *rest = [p.strip() for p in text.split(";")]
        name, _, value = first.partition("=")
        attrs = {}
        for av in rest:
            key, _, val = av.partition("=")
            attrs[key.strip().lower()] = val.strip()
        u = urlsplit(url)
        host = u.hostname

        domain = attrs.get("domain", "").lower()
        if domain.startswith("."):
            domain = domain[1:]
        if domain == "example":           # a public suffix in this lab
            return "ignored: Domain is a public suffix"
        if domain and not domain_matches(host, domain):
            return "ignored: Domain does not cover the host that set it"
        host_only = not domain
        path = attrs.get("path", "")
        if not path.startswith("/"):
            path = u.path[:u.path.rfind("/")] or "/"      # the default-path
        secure = "secure" in attrs
        if secure and u.scheme != "https":
            return "ignored: Secure cookie from a connection that is not secure"
        http_only = "httponly" in attrs
        if http_only and not http:
            return "ignored: HttpOnly cookie from a script"
        flag = attrs.get("samesite", "").capitalize()
        if flag not in ("Strict", "Lax", "None"):
            flag = "Default"
        if flag != "None" and cross_site and not top_level:
            return "ignored: SameSite cookie in a cross-site response"
        if flag == "None" and not secure:
            return "ignored: SameSite=None needs Secure"
        if name.lower().startswith("__secure-") and not secure:
            return "ignored: __Secure- needs Secure"
        if name.lower().startswith("__host-") and not (
                secure and host_only and attrs.get("path") == "/"):
            return "ignored: __Host- needs Secure, Path=/ and no Domain"

        self.ticks += 1
        new = Cookie(name, value, domain or host, host_only, path, secure,
                     http_only, flag, self.ticks)
        for i, old in enumerate(self.jar):
            if (old.name, old.domain, old.host_only, old.path) == \
                    (new.name, new.domain, new.host_only, new.path):
                if old.http_only and not http:
                    return "ignored: a script cannot replace an HttpOnly cookie"
                new.created = old.created
                self.jar[i] = new
                return "stored"
        self.jar.append(new)
        return "stored"

    def cookies_for(self, url, method="GET", cross_site=False, top_level=True,
                    http=True):
        """The cookie-list for one retrieval, as (name, value) pairs."""
        u = urlsplit(url)
        chosen = []
        for c in self.jar:
            if c.host_only and u.hostname != c.domain:
                continue
            if not c.host_only and not domain_matches(u.hostname, c.domain):
                continue
            if not path_matches(u.path or "/", c.path):
                continue
            if c.secure and u.scheme != "https":
                continue
            if c.http_only and not http:
                continue
            if self.enforce_samesite and c.same_site != "None" and cross_site:
                lax_exception = (http and c.same_site in ("Lax", "Default")
                                 and method in SAFE_METHODS and top_level)
                if not lax_exception:
                    continue
            chosen.append(c)
        chosen.sort(key=lambda c: (-len(c.path), c.created))
        return [(c.name, c.value) for c in chosen]

    def document_cookie(self, page_url):
        """What a script on `page_url` reads from document.cookie."""
        return dict(self.cookies_for(page_url, http=False))

    def script_storage(self, page_url):
        """What a script on `page_url` reads from storage: its own origin's
        entries and nobody else's."""
        return self.storage.get(origin_of(page_url), {})

    def send(self, server, initiator, url, method="GET", kind="navigation",
             headers=None, body=""):
        """One request. `initiator` is the URL of the page that caused it,
        or None when the user typed the address. `kind` is "navigation" (a
        link or a form, top level), "subresource" (an image) or "fetch" (a
        script call with credentials included)."""
        headers = dict(headers or {})
        cross_origin = initiator is not None and not same_origin(initiator, url)
        cross_site = initiator is not None and not same_site(initiator, url)
        top_level = kind == "navigation"

        unsafe = unsafe_header_names(headers)
        if kind == "fetch" and cross_origin and \
                (method not in SAFELISTED_METHODS or unsafe):
            if not server.preflight(origin_of(initiator), method, unsafe):
                return Result("blocked by the browser: preflight refused",
                              sent=False)

        cookies = self.cookies_for(url, method, cross_site, top_level)
        if initiator is not None and (method not in ("GET", "HEAD") or
                                      (kind == "fetch" and cross_origin)):
            headers["origin"] = origin_of(initiator)
        if self.fetch_metadata and urlsplit(url).scheme == "https":
            headers["sec-fetch-site"] = (
                "none" if initiator is None else
                "same-origin" if not cross_origin else
                "cross-site" if cross_site else "same-site")

        response = server.handle(Request(method, url, headers, body, cookies))
        for text in response.set_cookies:
            self.store_cookie(text, url, cross_site, top_level)
        return Result("%d %s" % (response.status, response.reason), True,
                      [name for name, _ in cookies], headers,
                      readable=initiator is not None and not cross_origin,
                      body=response.body)


# ---------------------------------------------------------------------------
# The API.
# ---------------------------------------------------------------------------

class Clock:
    def __init__(self):
        self.now = 0


class Request:
    def __init__(self, method, url, headers=None, body="", cookies=()):
        u = urlsplit(url)
        self.method, self.path = method, u.path or "/"
        self.query = dict(parse_qsl(u.query))
        self.headers, self.body = dict(headers or {}), body
        self.cookies = list(cookies)

    def cookie(self, name):
        """The first cookie with this name, as a naive server reads it."""
        for n, v in self.cookies:
            if n == name:
                return v
        return None


class Response:
    def __init__(self, status, reason, set_cookies=(), body=None):
        self.status, self.reason = status, reason
        self.set_cookies, self.body = list(set_cookies), body or {}


class Api:
    DEFAULTS = dict(
        session_cookie="sid",
        cookie_attributes="Path=/; Secure; HttpOnly; SameSite=None",
        auth="cookie",                 # or "bearer"
        json_only=False,               # require Content-Type: application/json
        state_changing_get=True,       # the legacy GET /api/transfer route
        csrf="none",                   # "synchronizer", "naive" or "signed"
        csrf_cookie="csrf",
        check_origin=False,
        check_fetch_metadata=False,
        trust_same_site=False,
        sid_from_url=True,             # adopt a session id from ?sid=
        regenerate_at_login=False,
        logout_on_server=True,
    )

    def __init__(self, clock, **config):
        unknown = set(config) - set(self.DEFAULTS)
        if unknown:
            raise ValueError("unknown settings: %s" % sorted(unknown))
        self.cfg = dict(self.DEFAULTS, **config)
        self.clock = clock
        self.sessions = {}             # session id -> session record
        self.tokens = {}               # bearer token -> user
        self.miles = {"maya": 50000, "attacker": 0, "hotel": 0}
        self.csrf_key = secrets.token_bytes(32)
        self.received = 0

    # -- sessions -----------------------------------------------------------

    def new_session(self, user=None):
        sid = secrets.token_hex(16)    # 128 random bits, never printed
        self.sessions[sid] = {"user": user, "created": self.clock.now,
                              "seen": self.clock.now,
                              "csrf": secrets.token_hex(16)}
        return sid

    def session_cookie(self, sid):
        return "%s=%s; %s" % (self.cfg["session_cookie"], sid,
                              self.cfg["cookie_attributes"])

    def live_session(self, sid):
        """The session for this id, or a reason there is none."""
        session = self.sessions.get(sid)
        if session is None:
            return None, "no session"
        now = self.clock.now
        if now - session["seen"] > IDLE_TIMEOUT or \
                now - session["created"] > ABSOLUTE_TIMEOUT:
            del self.sessions[sid]
            return None, "session expired"
        session["seen"] = now
        return session, ""

    def signed_token(self, sid, nonce):
        message = "%d!%s!%d!%s" % (len(sid), sid, len(nonce), nonce)
        mac = hmac.new(self.csrf_key, message.encode(), hashlib.sha256)
        return mac.hexdigest() + "." + nonce

    # -- the browser asks before a request that is not safelisted ----------

    def preflight(self, origin, method, header_names):
        return False                   # this API allows no other origin

    # -- requests -------------------------------------------------------------

    def handle(self, req):
        self.received += 1
        route = (req.method, req.path)
        if route == ("GET", "/login"):
            return self.login_page(req)
        if route == ("POST", "/login"):
            return self.login(req)

        if self.cfg["auth"] == "bearer":
            value = req.headers.get("authorization", "")
            user = self.tokens.get(value[len("Bearer "):])
            if user is None:
                return Response(401, "no credential")
            sid, session = None, {"user": user}
        else:
            sid = req.cookie(self.cfg["session_cookie"])
            session, why = self.live_session(sid)
            if session is None or session["user"] is None:
                return Response(401, why or "no session")
            refusal = self.forgery_checks(req, sid, session)
            if refusal:
                return Response(403, refusal)

        user = session["user"]
        if route == ("GET", "/api/balance"):
            return Response(200, "balance %d" % self.miles[user])
        if route == ("GET", "/api/csrf-token"):
            return Response(200, "token issued", body={"csrf": session["csrf"]})
        if route == ("POST", "/logout"):
            if self.cfg["logout_on_server"]:
                self.sessions.pop(sid, None)
            return Response(200, "logged out", [
                "%s=; Path=/; Secure; HttpOnly" % self.cfg["session_cookie"]])
        if route == ("GET", "/api/transfer"):
            if not self.cfg["state_changing_get"]:
                return Response(405, "use POST")
            return self.transfer(user, req.query)
        if route == ("POST", "/api/transfer"):
            ctype = req.headers.get("content-type", "").split(";")[0].strip()
            if self.cfg["json_only"] and ctype != "application/json":
                return Response(415, "content type must be application/json")
            return self.transfer(user, self.fields(req))
        return Response(404, "not found")

    def fields(self, req):
        """A lenient parser: JSON if the body parses as JSON, whatever the
        Content-Type says, and form fields otherwise."""
        try:
            parsed = json.loads(req.body)
            if isinstance(parsed, dict):
                return parsed
        except ValueError:
            pass
        return dict(parse_qsl(req.body))

    def transfer(self, user, fields):
        to, miles = fields.get("to"), int(fields.get("miles", 0))
        if to not in self.miles or not 0 < miles <= self.miles[user]:
            return Response(400, "bad transfer")
        self.miles[user] -= miles
        self.miles[to] += miles
        return Response(200, "transferred %d to %s" % (miles, to))

    def forgery_checks(self, req, sid, session):
        """Why this request is refused, or None. Only requests with an
        unsafe method are examined, as the cheat sheet's policy does."""
        if req.method in SAFE_METHODS:
            return None
        site = req.headers.get("sec-fetch-site")
        origin = req.headers.get("origin")
        metadata = self.cfg["check_fetch_metadata"]
        if metadata and site == "cross-site":
            return "cross-site request refused"
        if metadata and site == "same-site" and not self.cfg["trust_same_site"]:
            return "same-site request refused"
        if self.cfg["check_origin"] or (metadata and site is None):
            if origin != APP:          # absent counts as a mismatch
                return "origin not allowed"

        mode = self.cfg["csrf"]
        if mode == "none":
            return None
        sent = req.headers.get("x-csrf-token") or \
            self.fields(req).get("csrf_token")
        if not sent:
            return "csrf token missing"
        if mode == "synchronizer":
            expected = session["csrf"]
        elif mode == "naive":
            expected = req.cookie(self.cfg["csrf_cookie"]) or ""
        else:                          # "signed": bound to this session
            expected = self.signed_token(sid, str(sent).partition(".")[2])
        if not hmac.compare_digest(str(sent).encode(), expected.encode()):
            return "csrf token mismatch" if mode != "signed" \
                else "csrf token invalid"
        return None

    def login_page(self, req):
        """Start a session before login: a pre-login session."""
        if self.cfg["auth"] == "bearer":
            return Response(200, "login page")
        if self.cfg["sid_from_url"] and req.query.get("sid") in self.sessions:
            return Response(200, "login page",
                            [self.session_cookie(req.query["sid"])])
        if req.cookie(self.cfg["session_cookie"]) in self.sessions:
            return Response(200, "login page")
        return Response(200, "login page",
                        [self.session_cookie(self.new_session())])

    def login(self, req):
        user = self.fields(req).get("user")
        if user not in self.miles:
            return Response(401, "unknown user")
        if self.cfg["auth"] == "bearer":
            token = secrets.token_hex(16)
            self.tokens[token] = user
            return Response(200, "logged in", body={"access_token": token})
        old = req.cookie(self.cfg["session_cookie"])
        cookies = []
        if old in self.sessions and not self.cfg["regenerate_at_login"]:
            sid = old                  # the id from before login is kept
            self.sessions[sid]["user"] = user
        else:
            self.sessions.pop(old, None)
            sid = self.new_session(user)
            cookies.append(self.session_cookie(sid))
        if self.cfg["csrf"] in ("naive", "signed"):
            token = secrets.token_hex(16)
            if self.cfg["csrf"] == "signed":
                token = self.signed_token(sid, token)
            cookies.append("%s=%s; Path=/; Secure; SameSite=Strict"
                           % (self.cfg["csrf_cookie"], token))
        return Response(200, "logged in", cookies)


# ---------------------------------------------------------------------------
# The people in the story.
# ---------------------------------------------------------------------------

def logged_in(browser=None, user="maya", **config):
    """An API, and a browser in which `user` has just logged in."""
    api = Api(Clock(), **config)
    browser = browser or Browser()
    browser.send(api, None, APP + "/login")
    done = browser.send(api, APP + "/login", APP + "/login", "POST",
                        "navigation", FORM, "user=" + user)
    if api.cfg["auth"] == "bearer":
        browser.storage[APP] = {"access_token": done.body["access_token"]}
    return api, browser


def own_transfer(api, browser, headers=None,
                 body="to=hotel&miles=10000", ctype=None):
    """The app's own script moves miles to the member's hotel account."""
    sent = dict(FORM if ctype is None else {"content-type": ctype})
    sent.update(headers or {})
    return browser.send(api, APP + "/account", APP + "/api/transfer", "POST",
                        "fetch", sent, body)


def forged_form(api, browser, attacker=EVIL, extra=""):
    """A page on the attacker's host submits a hidden form."""
    return browser.send(api, attacker + "/win", APP + "/api/transfer", "POST",
                        "navigation", FORM, "to=attacker&miles=10000" + extra)


def forged_get(api, browser, kind):
    """An image tag ("subresource") or a link ("navigation") on evil."""
    return browser.send(api, EVIL + "/win",
                        APP + "/api/transfer?to=attacker&miles=10000", "GET",
                        kind)


def direct(api, method, path, cookies=(), headers=None, body=""):
    """A client that is not a browser: it sends exactly what it is told."""
    response = api.handle(Request(method, APP + path, headers, body, cookies))
    return "%d %s" % (response.status, response.reason)


def sid_in(browser, name="sid"):
    return dict(browser.cookies_for(APP + "/")).get(name)


def main():
    print("hosts use the reserved .example domain; no request leaves this process")
    json_body = '{"to": "attacker", "miles": 10000}'

    # ---------------- Part A -------------------------------------------
    section("Part A: no defence. The session cookie is SameSite=None.")

    api, maya = logged_in()
    record("the app's own page moves 10,000 miles", "200 transferred 10000 to hotel",
           own_transfer(api, maya).outcome)
    forged = forged_form(api, maya)
    record("a hidden form on evil.example posts a transfer: cookies attached",
           ["sid"], forged.cookies)
    record("  and the API answers", "200 transferred 10000 to attacker", forged.outcome)
    record("  the page on evil.example can read that answer", False, forged.readable)
    record("an image tag on evil.example with the transfer in its URL",
           "200 transferred 10000 to attacker", forged_get(api, maya, "subresource").outcome)
    record("miles the attacker now holds", 20000, api.miles["attacker"])
    record("the same POST from the attacker's own machine, with no cookie", "401 no session",
           direct(api, "POST", "/api/transfer", (), FORM, "to=attacker&miles=10000"))

    # ---------------- Part B -------------------------------------------
    section("Part B: \"our API only accepts JSON\".")

    api, maya = logged_in()
    as_json = {"content-type": "application/json"}
    as_text = {"content-type": "text/plain"}
    record("a script on evil.example sends JSON as application/json: unsafe names",
           ["content-type"], unsafe_header_names(as_json))
    before = api.received
    record("  the browser asks first, and the request is",
           "blocked by the browser: preflight refused",
           maya.send(api, EVIL + "/win", APP + "/api/transfer", "POST", "fetch",
                     as_json, json_body).outcome)
    record("  requests that reached the API handler", 0, api.received - before)
    record("the same body labelled text/plain: unsafe names", [], unsafe_header_names(as_text))
    record("  an API that parses any body as JSON answers", "200 transferred 10000 to attacker",
           maya.send(api, EVIL + "/win", APP + "/api/transfer", "POST", "fetch",
                     as_text, json_body).outcome)
    strict, maya = logged_in(json_only=True)
    record("  an API that requires application/json answers",
           "415 content type must be application/json",
           maya.send(strict, EVIL + "/win", APP + "/api/transfer", "POST",
                     "fetch", as_text, json_body).outcome)
    record("  and still serves its own page's JSON request", "200 transferred 10000 to hotel",
           own_transfer(strict, maya, body='{"to": "hotel", "miles": 10000}',
                        ctype="application/json").outcome)

    # ---------------- Part C -------------------------------------------
    section("Part C: what each cookie attribute scopes.")

    def sent(set_cookie, set_from, *urls, **how):
        jar = Browser()
        jar.store_cookie(set_cookie, set_from)
        return [bool(jar.cookies_for(u, **how)) for u in urls]

    record("no Domain attribute: sent to app, to m.app, to promo", [True, False, False],
           sent("a=1; Path=/", APP + "/", APP + "/", "https://m.app.exampleair.example/", PROMO + "/"))
    record("Domain=exampleair.example: sent to app, to promo", [True, True],
           sent("a=1; Path=/; Domain=exampleair.example", APP + "/", APP + "/", PROMO + "/"))
    record("Secure: sent over https, over http", [True, False],
           sent("a=1; Path=/; Secure", APP + "/", APP + "/", "http://app.exampleair.example/"))
    record("Path=/api: sent to /api/balance, /apiary, /login", [True, False, False],
           sent("a=1; Path=/api", APP + "/", APP + "/api/balance", APP + "/apiary", APP + "/login"))
    record("HttpOnly: in the Cookie header, in document.cookie", [True, False],
           sent("a=1; Path=/; HttpOnly", APP + "/", APP + "/") +
           sent("a=1; Path=/; HttpOnly", APP + "/", APP + "/", http=False))
    jar = Browser()
    record("__Host-sid with a Domain attribute",
           "ignored: __Host- needs Secure, Path=/ and no Domain",
           jar.store_cookie("__Host-sid=1; Path=/; Secure; Domain=exampleair.example", APP + "/"))
    record("__Host-sid with Secure and Path=/ only", "stored",
           jar.store_cookie("__Host-sid=1; Path=/; Secure", APP + "/"))
    record("__Secure-sid without Secure", "ignored: __Secure- needs Secure",
           jar.store_cookie("__Secure-sid=1; Path=/", APP + "/"))
    record("SameSite=None without Secure", "ignored: SameSite=None needs Secure",
           jar.store_cookie("sid=1; Path=/; SameSite=None", APP + "/"))

    # ---------------- Part D -------------------------------------------
    section("Part D: SameSite. Which requests carry the session cookie.")

    modes = [("None", "Path=/; Secure; HttpOnly; SameSite=None"),
             ("Lax", "Path=/; Secure; HttpOnly; SameSite=Lax"),
             ("Strict", "Path=/; Secure; HttpOnly; SameSite=Strict"),
             ("unset", "Path=/; Secure; HttpOnly")]
    transfer, get_url = APP + "/api/transfer", APP + "/api/balance"
    rows = [
        ("form POST from evil.example", EVIL, transfer, "POST", "navigation"),
        ("image GET from evil.example", EVIL, get_url, "GET", "subresource"),
        ("script POST from evil.example", EVIL, transfer, "POST", "fetch"),
        ("link GET from evil.example", EVIL, get_url, "GET", "navigation"),
        ("form POST from promo.exampleair.example", PROMO, transfer, "POST", "navigation"),
        ("script POST from the app's own page", APP, transfer, "POST", "fetch"),
        ("address typed by the user", None, get_url, "GET", "navigation"),
    ]
    expected = (["None=sent Lax=withheld Strict=withheld unset=withheld"] * 3 +
                ["None=sent Lax=sent Strict=withheld unset=sent"] +
                ["None=sent Lax=sent Strict=sent unset=sent"] * 3)
    for (label, who, url, method, kind), want in zip(rows, expected):
        cells = []
        for name, attributes in modes:
            api, maya = logged_in(cookie_attributes=attributes)
            page = None if who is None else who + "/page"
            got = maya.send(api, page, url, method, kind, FORM if method == "POST" else None,
                            "to=hotel&miles=1" if method == "POST" else "")
            cells.append("%s=%s" % (name, "sent" if got.cookies else "withheld"))
        record(label, want, " ".join(cells))

    lax, maya = logged_in(cookie_attributes=modes[1][1])
    record("Lax: the hidden form from Part A", "401 no session", forged_form(lax, maya).outcome)
    record("Lax: a link on evil.example to the GET transfer route",
           "200 transferred 10000 to attacker", forged_get(lax, maya, "navigation").outcome)
    fixed, maya = logged_in(cookie_attributes=modes[1][1], state_changing_get=False)
    record("Lax, and GET no longer changes state", "405 use POST",
           forged_get(fixed, maya, "navigation").outcome)
    strict, maya = logged_in(cookie_attributes=modes[2][1])
    record("Strict: the same link", "401 no session",
           forged_get(strict, maya, "navigation").outcome)
    record("Strict: a legitimate link from a partner site to the balance page", "401 no session",
           maya.send(strict, PARTNER + "/offers", APP + "/api/balance").outcome)
    record("Strict: a hidden form on promo.exampleair.example", "200 transferred 10000 to attacker",
           forged_form(strict, maya, PROMO).outcome)
    old, maya = logged_in(Browser(enforce_samesite=False), cookie_attributes=modes[1][1])
    record("Lax, in a browser that does not enforce SameSite",
           "200 transferred 10000 to attacker", forged_form(old, maya).outcome)

    # ---------------- Part E -------------------------------------------
    section("Part E: CSRF tokens. The cookie is Strict and the attacker is on promo.")

    strict_cookie = modes[2][1]
    plant = "csrf=%s; Domain=exampleair.example; Path=/api"
    api, maya = logged_in(cookie_attributes=strict_cookie, csrf="synchronizer")
    page = maya.send(api, APP + "/account", APP + "/api/csrf-token", "GET", "fetch")
    record("synchronizer: the app reads its token and sends it in a header",
           "200 transferred 10000 to hotel",
           own_transfer(api, maya, {"x-csrf-token": page.body["csrf"]}).outcome)
    record("  hidden form with no token", "403 csrf token missing",
           forged_form(api, maya, PROMO).outcome)
    record("  hidden form with a guessed token", "403 csrf token mismatch",
           forged_form(api, maya, PROMO, "&csrf_token=" + "0" * 32).outcome)
    stolen = maya.send(api, PROMO + "/win", APP + "/api/csrf-token", "GET", "fetch")
    record("  a script on promo asks for the token: cookie sent, answer readable",
           [True, False], [bool(stolen.cookies), stolen.readable])

    api, maya = logged_in(cookie_attributes=strict_cookie, csrf="naive")
    record("naive double submit: promo plants its own csrf cookie", "stored",
           maya.store_cookie(plant % "chosen-by-promo", PROMO + "/win"))
    record("  hidden form carrying the planted value", "200 transferred 10000 to attacker",
           forged_form(api, maya, PROMO, "&csrf_token=chosen-by-promo").outcome)

    api, maya = logged_in(cookie_attributes=strict_cookie, csrf="signed")
    maya.store_cookie(plant % "chosen-by-promo", PROMO + "/win")
    record("signed and session-bound: the same plant and form", "403 csrf token invalid",
           forged_form(api, maya, PROMO, "&csrf_token=chosen-by-promo").outcome)
    theirs = Browser()
    theirs.send(api, None, APP + "/login")
    theirs.send(api, APP + "/login", APP + "/login", "POST", "navigation", FORM, "user=attacker")
    own_token = theirs.document_cookie(APP + "/account")["csrf"]
    maya.store_cookie(plant % own_token, PROMO + "/win")
    record("  the attacker's own valid token, planted and submitted", "403 csrf token invalid",
           forged_form(api, maya, PROMO, "&csrf_token=" + own_token).outcome)
    mine = maya.document_cookie(APP + "/account")["csrf"]
    record("  the app's own request, token read from document.cookie",
           "200 transferred 10000 to hotel",
           own_transfer(api, maya, {"x-csrf-token": mine}).outcome)

    api, maya = logged_in(cookie_attributes=strict_cookie, csrf="naive", csrf_cookie="__Host-csrf")
    record("naive with a __Host-csrf cookie: the plant is",
           "ignored: __Host- needs Secure, Path=/ and no Domain",
           maya.store_cookie("__Host-" + plant % "chosen-by-promo" + "; Secure", PROMO + "/win"))
    record("  hidden form carrying the value promo chose", "403 csrf token mismatch",
           forged_form(api, maya, PROMO, "&csrf_token=chosen-by-promo").outcome)

    # ---------------- Part F -------------------------------------------
    section("Part F: Origin and Sec-Fetch-Site. The cookie is SameSite=None again.")

    def told(result):
        return "Origin=%s Sec-Fetch-Site=%s" % (result.headers.get("origin", "absent"),
                                                result.headers.get("sec-fetch-site", "absent"))

    api, maya = logged_in()
    record("the app's own script POST", "Origin=%s Sec-Fetch-Site=same-origin" % APP,
           told(own_transfer(api, maya)))
    record("hidden form on evil.example",
           "Origin=%s Sec-Fetch-Site=cross-site" % EVIL, told(forged_form(api, maya)))
    record("hidden form on promo.exampleair.example", "Origin=%s Sec-Fetch-Site=same-site" % PROMO,
           told(forged_form(api, maya, PROMO)))
    record("link on evil.example, a GET", "Origin=absent Sec-Fetch-Site=cross-site",
           told(forged_get(api, maya, "navigation")))
    record("address typed by the user", "Origin=absent Sec-Fetch-Site=none",
           told(maya.send(api, None, APP + "/api/balance")))

    api, maya = logged_in(check_origin=True)
    record("Origin check: forms on evil, on promo and on a lookalike host",
           ["403 origin not allowed"] * 3,
           [forged_form(api, maya, who).outcome for who in (EVIL, PROMO, LOOKALIKE)])
    record("  the app's own request", "200 transferred 10000 to hotel",
           own_transfer(api, maya).outcome)
    record("  a script client that forges Origin and has no cookie", "401 no session",
           direct(api, "POST", "/api/transfer", (), dict(FORM, origin=APP),
                  "to=attacker&miles=10000"))

    api, maya = logged_in(check_fetch_metadata=True)
    record("Sec-Fetch-Site check: forms on evil, on promo",
           ["403 cross-site request refused", "403 same-site request refused"],
           [forged_form(api, maya).outcome, forged_form(api, maya, PROMO).outcome])
    record("  the app's own request", "200 transferred 10000 to hotel",
           own_transfer(api, maya).outcome)
    api, maya = logged_in(Browser(fetch_metadata=False), check_fetch_metadata=True)
    record("  a browser that sends no Sec-Fetch-Site: the Origin fallback",
           "403 origin not allowed", forged_form(api, maya).outcome)
    api, maya = logged_in(check_fetch_metadata=True, check_origin=True)
    record("both checks on, and a link to the GET transfer route",
           "200 transferred 10000 to attacker", forged_get(api, maya, "navigation").outcome)
    api, maya = logged_in(check_fetch_metadata=True, check_origin=True, state_changing_get=False)
    record("  after GET stops changing state", "405 use POST",
           forged_get(api, maya, "navigation").outcome)

    # ---------------- Part G -------------------------------------------
    section("Part G: session fixation, expiry and logout.")

    def fixation(**config):
        api = Api(Clock(), **config)
        first = api.handle(Request("GET", APP + "/login"))
        known = first.set_cookies[0].split(";")[0].partition("=")[2]
        maya = Browser()
        maya.send(api, EVIL + "/win", APP + "/login?sid=" + known)
        before = sid_in(maya)
        maya.send(api, APP + "/login", APP + "/login", "POST", "navigation", FORM, "user=maya")
        return [before == known, sid_in(maya) == before,
                direct(api, "GET", "/api/balance", [("sid", known)]),
                maya.send(api, None, APP + "/api/balance").outcome]

    record("id kept at login: [planted, unchanged by login, attacker, Maya]",
           [True, True, "200 balance 50000", "200 balance 50000"], fixation())
    record("id regenerated at login", [True, False, "401 no session", "200 balance 50000"],
           fixation(regenerate_at_login=True))
    record("id kept, but never taken from the URL",
           [False, True, "401 no session", "200 balance 50000"], fixation(sid_from_url=False))

    api, maya = logged_in()
    api.clock.now += 14 * 60
    record("a request 14 minutes after the last one", "200 balance 50000",
           maya.send(api, None, APP + "/api/balance").outcome)
    api.clock.now += 16 * 60
    record("a request 16 minutes after that", "401 session expired",
           maya.send(api, None, APP + "/api/balance").outcome)
    api, maya = logged_in()
    busy = []
    for _ in range(49):                # every 10 minutes, for 8 hours 10 minutes
        api.clock.now += 10 * 60
        busy.append(maya.send(api, None, APP + "/api/balance").outcome)
    record("a request every 10 minutes: how many of 49 are answered", 48,
           busy.count("200 balance 50000"))
    record("  and the last one", "401 session expired", busy[-1])

    def logout(**config):
        api, maya = logged_in(**config)
        copied = sid_in(maya)          # the attacker copied this earlier
        maya.send(api, APP + "/account", APP + "/logout", "POST", "fetch")
        return [maya.send(api, None, APP + "/api/balance").outcome,
                direct(api, "GET", "/api/balance", [("sid", copied)])]

    record("logout destroys the session: [browser, a copied id]",
           ["401 no session", "401 no session"], logout())
    record("logout only clears the cookie: [browser, a copied id]",
           ["401 no session", "200 balance 50000"], logout(logout_on_server=False))

    # ---------------- Part H -------------------------------------------
    section("Part H: a bearer token in the Authorization header instead.")

    api, maya = logged_in(auth="bearer")
    bearer = {"authorization": "Bearer " + maya.storage[APP]["access_token"]}
    record("the app's own script attaches the token",
           "200 transferred 10000 to hotel", own_transfer(api, maya, bearer).outcome)
    forged = forged_form(api, maya)
    record("the hidden form from Part A: [cookies attached, answer]",
           [[], "401 no credential"], [forged.cookies, forged.outcome])
    record("a script on evil.example that sets Authorization: unsafe names",
           ["authorization"], unsafe_header_names({"authorization": "Bearer guess"}))
    record("a script injected into the app's page reads from storage",
           ["access_token"], sorted(maya.script_storage(APP + "/account")))
    api, maya = logged_in()
    record("the same script and the HttpOnly session cookie: document.cookie", {},
           maya.document_cookie(APP + "/account"))
    record("  but it can still send a transfer that carries the cookie",
           "200 transferred 10000 to attacker",
           own_transfer(api, maya, body="to=attacker&miles=10000").outcome)

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
