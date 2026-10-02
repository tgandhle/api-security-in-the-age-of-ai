#!/usr/bin/env python3
"""Module 17 lab: cross-origin resource sharing.

Python 3, standard library only. On Windows use `py -3` wherever this page
shows `python3`.

Nothing here opens a socket. There is no browser and no server. The lab
implements the algorithms the Fetch Standard specifies and runs requests and
responses through them as data, so every verdict is reproducible and the
output is identical on every run and every platform.

What is modelled, and from where (Fetch Standard, Living Standard, Last
Updated 21 September 2026):

  Part A  the CORS-safelisted request-header check and the CORS-unsafe
          request-header names algorithm, which together decide whether a
          preflight happens at all.
  Part B  the CORS check, section 4.10, run against the credentials
          combinations tabulated in section 3.3.5.
  Part C  the preflight response checks from CORS-preflight fetch,
          section 4.8.
  Part D  the CORS-preflight cache, section 4.9.
  Part E  a server that reflects any Origin, which the standard calls the
          confused deputy problem.

Deliberate simplifications, so nothing here is mistaken for a conformant
implementation:

  * MIME parsing keeps only what the safelist needs: the essence, lowercased,
    with parameters discarded. The standard's full parser is in the MIME
    Sniffing Standard.
  * Range parsing accepts `bytes=<first>-<last>` and `bytes=<first>-` and
    rejects everything else, which is enough to show why a suffix range such
    as `bytes=-500` is not safelisted.
  * The network partition key is a plain string, not the real structure.
  * Origins use the reserved `.example` domain. The combinations in Part B are
    the ones tabulated in section 3.3.5 with the origin changed from the
    standard's `rabbit.invalid` to `rabbit.example`; the outcomes are the
    standard's.
"""

import sys

RESULTS = []
CHECKS = 0


def section(title):
    RESULTS.append((None, title, None))


def record(label, expected, actual):
    """Numbers are assigned here so adding a check cannot renumber the rest."""
    global CHECKS
    CHECKS += 1
    RESULTS.append(("%2d. %s" % (CHECKS, label), expected, actual))


# ---------------------------------------------------------------------------
# Header model. A header list is a list of (name, value) pairs, because a
# request can carry the same header name twice and that turns out to matter.
# ---------------------------------------------------------------------------

def get(headers, name):
    """Getting a header: the values joined by ", ", or None if absent."""
    values = [v for n, v in headers if n.lower() == name.lower()]
    if not values:
        return None
    return ", ".join(values)


# --- the safelist ----------------------------------------------------------

CORS_SAFELISTED_METHODS = ("GET", "HEAD", "POST")
FORBIDDEN_METHODS = ("CONNECT", "TRACE", "TRACK")

# "A CORS-unsafe request-header byte is a byte byte for which one of the
# following is true: byte is less than 0x20 and is not 0x09 HT; byte is 0x22,
# 0x28, 0x29, 0x3A, 0x3C, 0x3E, 0x3F, 0x40, 0x5B, 0x5C, 0x5D, 0x7B, 0x7D, or
# 0x7F DEL."
UNSAFE_BYTES = {0x22, 0x28, 0x29, 0x3A, 0x3C, 0x3E, 0x3F, 0x40,
                0x5B, 0x5C, 0x5D, 0x7B, 0x7D, 0x7F}

# The byte set accept-language and content-language are restricted to.
LANGUAGE_EXTRA = {0x20, 0x2A, 0x2C, 0x2D, 0x2E, 0x3B, 0x3D}

SAFELISTED_CONTENT_TYPES = ("application/x-www-form-urlencoded",
                            "multipart/form-data", "text/plain")

# "A CORS non-wildcard request-header name is a header name that is a
# byte-case-insensitive match for `Authorization`."
NON_WILDCARD_REQUEST_HEADERS = ("authorization",)

SAFELISTED_RESPONSE_HEADERS = ("cache-control", "content-language",
                               "content-length", "content-type", "expires",
                               "last-modified", "pragma")


def unsafe_byte(value):
    for ch in value:
        b = ord(ch)
        if b < 0x20 and b != 0x09:
            return True
        if b in UNSAFE_BYTES:
            return True
    return False


def language_ok(value):
    for ch in value:
        b = ord(ch)
        if 0x30 <= b <= 0x39 or 0x41 <= b <= 0x5A or 0x61 <= b <= 0x7A:
            continue
        if b in LANGUAGE_EXTRA:
            continue
        return False
    return True


def essence(value):
    """The lowercased type/subtype, parameters discarded. None if unparsable."""
    head = value.split(";")[0].strip().lower()
    if head.count("/") != 1:
        return None
    kind, sub = head.split("/")
    if not kind or not sub:
        return None
    return head


def single_range(value):
    """Returns (first, last) or None. Only the forms browsers emit."""
    if not value.startswith("bytes="):
        return None
    spec = value[len("bytes="):]
    if "-" not in spec or "," in spec:
        return None
    first, _, last = spec.partition("-")
    if first == "":
        # A suffix range such as bytes=-500. first is null, so not safelisted.
        return (None, last or None)
    if not first.isdigit():
        return None
    if last != "" and not last.isdigit():
        return None
    return (int(first), int(last) if last else None)


def safelisted_request_header(name, value):
    """Fetch Standard: to determine whether a header is a CORS-safelisted
    request-header."""
    if len(value) > 128:
        return False
    key = name.lower()
    if key == "accept":
        return not unsafe_byte(value)
    if key in ("accept-language", "content-language"):
        return language_ok(value)
    if key == "content-type":
        if unsafe_byte(value):
            return False
        mime = essence(value)
        if mime is None:
            return False
        return mime in SAFELISTED_CONTENT_TYPES
    if key == "range":
        parsed = single_range(value)
        if parsed is None:
            return False
        return parsed[0] is not None
    return False


NORMALIZED_METHODS = ("DELETE", "GET", "HEAD", "OPTIONS", "POST", "PUT")


def normalize_method(method):
    """Fetch Standard: to normalize a method, byte-uppercase it if it is a
    byte-case-insensitive match for one of a fixed list. Anything else, such
    as a lowercase `patch`, is left exactly as it was."""
    if method.upper() in NORMALIZED_METHODS:
        return method.upper()
    return method


def naive_content_type(headers):
    """NOT the standard. A server that reads the first Content-Type header it
    finds and ignores the rest, which is what the standard's note about
    forgiving parsers is warning about."""
    for name, value in headers:
        if name.lower() == "content-type":
            return essence(value)
    return None


def forgiving_content_type(headers):
    """NOT the standard either. The last valid Content-Type wins, the way a
    forgiving MIME extractor behaves."""
    chosen = None
    for name, value in headers:
        if name.lower() != "content-type":
            continue
        parsed = essence(value)
        if parsed is not None:
            chosen = parsed
    return chosen


def unsafe_request_header_names(headers):
    """Fetch Standard: the CORS-unsafe request-header names."""
    unsafe = []
    potentially_unsafe = []
    safelist_value_size = 0
    for name, value in headers:
        if not safelisted_request_header(name, value):
            unsafe.append(name)
        else:
            potentially_unsafe.append(name)
            safelist_value_size += len(value)
    if safelist_value_size > 1024:
        unsafe.extend(potentially_unsafe)
    return sorted({n.lower() for n in unsafe})


def forgiving_unsafe_names(headers):
    """NOT the standard. This is the variant the standard warns about: it
    combines duplicate Content-Type headers and lets the last valid one win,
    the way a forgiving MIME extractor would."""
    merged = []
    seen_content_type = False
    for name, value in headers:
        if name.lower() == "content-type":
            continue
        merged.append((name, value))
    values = [v for n, v in headers if n.lower() == "content-type"]
    for value in reversed(values):
        if essence(value) is not None:
            merged.append(("content-type", value))
            seen_content_type = True
            break
    if values and not seen_content_type:
        merged.append(("content-type", values[-1]))
    return unsafe_request_header_names(merged)


def needs_preflight(method, headers, unsafe_names=None):
    """A preflight happens when the method is not safelisted or any header is
    CORS-unsafe."""
    names = unsafe_request_header_names(headers) if unsafe_names is None \
        else unsafe_names
    if method.upper() in FORBIDDEN_METHODS:
        return True
    if method.upper() not in CORS_SAFELISTED_METHODS:
        return True
    return bool(names)


# --- the CORS check, section 4.10 -----------------------------------------

def cors_check(request_origin, credentials_mode, response_headers):
    """Fetch Standard 4.10, step for step. Returns "success" or "failure"."""
    origin = get(response_headers, "Access-Control-Allow-Origin")
    if origin is None:                                   # step 2
        return "failure"
    if credentials_mode != "include" and origin == "*":  # step 3
        return "success"
    if request_origin != origin:                         # step 4
        return "failure"
    if credentials_mode != "include":                    # step 5
        return "success"
    credentials = get(response_headers, "Access-Control-Allow-Credentials")
    if credentials == "true":                            # step 7, byte exact
        return "success"
    return "failure"                                     # step 8


# --- preflight response checks, section 4.8 -------------------------------

OK_STATUSES = range(200, 300)
MAX_AGE_DEFAULT = 5
MAX_AGE_IMPOSED_LIMIT = 600


def split_values(raw):
    if raw is None:
        return None
    return [part.strip() for part in raw.split(",") if part.strip()]


def preflight_fetch(request_origin, method, headers, credentials_mode,
                    response_status, response_headers,
                    use_cors_preflight=False):
    """The checks CORS-preflight fetch performs on the preflight response.
    Returns ("ok", max_age) or ("network error", reason)."""
    if cors_check(request_origin, credentials_mode, response_headers) != "success":
        return ("network error", "CORS check failed on the preflight response")
    if response_status not in OK_STATUSES:
        return ("network error", "preflight status %d is not an ok status"
                % response_status)

    methods = split_values(get(response_headers, "Access-Control-Allow-Methods"))
    header_names = split_values(
        get(response_headers, "Access-Control-Allow-Headers"))
    if methods is None and use_cors_preflight:
        methods = [method]
    methods = methods or []
    lowered = [h.lower() for h in (header_names or [])]

    if method not in methods and method.upper() not in CORS_SAFELISTED_METHODS:
        if credentials_mode == "include" or "*" not in methods:
            return ("network error",
                    "method %s is not allowed by the preflight" % method)

    for name, _ in headers:
        if name.lower() in NON_WILDCARD_REQUEST_HEADERS \
                and name.lower() not in lowered:
            return ("network error",
                    "%s is a non-wildcard name and was not listed" % name)

    for unsafe in unsafe_request_header_names(headers):
        if unsafe in lowered:
            continue
        if credentials_mode == "include" or "*" not in lowered:
            return ("network error",
                    "header %s is not allowed by the preflight" % unsafe)

    max_age = get(response_headers, "Access-Control-Max-Age")
    if max_age is None or not max_age.lstrip("-").isdigit():
        max_age = MAX_AGE_DEFAULT
    else:
        max_age = int(max_age)
    if max_age > MAX_AGE_IMPOSED_LIMIT:
        max_age = MAX_AGE_IMPOSED_LIMIT
    return ("ok", max_age)


# --- the preflight cache, section 4.9 -------------------------------------

class PreflightCache:
    """Fetch Standard 4.9. Entries are (key, origin, url, max_age,
    credentials, method, header_name) with a stored time."""

    def __init__(self):
        self.entries = []

    def store(self, key, origin, url, max_age, credentials, method=None,
              header_name=None, now=0):
        self.entries.append({"key": key, "origin": origin, "url": url,
                             "max_age": max_age, "credentials": credentials,
                             "method": method, "header_name": header_name,
                             "stored": now})

    def _live(self, now):
        return [e for e in self.entries if now - e["stored"] < e["max_age"]]

    def _matches(self, entry, key, origin, url, credentials_mode):
        if (entry["key"], entry["origin"], entry["url"]) != (key, origin, url):
            return False
        if entry["credentials"]:
            return True
        return credentials_mode != "include"

    def method_match(self, key, origin, url, credentials_mode, method, now=0):
        for e in self._live(now):
            if not self._matches(e, key, origin, url, credentials_mode):
                continue
            if e["method"] == method or e["method"] == "*":
                return True
        return False

    def header_match(self, key, origin, url, credentials_mode, header_name,
                     now=0):
        for e in self._live(now):
            if not self._matches(e, key, origin, url, credentials_mode):
                continue
            stored = e["header_name"]
            if stored is None:
                continue
            if stored.lower() == header_name.lower():
                return True
            # "its header name is `*` and headerName is not a CORS
            # non-wildcard request-header name"
            if stored == "*" and \
                    header_name.lower() not in NON_WILDCARD_REQUEST_HEADERS:
                return True
        return False


# --- servers used in Part E -----------------------------------------------

def reflecting_server(request_origin):
    """Echoes whatever Origin it is given and allows credentials."""
    return [("Access-Control-Allow-Origin", request_origin),
            ("Access-Control-Allow-Credentials", "true")]


ALLOWED_ORIGINS = ("https://app.examplehotels.example",
                   "https://admin.examplehotels.example")


def allowlist_server(request_origin):
    if request_origin in ALLOWED_ORIGINS:
        return [("Access-Control-Allow-Origin", request_origin),
                ("Access-Control-Allow-Credentials", "true"),
                ("Vary", "Origin")]
    return [("Vary", "Origin")]


# ===========================================================================


def main():
    print("origins use the reserved .example domain; no request leaves this process")
    # ---------------- Part A -------------------------------------------
    section("Part A: whether a preflight happens at all.")

    form_post = [("Content-Type", "application/x-www-form-urlencoded")]
    record("form POST, safelisted content type: unsafe names", [],
           unsafe_request_header_names(form_post))
    record("  so a preflight is", False,
           needs_preflight("POST", form_post))

    json_post = [("Content-Type", "application/json")]
    record("JSON POST: unsafe names", ["content-type"],
           unsafe_request_header_names(json_post))
    record("  so a preflight is", True,
           needs_preflight("POST", json_post))

    record("a DELETE with no headers still preflights", True,
           needs_preflight("DELETE", []))
    record("post is normalized, so the safelist sees", "POST",
           normalize_method("post"))
    record("  and that normalized method skips the preflight", False,
           needs_preflight(normalize_method("post"), form_post))
    record("patch is not in the normalize list, so it stays", "patch",
           normalize_method("patch"))
    record("  which a server matching on PATCH would not recognise", False,
           normalize_method("patch") == "PATCH")

    # The attack the standard's own note describes.
    doubled = [("Content-Type", "application/json"),
               ("Content-Type", "text/plain")]
    record("duplicated content type, per the standard", ["content-type"],
           unsafe_request_header_names(doubled))
    record("  so the standard requires a preflight", True,
           needs_preflight("POST", doubled))
    forgiving = forgiving_unsafe_names(doubled)
    record("the same request under a forgiving parser", [], forgiving)
    record("  which would skip the preflight", False,
           needs_preflight("POST", doubled, unsafe_names=forgiving))
    record("  a server reading the first content type sees",
           "application/json", naive_content_type(doubled))
    record("  a forgiving extractor sees", "text/plain",
           forgiving_content_type(doubled))
    record("  so the safelist and the server disagree", True,
           naive_content_type(doubled) != forgiving_content_type(doubled))

    long_accept = [("Accept", "text/plain" + "," * 130)]
    record("a safelisted name whose value is this many bytes", 140,
           len(long_accept[0][1]))
    record("  over the 128 byte limit, so not safelisted", False,
           safelisted_request_header(*long_accept[0]))

    # The aggregate limit. Every value here is exactly 128 bytes, the most a
    # single safelisted value may be, so the only thing that varies is how
    # many of them the request carries.
    def maxed(seed):
        return [("Accept", seed * 128),
                ("Accept-Language", chr(ord(seed) + 1) * 128),
                ("Content-Language", chr(ord(seed) + 2) * 128),
                ("Content-Type", "text/plain;x=" + chr(ord(seed) + 3) * 115)]

    four = maxed("a")
    record("four headers, each value exactly", [128, 128, 128, 128],
           [len(v) for _, v in four])
    record("  each one alone is safelisted", [True, True, True, True],
           [safelisted_request_header(n, v) for n, v in four])
    record("  combined value size", 512, sum(len(v) for _, v in four))
    record("  unsafe names", [], unsafe_request_header_names(four))

    eight = four + maxed("f")
    record("eight of them, combined value size", 1024,
           sum(len(v) for _, v in eight))
    record("  exactly 1024 is not over 1024, so unsafe names", [],
           unsafe_request_header_names(eight))
    record("  and a GET still skips the preflight", False,
           needs_preflight("GET", eight))

    nine = eight + [("Accept", "k" * 128)]
    record("one more header, combined value size", 1152,
           sum(len(v) for _, v in nine))
    record("  now over the limit, so every safelisted name turns unsafe",
           ["accept", "accept-language", "content-language", "content-type"],
           unsafe_request_header_names(nine))
    record("  so the same GET now preflights", True,
           needs_preflight("GET", nine))

    record("a byte range browsers emit is safelisted", True,
           safelisted_request_header("Range", "bytes=0-499"))
    record("an open-ended range is safelisted", True,
           safelisted_request_header("Range", "bytes=500-"))
    record("a suffix range is not", False,
           safelisted_request_header("Range", "bytes=-500"))
    record("a colon in an Accept value is an unsafe byte", True,
           unsafe_byte("text/plain:x"))
    record("Authorization is never safelisted", False,
           safelisted_request_header("Authorization", "Bearer x"))


    # ---------------- Part B -------------------------------------------
    section("Part B: the CORS check, on the combinations the standard tabulates.")

    caller = "https://rabbit.example"

    def row(mode, acao, acac):
        headers = [("Access-Control-Allow-Origin", acao)]
        if acac is not None:
            headers.append(("Access-Control-Allow-Credentials", acac))
        return cors_check(caller, mode, headers)

    table = [
        ("omit", "*", None, "success"),
        ("omit", "*", "true", "success"),
        ("omit", "https://rabbit.example/", None, "failure"),
        ("omit", "https://rabbit.example", None, "success"),
        ("include", "*", "true", "failure"),
        ("include", "https://rabbit.example", "true", "success"),
        ("include", "https://rabbit.example", "True", "failure"),
    ]
    for mode, acao, acac, expected in table:
        shown = acac if acac is not None else "omitted"
        record("credentials %-8s allow-origin %-24s allow-credentials %-7s"
               % (mode, acao, shown), expected, row(mode, acao, acac))

    record("no allow-origin header at all", "failure",
           cors_check(caller, "omit", [("Vary", "Origin")]))
    record("the literal string null is not the absent header", "failure",
           cors_check(caller, "omit", [("Access-Control-Allow-Origin", "null")]))
    record("  but it succeeds for an opaque origin", "success",
           cors_check("null", "omit",
                      [("Access-Control-Allow-Origin", "null")]))


    # ---------------- Part C -------------------------------------------
    section("Part C: what the preflight response has to say.")

    api = "https://api.examplehotels.example"
    app = "https://app.examplehotels.example"

    bearer = [("Authorization", "Bearer <secret from vault>"),
              ("Content-Type", "application/json")]

    wildcard_headers = [("Access-Control-Allow-Origin", app),
                        ("Access-Control-Allow-Credentials", "true"),
                        ("Access-Control-Allow-Methods", "PATCH"),
                        ("Access-Control-Allow-Headers", "*")]
    outcome, detail = preflight_fetch(app, "PATCH", bearer, "include", 204,
                                      wildcard_headers)
    record("allow-headers is * and the request sends Authorization",
           "network error", outcome)
    record("  because", "Authorization is a non-wildcard name and was not listed",
           detail)

    named_headers = wildcard_headers[:3] + [
        ("Access-Control-Allow-Headers", "authorization, content-type")]
    outcome, max_age = preflight_fetch(app, "PATCH", bearer, "include", 204,
                                       named_headers)
    record("naming it explicitly", "ok", outcome)
    record("  max age with no header, the default", 5, max_age)

    outcome, detail = preflight_fetch(app, "PATCH", bearer, "include", 301,
                                      named_headers)
    record("a preflight answered with 301", "network error", outcome)
    record("  because", "preflight status 301 is not an ok status", detail)

    star_methods = [("Access-Control-Allow-Origin", app),
                    ("Access-Control-Allow-Credentials", "true"),
                    ("Access-Control-Allow-Methods", "*"),
                    ("Access-Control-Allow-Headers", "authorization, content-type")]
    outcome, detail = preflight_fetch(app, "PATCH", bearer, "include", 204,
                                      star_methods)
    record("allow-methods is * and credentials are included",
           "network error", outcome)
    record("  the same response without credentials", "ok",
           preflight_fetch(app, "PATCH", [("Content-Type", "application/json")],
                           "omit", 204,
                           [("Access-Control-Allow-Origin", "*"),
                            ("Access-Control-Allow-Methods", "*"),
                            ("Access-Control-Allow-Headers", "*")])[0])

    capped = named_headers + [("Access-Control-Max-Age", "86400")]
    record("a max age of 86400 is clamped to the imposed limit", 600,
           preflight_fetch(app, "PATCH", bearer, "include", 204, capped)[1])
    unparsable = named_headers + [("Access-Control-Max-Age", "forever")]
    record("an unparsable max age falls back to the default", 5,
           preflight_fetch(app, "PATCH", bearer, "include", 204,
                           unparsable)[1])


    # ---------------- Part D -------------------------------------------
    section("Part D: the preflight cache.")

    cache = PreflightCache()
    cache.store("partition-a", app, api + "/bookings", max_age=600,
                credentials=True, method="PATCH", now=0)
    cache.store("partition-a", app, api + "/bookings", max_age=600,
                credentials=True, header_name="*", now=0)

    record("the cached method is reused", True,
           cache.method_match("partition-a", app, api + "/bookings",
                              "include", "PATCH", now=59))
    record("a different path is a different entry", False,
           cache.method_match("partition-a", app, api + "/payments",
                              "include", "PATCH", now=59))
    record("a different partition key does not match", False,
           cache.method_match("partition-b", app, api + "/bookings",
                              "include", "PATCH", now=59))
    record("after the max age has passed", False,
           cache.method_match("partition-a", app, api + "/bookings",
                              "include", "PATCH", now=601))
    record("a cached * header name covers content-type", True,
           cache.header_match("partition-a", app, api + "/bookings",
                              "include", "Content-Type", now=59))
    record("  but never covers Authorization", False,
           cache.header_match("partition-a", app, api + "/bookings",
                              "include", "Authorization", now=59))

    nocreds = PreflightCache()
    nocreds.store("partition-a", app, api + "/bookings", max_age=600,
                  credentials=False, method="PATCH", now=0)
    record("an entry stored without credentials serves a request without them",
           True, nocreds.method_match("partition-a", app, api + "/bookings",
                                      "omit", "PATCH", now=10))
    record("  and does not serve one with them", False,
           nocreds.method_match("partition-a", app, api + "/bookings",
                                "include", "PATCH", now=10))


    # ---------------- Part E -------------------------------------------
    section("Part E: a server that reflects whatever Origin it is given.")

    attacker = "https://booking-rewards.example"

    record("the reflecting server answers the real app", "success",
           cors_check(app, "include", reflecting_server(app)))
    record("  and answers the attacker just as happily", "success",
           cors_check(attacker, "include", reflecting_server(attacker)))
    record("  what it echoed back to the attacker", attacker,
           get(reflecting_server(attacker), "Access-Control-Allow-Origin"))

    record("the allowlist server answers the real app", "success",
           cors_check(app, "include", allowlist_server(app)))
    record("  and refuses the attacker", "failure",
           cors_check(attacker, "include", allowlist_server(attacker)))
    record("  by omitting the header rather than denying it", None,
           get(allowlist_server(attacker), "Access-Control-Allow-Origin"))
    record("  while still varying on Origin for caches", "Origin",
           get(allowlist_server(attacker), "Vary"))

    origins = [app, "https://admin.examplehotels.example", attacker,
               "https://app.examplehotels.example.evil.example",
               "http://app.examplehotels.example"]
    reflected = [cors_check(o, "include", reflecting_server(o)) for o in origins]
    allowed = [cors_check(o, "include", allowlist_server(o)) for o in origins]
    record("five origins against the reflecting server",
           ["success", "success", "success", "success", "success"], reflected)
    record("the same five against the allowlist",
           ["success", "success", "failure", "failure", "failure"], allowed)
    record("  what the allowlist actually sent each of the five",
           [app, "https://admin.examplehotels.example", None, None, None],
           [get(allowlist_server(o), "Access-Control-Allow-Origin")
            for o in origins])

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


if __name__ == "__main__":
    sys.exit(main())
