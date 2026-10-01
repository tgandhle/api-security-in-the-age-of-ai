#!/usr/bin/env python3
"""Module 20 lab: MCP server authorization.

Pinned to MCP protocol revision 2026-07-28, which the specification's
versioning page calls the current revision.

An MCP server is an OAuth 2.1 resource server with a tool-shaped front end.
Almost everything the specification requires of it is a rule you have met
already in this course. What is new is how many of those rules are stated as
MUST, and how many deployments fail them because the MCP server and the API
behind it share one authorization server.

Part A is audience validation and the token passthrough anti-pattern, with
the two servers sharing an issuer so the signature check cannot help.
Part B implements the canonical resource URI rules and runs the
specification's own valid and invalid examples. Part C implements the
RFC 9207 issuer validation table exactly as the specification prints it,
including the comparison rules it forbids. Part D is the WWW-Authenticate
challenge and the step-up flow's scope union. Part E is state handle
hijacking, which replaced session hijacking in this revision because MCP is
now stateless. Part F is scope minimization and what the client's documented
fallback does when a server publishes its whole catalogue.

Tokens are real HS256 JWTs, minted with hmac and checked with
hmac.compare_digest. Keys are generated for this run and never printed.
Nothing opens a socket.

Needs nothing beyond Python 3.

Exit codes: 0 all checks matched, 1 a check did not match.
"""
import base64
import hashlib
import hmac
import json
import secrets
import sys
import urllib.parse

NOW = 1790000000

MCP_SERVER = "https://mcp.exampletools.example/mcp"
UPSTREAM_API = "https://api.examplecrm.example"
SHARED_AS = "https://login.examplecorp.example"


class Refused(Exception):
    pass


# ---------------------------------------------------------------- JWT plumbing

def b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def unb64u(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def mint(payload, key):
    head = b64u(json.dumps({"alg": "HS256", "typ": "JWT"},
                           separators=(",", ":"), sort_keys=True).encode())
    body = b64u(json.dumps(payload, separators=(",", ":"),
                           sort_keys=True).encode())
    signed = ("%s.%s" % (head, body)).encode("ascii")
    return "%s.%s.%s" % (head, body,
                         b64u(hmac.new(key, signed, hashlib.sha256).digest()))


def verify(token, key, now=NOW):
    head, body, sig = token.split(".")
    signed = ("%s.%s" % (head, body)).encode("ascii")
    if not hmac.compare_digest(
            sig, b64u(hmac.new(key, signed, hashlib.sha256).digest())):
        raise Refused("signature does not verify")
    payload = json.loads(unb64u(body))
    if payload.get("exp", 0) <= now:
        raise Refused("expired")
    return payload


# ------------------------------------------------- the canonical resource URI

def canonical_resource(text):
    """Apply the 2026-07-28 canonical server URI rules.

    The specification defines the canonical URI as the RFC 8707 resource
    identifier, gives four valid examples and two invalid ones, says the
    form without a trailing slash is preferred for interoperability, and
    says implementations should accept uppercase scheme and host for
    robustness. Returns the normalised URI or raises Refused.
    """
    parts = urllib.parse.urlsplit(text)
    if not parts.scheme:
        raise Refused("missing scheme")
    if parts.fragment or "#" in text:
        raise Refused("contains fragment")
    if parts.scheme.lower() not in ("https", "http"):
        raise Refused("scheme is not http or https")
    if not parts.netloc:
        raise Refused("missing host")
    # Uppercase scheme and host are accepted, and lowercased here. The path
    # is left exactly as given, because a path can be case significant.
    netloc = parts.netloc.lower()
    path = parts.path
    if path == "/":
        path = ""          # prefer the form without a trailing slash
    return urllib.parse.urlunsplit(
        (parts.scheme.lower(), netloc, path, parts.query, ""))


# ----------------------------------------------- RFC 9207 issuer validation

def check_iss(advertised, iss_present, iss_value, recorded):
    """The four-row table the specification prints, in order.

    advertised is authorization_response_iss_parameter_supported.
    Comparison is simple string comparison per RFC 3986 section 6.2.1, and
    the specification forbids applying case folding, default-port elision,
    trailing-slash or percent-encoding normalisation first.
    """
    if advertised and not iss_present:
        return "reject: iss absent though the server advertises it"
    if iss_present:
        if iss_value == recorded:          # simple string comparison, only
            return "proceed"
        return "reject: iss does not match the recorded issuer"
    return "proceed"


# ------------------------------------------------------------- the MCP server

class McpServer:
    """An MCP server acting as an OAuth 2.1 resource server."""

    def __init__(self, resource, key, check_audience=True, scopes=None,
                 pass_token_upstream=False, bind_handles=True,
                 random_handles=True, scopes_supported=None):
        self.resource = resource
        self.key = key
        self.check_audience = check_audience
        self.scopes = dict(scopes or {})
        self.pass_token_upstream = pass_token_upstream
        self.bind_handles = bind_handles
        self.random_handles = random_handles
        self.scopes_supported = list(scopes_supported or [])
        self.state = {}
        self.counter = 0
        self.upstream = None

    # The 401 the specification's flow starts with.
    def challenge(self, scope=None):
        parts = ['Bearer resource_metadata="%s/.well-known/'
                 'oauth-protected-resource"' % self.resource.rstrip("/")]
        if scope:
            parts.append('scope="%s"' % scope)
        return "401 " + ", ".join(parts)

    def insufficient(self, scope):
        return ('403 Bearer error="insufficient_scope", scope="%s"' % scope)

    def call(self, name, token=None, handle=None, now=NOW):
        if token is None:
            return self.challenge(self.scopes.get(name))
        try:
            claims = verify(token, self.key, now)
        except Refused as exc:
            return "401 %s" % exc
        # "MCP servers MUST validate that access tokens were issued
        # specifically for them as the intended audience."
        if self.check_audience:
            aud = claims.get("aud")
            auds = aud if isinstance(aud, list) else [aud]
            if self.resource not in auds:
                return "401 token audience is %r, not this server" % aud
        need = self.scopes.get(name)
        if need and need not in claims.get("scope", "").split():
            return self.insufficient(need)
        if name == "fetch_customer":
            return self.fetch(claims, token)
        if name == "open_cart":
            return self.open_cart(claims)
        if name == "read_cart":
            return self.read_cart(claims, handle)
        return "200 ok"

    # Part A: what the server sends upstream.
    def fetch(self, claims, token):
        if self.pass_token_upstream:
            # The anti-pattern: forward the client's token unchanged.
            return "upstream says: " + self.upstream.call(token)
        # Correct: a separate token the MCP server obtains for itself, for
        # the upstream's audience, naming the user as the party it acts for.
        own = mint({"iss": SHARED_AS, "aud": UPSTREAM_API,
                    "sub": self.resource, "act": {"sub": claims["sub"]},
                    "scope": "customers:read", "exp": NOW + 300},
                   self.key)
        return "upstream says: " + self.upstream.call(own)

    # Part E: state handles replace sessions in this revision.
    def open_cart(self, claims):
        self.counter += 1
        handle = ("cart-%s" % secrets.token_hex(8)) if self.random_handles \
            else "cart-%d" % self.counter
        slot = "%s:%s" % (claims["sub"], handle) if self.bind_handles else handle
        self.state[slot] = {"owner": claims["sub"], "items": ["seat-14C"]}
        return handle

    def read_cart(self, claims, handle):
        slot = "%s:%s" % (claims["sub"], handle) if self.bind_handles else handle
        if slot not in self.state:
            return "404 no such cart for this caller"
        return "200 " + ",".join(self.state[slot]["items"])


class UpstreamApi:
    def __init__(self, key, audience):
        self.key = key
        self.audience = audience

    def call(self, token, now=NOW):
        try:
            claims = verify(token, self.key, now)
        except Refused as exc:
            return "401 %s" % exc
        aud = claims.get("aud")
        if aud != self.audience:
            return "401 wrong audience"
        caller = claims.get("sub")
        on_behalf = claims.get("act", {}).get("sub", "nobody named")
        return "200 served %s for %s" % (caller, on_behalf)


# --------------------------------------------- Part D: the client's step-up

def parse_challenge(header):
    """Pull the parameters out of a WWW-Authenticate Bearer challenge."""
    out = {}
    for piece in header.split(" ", 2)[-1].split(", "):
        if "=" in piece:
            k, v = piece.split("=", 1)
            out[k.replace("Bearer ", "").strip()] = v.strip().strip('"')
    return out


def step_up(previous, challenged, union=True):
    """The specification: compute the union of previous and challenged."""
    if union:
        return sorted(set(previous) | set(challenged))
    return sorted(set(challenged))


RESULTS = []


def check(label, expected, actual):
    RESULTS.append((label, expected, actual))
    print("%2d. %-54s %s" % (len(RESULTS), label, actual))


def main():
    # One authorization server, so one signing key. The MCP server and the
    # API behind it both verify against it, which is the common deployment
    # and the reason the audience claim is the only thing that separates
    # them. other_key belongs to an unrelated authorization server.
    as_key = secrets.token_bytes(32)
    other_key = secrets.token_bytes(32)
    print("MCP protocol revision 2026-07-28")
    print("signing keys: random, this run only; nothing is printed")
    print()

    upstream = UpstreamApi(as_key, UPSTREAM_API)
    tools = {"fetch_customer": "customers:read", "open_cart": "cart:write",
             "read_cart": "cart:read"}

    strict = McpServer(MCP_SERVER, as_key, scopes=tools)
    strict.upstream = upstream
    loose = McpServer(MCP_SERVER, as_key, check_audience=False, scopes=tools)
    loose.upstream = upstream

    for_mcp = mint({"iss": SHARED_AS, "aud": MCP_SERVER, "sub": "user-41",
                    "scope": "customers:read cart:read cart:write",
                    "exp": NOW + 300}, as_key)
    for_api = mint({"iss": SHARED_AS, "aud": UPSTREAM_API, "sub": "user-41",
                    "scope": "customers:read", "exp": NOW + 300}, as_key)

    print("Part A: audience validation, and token passthrough.")
    check("no token at all",
          '401 Bearer resource_metadata="https://mcp.exampletools.example/mcp'
          '/.well-known/oauth-protected-resource", scope="customers:read"',
          strict.call("fetch_customer"))
    check("a token issued for this MCP server",
          "upstream says: 200 served https://mcp.exampletools.example/mcp "
          "for user-41",
          strict.call("fetch_customer", for_mcp))
    check("a token issued for the API behind it",
          "401 token audience is 'https://api.examplecrm.example', "
          "not this server",
          strict.call("fetch_customer", for_api))
    def signature_ok(token):
        try:
            verify(token, as_key)
            return "yes"
        except Refused as exc:
            return "no: %s" % exc

    check("  did its signature verify", "yes", signature_ok(for_api))
    check("the same token to a server that skips the audience check",
          "upstream says: 200 served https://mcp.exampletools.example/mcp "
          "for user-41",
          loose.call("fetch_customer", for_api))
    passthrough = McpServer(MCP_SERVER, as_key, check_audience=False,
                            scopes=tools, pass_token_upstream=True)
    passthrough.upstream = upstream
    check("  and that also forwards the token unchanged",
          "upstream says: 200 served user-41 for nobody named",
          passthrough.call("fetch_customer", for_api))
    check("  the caller the upstream log names after a passthrough",
          "user-41", verify(for_api, as_key)["sub"])
    check("  the caller it names when the MCP server holds its own token",
          "https://mcp.exampletools.example/mcp",
          strict.call("fetch_customer", for_mcp).split("served ")[1]
          .split(" for ")[0])
    # A token from an authorization server with nothing to do with either.
    elsewhere = mint({"iss": "https://login.attacker.example",
                      "aud": MCP_SERVER, "sub": "user-41",
                      "scope": "customers:read", "exp": NOW + 300}, other_key)
    check("a token from an unrelated authorization server",
          "401 signature does not verify",
          strict.call("fetch_customer", elsewhere))
    check("  the same token to the server that skips the audience check",
          "401 signature does not verify",
          loose.call("fetch_customer", elsewhere))

    print()
    print("Part B: the canonical resource URI, with the spec's own examples.")
    # The mcp.example.com hostnames below are the specification's own printed
    # examples, quoted unchanged so they can be compared with it line by line.
    # Everywhere else this course uses the reserved .example domain. example.com
    # is itself reserved for documentation by RFC 2606 section 3.
    for text, expected in [
            ("https://mcp.example.com/mcp", "https://mcp.example.com/mcp"),
            ("https://mcp.example.com", "https://mcp.example.com"),
            ("https://mcp.example.com:8443", "https://mcp.example.com:8443"),
            ("https://mcp.example.com/server/mcp",
             "https://mcp.example.com/server/mcp"),
            ("mcp.example.com", "refused: missing scheme"),
            ("https://mcp.example.com#fragment", "refused: contains fragment"),
            ("https://mcp.example.com/", "https://mcp.example.com"),
            ("HTTPS://MCP.Example.COM/mcp", "https://mcp.example.com/mcp")]:
        try:
            got = canonical_resource(text)
        except Refused as exc:
            got = "refused: %s" % exc
        check("  %s" % text, expected, got)
    check("the resource parameter as it appears in the request",
          "resource=https%3A%2F%2Fmcp.example.com",
          "resource=" + urllib.parse.quote("https://mcp.example.com",
                                           safe=""))

    print()
    print("Part C: the RFC 9207 issuer validation table.")
    recorded = SHARED_AS
    check("advertises iss, iss present and matching", "proceed",
          check_iss(True, True, SHARED_AS, recorded))
    check("advertises iss, iss absent",
          "reject: iss absent though the server advertises it",
          check_iss(True, False, None, recorded))
    check("does not advertise, iss present and matching", "proceed",
          check_iss(False, True, SHARED_AS, recorded))
    check("does not advertise, iss absent", "proceed",
          check_iss(False, False, None, recorded))
    check("iss from another authorization server",
          "reject: iss does not match the recorded issuer",
          check_iss(True, True, "https://login.attacker.example", recorded))
    for variant, why in [(SHARED_AS + "/", "a trailing slash"),
                         (SHARED_AS.replace("login", "LOGIN"), "a capital"),
                         (SHARED_AS + ":443", "the default port")]:
        check("  differing only by %s" % why,
              "reject: iss does not match the recorded issuer",
              check_iss(True, True, variant, recorded))

    print()
    print("Part D: the challenge, and the step-up scope union.")
    granted = ["cart:read"]
    narrow = mint({"iss": SHARED_AS, "aud": MCP_SERVER, "sub": "user-41",
                   "scope": " ".join(granted), "exp": NOW + 300}, as_key)
    denied = strict.call("open_cart", narrow)
    check("a cart:read token calling a cart:write tool",
          '403 Bearer error="insufficient_scope", scope="cart:write"', denied)
    challenge = parse_challenge(denied)
    check("  the error the challenge names", "insufficient_scope",
          challenge.get("error", "no error parameter"))
    check("  the scope it names", "cart:write",
          challenge.get("scope", "no scope parameter"))
    union = step_up(granted, challenge.get("scope", "").split())
    check("scopes a client that unions will ask for",
          "['cart:read', 'cart:write']", str(union))
    replaced = step_up(granted, challenge.get("scope", "").split(),
                        union=False)
    check("scopes a client that replaces will ask for", "['cart:write']",
          str(replaced))
    reissued = mint({"iss": SHARED_AS, "aud": MCP_SERVER, "sub": "user-41",
                     "scope": " ".join(union), "exp": NOW + 300}, as_key)
    lost = mint({"iss": SHARED_AS, "aud": MCP_SERVER, "sub": "user-41",
                 "scope": " ".join(replaced), "exp": NOW + 300}, as_key)
    after_union = strict.call("open_cart", reissued)
    check("the unioned token, on the tool that first failed",
          "a handle, not a challenge",
          "a handle, not a challenge" if after_union.startswith("cart-")
          else after_union),
    check("the replaced token, back on the tool it had working",
          '403 Bearer error="insufficient_scope", scope="cart:read"',
          strict.call("read_cart", lost, handle="cart-1"))

    print()
    print("Part E: state handles, which replaced sessions in this revision.")
    bound = McpServer(MCP_SERVER, as_key, scopes=tools)
    victim = mint({"iss": SHARED_AS, "aud": MCP_SERVER, "sub": "user-41",
                   "scope": "cart:read cart:write", "exp": NOW + 300}, as_key)
    attacker = mint({"iss": SHARED_AS, "aud": MCP_SERVER, "sub": "user-99",
                     "scope": "cart:read cart:write", "exp": NOW + 300},
                    as_key)
    handle = bound.open_cart(verify(victim, as_key))
    check("the owner reading their own cart", "200 seat-14C",
          bound.read_cart(verify(victim, as_key), handle))
    check("another caller presenting the same handle",
          "404 no such cart for this caller",
          bound.read_cart(verify(attacker, as_key), handle))
    unbound = McpServer(MCP_SERVER, as_key, scopes=tools, bind_handles=False,
                        random_handles=False)
    guessable = unbound.open_cart(verify(victim, as_key))
    check("a server that keys state by the handle alone", "cart-1", guessable)
    check("  the same caller reading it", "200 seat-14C",
          unbound.read_cart(verify(attacker, as_key), guessable))
    check("  and the next handle it will mint", "cart-2",
          "cart-%d" % (unbound.counter + 1))
    check("handle length when generated with secrets", "21", str(len(handle)))

    print()
    print("Part F: scope minimization, and the client's documented fallback.")
    catalogue = ["admin:all", "cart:read", "cart:write", "customers:read",
                 "customers:write", "files:read", "files:write"]
    minimal = ["cart:read", "customers:read"]
    wide = McpServer(MCP_SERVER, as_key, scopes=tools,
                     scopes_supported=catalogue)
    thin = McpServer(MCP_SERVER, as_key, scopes=tools,
                     scopes_supported=minimal)

    def initial_scopes(server, challenge_scope=None):
        # The specification's priority order: the challenge's scope if it
        # has one, otherwise every scope in scopes_supported.
        if challenge_scope:
            return sorted(challenge_scope.split())
        return sorted(server.scopes_supported)

    check("challenge carries a scope, so the client asks for that",
          "['customers:read']",
          str(initial_scopes(wide, "customers:read")))
    check("challenge carries none, against the full catalogue",
          str(sorted(catalogue)), str(initial_scopes(wide)))
    check("  how many scopes that token would carry", "7",
          str(len(initial_scopes(wide))))
    check("challenge carries none, against a minimal list",
          "['cart:read', 'customers:read']", str(initial_scopes(thin)))
    check("  how many scopes that token would carry", "2",
          str(len(initial_scopes(thin))))
    check("  whether admin:all is among them", "no",
          "yes" if "admin:all" in initial_scopes(thin) else "no")
    check("  and among the other one's", "yes",
          "yes" if "admin:all" in initial_scopes(wide) else "no")

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
