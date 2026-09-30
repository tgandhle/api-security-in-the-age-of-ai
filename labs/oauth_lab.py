#!/usr/bin/env python3
"""Module 4 lab: OAuth basics.

Runs a stub authorization server and two stub resource servers inside this
process. No sockets are opened and no network traffic is sent. Client secrets,
authorization codes, PKCE verifiers and access tokens are generated per run and
are never printed.

Part A walks a client credentials exchange and shows audience checking.
Part B intercepts an authorization code, redeems it as the attacker, then
repeats the interception once PKCE S256 is required, and shows a code replay
revoking the token that was legitimately issued from that code.
Part C shows the two grants RFC 9700 rules out.

Exits non-zero if any check does not produce its expected outcome.

Standard library only. Run from the project root:
    python3 labs/oauth_lab.py
"""
import base64
import hashlib
import hmac
import secrets
import sys

HOTEL_API = "https://api.hotel.example"
LEDGER_API = "https://ledger.hotel.example"
CALLBACK = "https://app.exampleair.example/callback"


def s256(verifier):
    """RFC 7636 section 4.2: BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def new_verifier():
    """RFC 7636 section 4.1: 43 to 128 unreserved characters, high entropy."""
    value = secrets.token_urlsafe(48)
    assert 43 <= len(value) <= 128
    return value


class AuthorizationServer:
    """A deliberately small authorization server. Not for production use."""

    grant_types = ("client_credentials", "authorization_code")
    response_types = ("code",)
    challenge_methods = ("S256",)

    def __init__(self):
        self.clients = {}
        self.codes = {}
        self.tokens = {}

    def register(self, client_id, secret, scopes, redirect_uris, audience):
        self.clients[client_id] = {
            "secret": secret,
            "scopes": set(scopes),
            "redirect_uris": tuple(redirect_uris),
            "audience": audience,
        }

    def _client(self, client_id):
        return self.clients.get(client_id)

    def _issue(self, client_id, scope, audience, code=None):
        token = secrets.token_urlsafe(32)
        self.tokens[token] = {"client_id": client_id, "scope": scope,
                              "audience": audience, "code": code}
        return {"access_token": token, "token_type": "Bearer", "expires_in": 300, "scope": scope}

    def authorize(self, params):
        """Front-channel authorization request. Returns (status, body)."""
        if params.get("response_type") not in self.response_types:
            return 400, {"error": "unsupported_response_type"}
        client = self._client(params.get("client_id"))
        if client is None:
            return 400, {"error": "invalid_request"}
        # RFC 9700 section 2.1: exact string matching of the redirect URI.
        if params.get("redirect_uri") not in client["redirect_uris"]:
            return 400, {"error": "invalid_request"}
        requested = set(params.get("scope", "").split())
        if not requested <= client["scopes"]:
            return 400, {"error": "invalid_scope"}
        method = params.get("code_challenge_method")
        if method is not None and method not in self.challenge_methods:
            return 400, {"error": "invalid_request"}
        code = secrets.token_urlsafe(24)
        self.codes[code] = {
            "client_id": params["client_id"],
            "redirect_uri": params["redirect_uri"],
            "scope": params.get("scope", ""),
            "challenge": params.get("code_challenge"),
            "method": method,
            "used": False,
        }
        return 302, {"code": code}

    def token(self, params):
        """Back-channel token request. Returns (status, body)."""
        grant = params.get("grant_type")
        if grant not in self.grant_types:
            return 400, {"error": "unsupported_grant_type"}
        if grant == "client_credentials":
            return self._client_credentials(params)
        return self._authorization_code(params)

    def _client_credentials(self, params):
        client = self._client(params.get("client_id"))
        presented = params.get("client_secret") or ""
        if client is None or client["secret"] is None:
            return 401, {"error": "invalid_client"}
        if not hmac.compare_digest(presented, client["secret"]):
            return 401, {"error": "invalid_client"}
        requested = set(params.get("scope", "").split())
        if not requested <= client["scopes"]:
            return 400, {"error": "invalid_scope"}
        body = self._issue(params["client_id"], params.get("scope", ""), client["audience"])
        # RFC 6749 section 4.4.3: a refresh token SHOULD NOT be included.
        assert "refresh_token" not in body
        return 200, body

    def _authorization_code(self, params):
        presented = params.get("code")
        record = self.codes.get(presented)
        if record is None:
            return 400, {"error": "invalid_grant"}
        if record["used"]:
            # RFC 6749 section 4.1.2: on reuse the server MUST deny the request
            # and SHOULD revoke tokens previously issued from that code.
            for token, issued in list(self.tokens.items()):
                if issued["code"] == presented:
                    del self.tokens[token]
            return 400, {"error": "invalid_grant"}
        if params.get("client_id") != record["client_id"]:
            return 400, {"error": "invalid_grant"}
        if params.get("redirect_uri") != record["redirect_uri"]:
            return 400, {"error": "invalid_grant"}
        if record["challenge"] is not None:
            verifier = params.get("code_verifier")
            if not verifier:
                return 400, {"error": "invalid_grant"}
            # The method is the one recorded at the authorization request.
            # A method supplied at redemption time is ignored.
            if not hmac.compare_digest(s256(verifier), record["challenge"]):
                return 400, {"error": "invalid_grant"}
        record["used"] = True
        client = self._client(record["client_id"])
        body = self._issue(record["client_id"], record["scope"], client["audience"], presented)
        return 200, body

    def introspect(self, token):
        return self.tokens.get(token)


class ResourceServer:
    """Validates the bearer token and its audience. Nothing else."""

    def __init__(self, name, audience, auth_server, required_scope):
        self.name = name
        self.audience = audience
        self.auth_server = auth_server
        self.required_scope = required_scope

    def call(self, token):
        record = self.auth_server.introspect(token)
        if record is None:
            return 401, {"error": "invalid_token"}
        if record["audience"] != self.audience:
            return 401, {"error": "invalid_token", "reason": "wrong audience"}
        if self.required_scope not in record["scope"].split():
            return 403, {"error": "insufficient_scope"}
        return 200, {"balance": 41250}


def bearer_header(token):
    """RFC 6750 section 2.1. Built to show the shape; nothing is sent."""
    return "Authorization: Bearer " + token


RESULTS = []


def check(label, expected, actual):
    RESULTS.append((label, expected, actual))
    print("%2d. %-40s %s" % (len(RESULTS), label, actual))


def main():
    auth = AuthorizationServer()
    service_secret = secrets.token_urlsafe(32)
    auth.register("svc-transfers", service_secret, ("balance:read", "points:write"), (), HOTEL_API)
    auth.register("app-exampleair", None, ("balance:read",), (CALLBACK,), HOTEL_API)
    hotel = ResourceServer("hotel", HOTEL_API, auth, "balance:read")
    ledger = ResourceServer("ledger", LEDGER_API, auth, "balance:read")

    print("secret source: random, this run only; secrets and tokens never printed")
    print()
    print("Part A: client credentials. A service authenticates as itself.")

    base = {"grant_type": "client_credentials", "client_id": "svc-transfers", "scope": "balance:read"}
    status, body = auth.token(dict(base, client_secret=service_secret))
    check("token request, correct secret", "accept",
          "accept" if status == 200 else "reject: " + body["error"])
    service_token = body.get("access_token")

    check("no refresh token in the response", "pass",
          "pass: RFC 6749 4.4.3" if "refresh_token" not in body else "fail: refresh token present")

    status, body = auth.token(dict(base, client_secret=secrets.token_urlsafe(32)))
    check("wrong client secret", "reject",
          "accept" if status == 200 else "reject: " + body["error"])

    status, body = auth.token(dict(base, client_secret=service_secret, scope="admin:all"))
    check("scope beyond the client's grant", "reject",
          "accept" if status == 200 else "reject: " + body["error"])

    assert bearer_header(service_token).startswith("Authorization: Bearer ")
    status, body = hotel.call(service_token)
    check("token at its intended audience", "accept",
          "accept" if status == 200 else "reject: " + body["error"])

    status, body = ledger.call(service_token)
    check("token at a different resource server", "reject",
          "accept" if status == 200 else "reject: %s, audience" % body["error"])

    print()
    print("Part B: an intercepted authorization code. The attacker has the code.")

    plain_request = {
        "response_type": "code",
        "client_id": "app-exampleair",
        "redirect_uri": CALLBACK,
        "scope": "balance:read",
    }
    status, body = auth.authorize(dict(plain_request))
    stolen = body["code"]
    status, body = auth.token({
        "grant_type": "authorization_code",
        "code": stolen,
        "client_id": "app-exampleair",
        "redirect_uri": CALLBACK,
    })
    check("no PKCE, attacker redeems stolen code", "accept",
          "accept" if status == 200 else "reject: " + body["error"])

    verifier = new_verifier()
    status, body = auth.authorize(dict(plain_request, code_challenge=s256(verifier),
                                       code_challenge_method="S256"))
    protected = body["code"]
    status, body = auth.token({
        "grant_type": "authorization_code",
        "code": protected,
        "client_id": "app-exampleair",
        "redirect_uri": CALLBACK,
    })
    check("S256, attacker has no verifier", "reject",
          "accept" if status == 200 else "reject: " + body["error"])

    status, body = auth.token({
        "grant_type": "authorization_code",
        "code": protected,
        "client_id": "app-exampleair",
        "redirect_uri": CALLBACK,
        "code_verifier": new_verifier(),
    })
    check("S256, attacker invents a verifier", "reject",
          "accept" if status == 200 else "reject: " + body["error"])

    status, body = auth.token({
        "grant_type": "authorization_code",
        "code": protected,
        "client_id": "app-exampleair",
        "redirect_uri": CALLBACK,
        "code_verifier": s256(verifier),
        "code_challenge_method": "plain",
    })
    check("S256, attacker claims method plain", "reject",
          "accept" if status == 200 else "reject: " + body["error"])

    status, body = auth.token({
        "grant_type": "authorization_code",
        "code": protected,
        "client_id": "app-exampleair",
        "redirect_uri": CALLBACK,
        "code_verifier": verifier,
    })
    check("S256, real client sends its verifier", "accept",
          "accept" if status == 200 else "reject: " + body["error"])
    user_token = body.get("access_token")

    status, body = hotel.call(user_token)
    check("the new token at the hotel API", "accept",
          "accept" if status == 200 else "reject: " + body["error"])

    status, body = auth.token({
        "grant_type": "authorization_code",
        "code": protected,
        "client_id": "app-exampleair",
        "redirect_uri": CALLBACK,
        "code_verifier": verifier,
    })
    check("same code redeemed twice", "reject",
          "accept" if status == 200 else "reject: " + body["error"])

    status, body = hotel.call(user_token)
    check("the first token after that code replay", "reject",
          "accept" if status == 200 else "reject: " + body["error"])

    verifier2 = new_verifier()
    status, body = auth.authorize(dict(plain_request, redirect_uri=CALLBACK + "/",
                                       code_challenge=s256(verifier2),
                                       code_challenge_method="S256"))
    check("redirect URI off by one character", "reject",
          "accept" if status == 302 else "reject: " + body["error"])

    status, body = auth.authorize(dict(plain_request, code_challenge=s256(verifier2),
                                       code_challenge_method="plain"))
    check("authorization request asks for plain", "reject",
          "accept" if status == 302 else "reject: " + body["error"])

    print()
    print("Part C: the grants RFC 9700 rules out.")

    status, body = auth.token({
        "grant_type": "password",
        "client_id": "app-exampleair",
        "username": "member@exampleair.example",
        "scope": "balance:read",
    })
    check("password grant", "reject",
          "accept" if status == 200 else "reject: " + body["error"])

    status, body = auth.authorize(dict(plain_request, response_type="token"))
    check("response_type=token", "reject",
          "accept" if status == 302 else "reject: " + body["error"])

    failures = [(label, expected, actual) for label, expected, actual in RESULTS
                if not actual.startswith(expected)]
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
