#!/usr/bin/env python3
"""Module 36 lab: client authentication, PAR and high-assurance OAuth.

Module 4 built the authorization code grant with PKCE. This lab adds the
controls a high-assurance deployment puts around it, one attack at a time.

  Part A  client authentication. A shared client secret works for anyone who
          has seen it. With private_key_jwt (RFC 7523) the server stores a
          public key, and the assertion's signature, audience, expiry and jti
          are each checked.
  Part B  pushed authorization requests (RFC 9126). A request edited in the
          browser is accepted as sent. A pushed request cannot be edited, and
          its request_uri is single use, short lived, bound to the client and
          unguessable.
  Part C  rich authorization requests (RFC 9396). A coarse scope pays anyone.
          authorization_details names one payee and one amount, and the
          resource server has to enforce every field.
  Part D  step-up authentication (RFC 9470). An old or weak user
          authentication is challenged with insufficient_user_authentication.
  Part E  the controls together, on a server configured as the FAPI 2.0
          Security Profile requires. Rich authorization requests and step-up
          are added on top: the profile requires neither. Then one request
          that none of it stops.

ExampleBank, ExamplePay and ExampleAir are fictional. The authorization
server, the client and the resource server are Python objects in this file
and a request is a method call. Nothing opens a socket, starts a thread or a
process, writes a file or reads a clock: time is a number the lab advances.

What is real: every client assertion is a JWT built and checked by hand, with
a real ES256 (ECDSA P-256) or HS256 signature, and PKCE uses real SHA-256.

Deliberate simplifications:

  * Access tokens are opaque random strings and the resource server learns
    what they mean by calling the authorization server's introspect method.
    Modules 5 and 6 cover JWT access tokens and introspection.
  * The sender constraint in Part E is simulated. The key a caller proved on
    its connection is passed to the handler directly, as module 7's lab does
    for mutual TLS. Module 7 builds the real proofs.
  * tls_client_auth and self_signed_tls_client_auth are not modelled. The
    lab implements client_secret_basic, client_secret_post, client_secret_jwt
    and private_key_jwt.
  * The user is an object that approves whatever the consent screen shows.
  * One-time use of a request_uri is enforced when the authorization request
    is processed. RFC 9126 recommends one-time use and lets a server allow a
    reload; this server does not.
  * The server's reasons are spelled out so each refusal can be told apart.
    A production server says less.

Keys, secrets, assertions, codes, tokens and request_uri values stay in
memory and are never printed.

This lab needs one package:
    python3 -m pip install cryptography==50.0.1
Inside an activated virtual environment the command is python, not py -3.

Exit codes: 0 all checks matched, 1 a check did not match, 2 the package is
missing so nothing ran.
"""
import base64
import hashlib
import hmac
import json
import secrets
import sys

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import (
        decode_dss_signature, encode_dss_signature)
except ImportError:
    print("This lab needs the cryptography package, because Python has no")
    print("asymmetric cryptography in its standard library.")
    print()
    print("    python3 -m pip install cryptography==50.0.1")
    print()
    print("Most labs in this course need nothing beyond Python 3.")
    sys.exit(2)

ISSUER = "https://auth.examplebank.example"
API = "https://api.examplebank.example"
REDIRECT = "https://app.examplepay.example/cb"
JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
URN = "urn:ietf:params:oauth:request_uri:"
ACR_PWD = "https://acr.examplebank.example/pwd"
ACR_MFA = "https://acr.examplebank.example/mfa"

START = 1790000000             # a fixed starting time, in seconds
ASSERTION_LIFETIME = 60        # what the lab's clients put in exp
MAX_ASSERTION_LIFETIME = 300   # this server refuses an exp further away
REQUEST_URI_LIFETIME = 60      # expires_in of a pushed request
CODE_LIFETIME = 60
TOKEN_LIFETIME = 3600
PAYMENT_MAX_AGE = 300          # the payment endpoint's step-up policy

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


class Clock:
    def __init__(self, now):
        self.now = now

    def advance(self, seconds):
        self.now += seconds


# ---------------------------------------------------------------------------
# JWTs by hand. Three base64url parts joined by dots (RFC 7519, RFC 7515).
# ---------------------------------------------------------------------------

def b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64u_decode(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def compact(obj):
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


def jwt_es256(private_key, claims):
    """ES256: the signature is R and S, 32 bytes each, not DER."""
    signing_input = "%s.%s" % (b64u(compact({"alg": "ES256", "typ": "JWT"})),
                               b64u(compact(claims)))
    der = private_key.sign(signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return signing_input + "." + b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def jwt_hs256(secret, claims):
    signing_input = "%s.%s" % (b64u(compact({"alg": "HS256", "typ": "JWT"})),
                               b64u(compact(claims)))
    mac = hmac.new(secret, signing_input.encode("ascii"), hashlib.sha256).digest()
    return signing_input + "." + b64u(mac)


def jwt_parts(token):
    """Header, claims, signing input and signature, or None if malformed.
    Nothing returned here is trusted until the signature has been checked."""
    try:
        head, body, sig = token.split(".")
        header = json.loads(b64u_decode(head))
        claims = json.loads(b64u_decode(body))
        signature = b64u_decode(sig)
    except (ValueError, AttributeError):
        return None
    if not isinstance(header, dict) or not isinstance(claims, dict):
        return None
    return header, claims, ("%s.%s" % (head, body)).encode("ascii"), signature


def es256_ok(public_key, signing_input, signature):
    if len(signature) != 64:
        return False
    der = encode_dss_signature(int.from_bytes(signature[:32], "big"),
                               int.from_bytes(signature[32:], "big"))
    try:
        public_key.verify(der, signing_input, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


def public_bytes(public_key):
    """The P-256 public key as an uncompressed point: 0x04, then X and Y."""
    numbers = public_key.public_numbers()
    return b"\x04" + numbers.x.to_bytes(32, "big") + numbers.y.to_bytes(32, "big")


def thumbprint(public_key):
    """Stands in for a certificate or JWK thumbprint. None stays None."""
    if public_key is None:
        return None
    return hashlib.sha256(public_bytes(public_key)).hexdigest()


def s256(verifier):
    return b64u(hashlib.sha256(verifier.encode("ascii")).digest())


def basic(client_id, secret):
    return "Basic " + base64.b64encode(("%s:%s" % (client_id, secret)).encode()).decode()


# ---------------------------------------------------------------------------
# The authorization server.
# ---------------------------------------------------------------------------

# One authorization details type, defined by this API (RFC 9396 section 2).
# Every field is required and no other field is allowed.
DETAIL_TYPES = {"payment_initiation": {
    "type": str, "actions": list, "locations": list, "instructedAmount": dict,
    "creditorName": str, "creditorAccount": str}}


class AuthorizationServer:
    """ExampleBank's authorization server.

    track_jti      remember each assertion's jti until it expires
    aud_policy     "rfc9126": the issuer, the token endpoint URL or the PAR
                   endpoint URL identify this server (RFC 9126 section 2).
                   "issuer-string": only the issuer, as a string (FAPI 2.0
                   Security Profile section 5.3.2.1).
    require_par    require_pushed_authorization_requests for every client
    allowed_methods  which client authentication methods this server accepts
    require_bound_tokens  refuse to issue a token that is not bound to a key
    """

    def __init__(self, clock, clients, track_jti=True, aud_policy="rfc9126",
                 require_par=False, require_bound_tokens=False,
                 allowed_methods=("client_secret_basic", "client_secret_post",
                                  "client_secret_jwt", "private_key_jwt")):
        self.clock = clock
        self.clients = clients
        self.track_jti = track_jti
        self.aud_policy = aud_policy
        self.require_par = require_par
        self.require_bound_tokens = require_bound_tokens
        self.allowed_methods = tuple(allowed_methods)
        self.issuer = ISSUER
        self.token_endpoint = ISSUER + "/token"
        self.par_endpoint = ISSUER + "/par"
        self.seen_jti = {}     # (client_id, jti) -> exp
        self.pushed = {}       # request_uri -> entry
        self.codes = {}        # code -> grant
        self.tokens = {}       # access token -> record

    # -- client authentication (RFC 6749 section 2.3, RFC 7523 section 3) --

    def authenticate(self, request):
        """Returns (client, verdict). client is None unless authenticated."""
        headers, form = request.get("headers", {}), request.get("form", {})
        presented = [name for name, present in (
            ("client_secret_basic", headers.get("authorization", "").startswith("Basic ")),
            ("client_secret_post", "client_secret" in form),
            ("assertion", "client_assertion" in form)) if present]
        if not presented:
            return None, "invalid_client: no client authentication"
        if len(presented) > 1:
            return None, "invalid_client: more than one method"
        if presented[0] == "assertion":
            return self._authenticate_assertion(form)
        if presented[0] == "client_secret_basic":
            try:
                decoded = base64.b64decode(headers["authorization"][6:]).decode()
            except ValueError:
                return None, "invalid_client: malformed"
            client_id, _, secret = decoded.partition(":")
        else:
            client_id, secret = form.get("client_id"), form["client_secret"]
        client = self.clients.get(client_id)
        if client is None or client["method"] != presented[0]:
            return None, "invalid_client: method not registered for this client"
        if presented[0] not in self.allowed_methods:
            return None, "invalid_client: method not accepted by this server"
        offered = hashlib.sha256(secret.encode()).digest()
        if not hmac.compare_digest(offered, client["secret_hash"]):
            return None, "invalid_client: wrong secret"
        return client, "authenticated"

    def _authenticate_assertion(self, form):
        if form.get("client_assertion_type") != JWT_BEARER:
            return None, "invalid_client: assertion type"
        parts = jwt_parts(form["client_assertion"])
        if parts is None:
            return None, "invalid_client: malformed"
        header, claims, signing_input, signature = parts
        # The subject names the client. It is only a lookup key until the
        # signature below has been verified with that client's key.
        client = self.clients.get(claims.get("sub"))
        if client is None or client["method"] not in ("client_secret_jwt", "private_key_jwt"):
            return None, "invalid_client: method not registered for this client"
        if "client_id" in form and form["client_id"] != client["client_id"]:
            return None, "invalid_client: client_id does not match the assertion"
        if client["method"] not in self.allowed_methods:
            return None, "invalid_client: method not accepted by this server"
        # The algorithm comes from the registration, never from the header.
        if client["method"] == "private_key_jwt":
            if header.get("alg") != "ES256":
                return None, "invalid_client: alg is not the registered one"
            good = es256_ok(client["public_key"], signing_input, signature)
        else:
            if header.get("alg") != "HS256":
                return None, "invalid_client: alg is not the registered one"
            expected = hmac.new(client["secret"], signing_input, hashlib.sha256).digest()
            good = hmac.compare_digest(signature, expected)
        if not good:
            return None, "invalid_client: signature"
        if claims.get("iss") != client["client_id"]:
            return None, "invalid_client: iss is not the client"
        if not self._audience_ok(claims.get("aud")):
            return None, "invalid_client: audience"
        exp, now = claims.get("exp"), self.clock.now
        if not isinstance(exp, int) or now >= exp:
            return None, "invalid_client: expired"
        if exp - now > MAX_ASSERTION_LIFETIME:
            return None, "invalid_client: lifetime too long"
        jti = claims.get("jti")
        if not isinstance(jti, str) or not jti:
            return None, "invalid_client: jti missing"
        if self.track_jti:
            # Entries are dropped once the assertion they came from has
            # expired, so the record never outgrows the lifetime cap.
            self.seen_jti = {k: e for k, e in self.seen_jti.items() if e > now}
            if (client["client_id"], jti) in self.seen_jti:
                return None, "invalid_client: jti already used"
            # Recorded last, after the signature and every claim passed, so
            # a forged assertion cannot fill the record.
            self.seen_jti[(client["client_id"], jti)] = exp
        return client, "authenticated"

    def _audience_ok(self, aud):
        if self.aud_policy == "issuer-string":
            return aud == self.issuer
        values = aud if isinstance(aud, list) else [aud]
        return any(v in (self.issuer, self.token_endpoint, self.par_endpoint)
                   for v in values)

    # -- validating an authorization request, pushed or not --

    def _validate(self, client, params):
        if params.get("response_type") != "code":
            return "unsupported_response_type"
        if params.get("redirect_uri") not in client["redirect_uris"]:
            return "invalid_request: redirect_uri"
        if not params.get("code_challenge") or params.get("code_challenge_method") != "S256":
            return "invalid_request: PKCE with S256 is required"
        for value in params.get("scope", "").split():
            if value not in client["scopes"]:
                return "invalid_scope"
        if "authorization_details" in params:
            return self._validate_details(client, params["authorization_details"])
        return None

    def _validate_details(self, client, text):
        """RFC 9396 section 5: refuse what the type definition does not allow."""
        try:
            details = json.loads(text)
        except ValueError:
            details = None
        if not isinstance(details, list) or not details:
            return "invalid_authorization_details: not an array of objects"
        for item in details:
            kind = item.get("type") if isinstance(item, dict) else None
            if kind not in DETAIL_TYPES:
                return "invalid_authorization_details: unknown type"
            if kind not in client["detail_types"]:
                return "invalid_authorization_details: type not allowed for this client"
            spec = DETAIL_TYPES[kind]
            unknown = sorted(set(item) - set(spec))
            if unknown:
                return "invalid_authorization_details: unknown field %s" % unknown[0]
            for field in sorted(spec):
                if field not in item:
                    return "invalid_authorization_details: missing field %s" % field
                if not isinstance(item[field], spec[field]):
                    return "invalid_authorization_details: wrong type for %s" % field
        return None

    # -- the pushed authorization request endpoint (RFC 9126 section 2) --

    def par(self, request):
        client, verdict = self.authenticate(request)
        if client is None:
            return 401, {"error": verdict}
        form = request["form"]
        if "request_uri" in form:
            return 400, {"error": "invalid_request: request_uri is not allowed here"}
        params = {k: v for k, v in form.items()
                  if k not in ("client_assertion", "client_assertion_type", "client_secret")}
        params["client_id"] = client["client_id"]
        error = self._validate(client, params)
        if error:
            return 400, {"error": error}
        request_uri = URN + secrets.token_urlsafe(32)   # 32 random bytes
        self.pushed[request_uri] = {
            "client_id": client["client_id"], "params": params, "used": False,
            "expires_at": self.clock.now + REQUEST_URI_LIFETIME}
        return 201, {"request_uri": request_uri, "expires_in": REQUEST_URI_LIFETIME}

    # -- the authorization endpoint, reached through the user's browser --

    def authorize(self, query, user):
        """Returns the parameters of the redirect back to the client."""
        client = self.clients.get(query.get("client_id"))
        if client is None:
            return {"error": "invalid_request: unknown client"}
        if "request_uri" in query:
            entry = self.pushed.get(query["request_uri"])
            if entry is None:
                return self._redirect({"error": "invalid_request: unknown request_uri"})
            if entry["client_id"] != client["client_id"]:
                return self._redirect({"error": "invalid_request: request_uri belongs to another client"})
            if self.clock.now >= entry["expires_at"]:
                return self._redirect({"error": "invalid_request: request_uri expired"})
            if entry["used"]:
                return self._redirect({"error": "invalid_request: request_uri already used"})
            entry["used"] = True
            # Only what was pushed is used. Anything else on the URL is ignored.
            params = entry["params"]
        else:
            if self.require_par or client.get("require_par"):
                return self._redirect({"error": "invalid_request: a pushed authorization request is required"})
            params = dict(query)
            error = self._validate(client, params)
            if error:
                return self._redirect({"error": error})

        # User authentication, to the strength and recency the request asks.
        wanted = params.get("acr_values", "").split()
        max_age = params.get("max_age")
        session = user["session"]
        fresh = max_age is None or self.clock.now - session["auth_time"] <= int(max_age)
        if not fresh or (wanted and session["acr"] not in wanted):
            session["acr"] = ACR_MFA if "otp" in user["factors"] else ACR_PWD
            session["auth_time"] = self.clock.now
            if wanted and session["acr"] not in wanted:
                return self._redirect({"error": "unmet_authentication_requirements"})

        details = json.loads(params["authorization_details"]) \
            if "authorization_details" in params else None
        user["seen"].append(consent_text(params.get("scope", ""), details))
        code = secrets.token_urlsafe(32)
        self.codes[code] = {
            "client_id": client["client_id"], "sub": user["sub"],
            "scope": params.get("scope", ""), "details": details,
            "challenge": params["code_challenge"],
            "auth_time": session["auth_time"], "acr": session["acr"],
            "expires_at": self.clock.now + CODE_LIFETIME, "used": False}
        return self._redirect({"code": code, "state": params.get("state")})

    def _redirect(self, params):
        params["iss"] = self.issuer      # RFC 9207 section 2
        return params

    # -- the token endpoint --

    def token(self, request, conn_key=None):
        client, verdict = self.authenticate(request)
        if client is None:
            return 401, {"error": verdict}
        form = request["form"]
        if form.get("grant_type") != "authorization_code":
            return 400, {"error": "unsupported_grant_type"}
        grant = self.codes.get(form.get("code"))
        if grant is None or grant["used"] or self.clock.now >= grant["expires_at"] \
                or grant["client_id"] != client["client_id"]:
            return 400, {"error": "invalid_grant"}
        if not hmac.compare_digest(s256(form.get("code_verifier", "")), grant["challenge"]):
            return 400, {"error": "invalid_grant"}
        if self.require_bound_tokens and conn_key is None:
            return 400, {"error": "invalid_request: no key to bind the token to"}
        grant["used"] = True
        access_token = secrets.token_urlsafe(32)
        self.tokens[access_token] = {
            "client_id": client["client_id"], "sub": grant["sub"],
            "scope": grant["scope"], "details": grant["details"],
            "auth_time": grant["auth_time"], "acr": grant["acr"],
            "cnf": thumbprint(conn_key), "exp": self.clock.now + TOKEN_LIFETIME}
        body = {"access_token": access_token, "token_type": "Bearer",
                "expires_in": TOKEN_LIFETIME, "scope": grant["scope"]}
        if grant["details"] is not None:
            body["authorization_details"] = grant["details"]   # RFC 9396 section 7
        return 200, body

    def introspect(self, access_token):
        """What the resource server is told (RFC 7662, RFC 9396 section 9.2,
        RFC 9470 section 6.2)."""
        entry = self.tokens.get(access_token)
        if entry is None or self.clock.now >= entry["exp"]:
            return {"active": False}
        info = {"active": True, "client_id": entry["client_id"], "sub": entry["sub"],
                "scope": entry["scope"], "exp": entry["exp"],
                "auth_time": entry["auth_time"], "acr": entry["acr"]}
        if entry["details"] is not None:
            info["authorization_details"] = entry["details"]
        if entry["cnf"] is not None:
            info["cnf"] = entry["cnf"]
        return info


def consent_text(scope, details):
    """What the user is asked to approve, built from the request itself."""
    lines = []
    if "accounts:read" in scope.split():
        lines.append("read your balance")
    if "payments:write" in scope.split():
        lines.append("make payments from your account")
    for item in details or []:
        amount = item["instructedAmount"]
        lines.append("pay %s %s to %s (%s)" % (amount.get("amount"), amount.get("currency"),
                                               item["creditorName"], item["creditorAccount"]))
    return "; ".join(lines)


# ---------------------------------------------------------------------------
# The resource server.
# ---------------------------------------------------------------------------

class PaymentsAPI:
    """ExampleBank's payments API.

    enforce      "fields": a payment must match the creditor account, amount
                 and currency of a granted payment_initiation object.
                 "type-only": any granted payment_initiation object will do.
    step_up      apply the payment endpoint's authentication policy
    check_owner  read the owner from the stored payment before returning it
    """

    def __init__(self, auth_server, enforce="fields", step_up=False, check_owner=True):
        self.auth_server = auth_server
        self.enforce = enforce
        self.step_up = step_up
        self.check_owner = check_owner
        self.payments = {"pay-7002": {"owner": "customer-42", "amount": "310.00",
                                      "currency": "EUR", "creditor": "acct-landlord"}}
        self.next_id = 7003

    def handle(self, method, path, token, body=None, conn_key=None):
        """Returns one line: a status, then a WWW-Authenticate value or a note."""
        info = self.auth_server.introspect(token)
        if not info["active"]:
            return '401 Bearer error="invalid_token"'
        # A bound token is only good from the key it is bound to (module 7).
        if "cnf" in info and info["cnf"] != thumbprint(conn_key):
            return '401 Bearer error="invalid_token"'
        scopes = info["scope"].split()
        granted = [d for d in info.get("authorization_details", [])
                   if d["type"] == "payment_initiation" and API + "/payments" in d["locations"]]

        if (method, path) == ("GET", "/accounts"):
            if "accounts:read" not in scopes:
                return '403 Bearer error="insufficient_scope", scope="accounts:read"'
            return "200 balance of %s" % info["sub"]

        if (method, path) == ("POST", "/payments"):
            if "payments:write" not in scopes and not self._covers(granted, body):
                return '403 Bearer error="insufficient_scope"'
            # The authentication policy is applied only after the token has
            # been validated, so an invalid token never learns the policy.
            if self.step_up:
                age = self.auth_server.clock.now - info["auth_time"]
                if info["acr"] != ACR_MFA or age > PAYMENT_MAX_AGE:
                    return ('401 Bearer error="insufficient_user_authentication", '
                            'acr_values="%s", max_age="%d"' % (ACR_MFA, PAYMENT_MAX_AGE))
            payment_id = "pay-%d" % self.next_id
            self.next_id += 1
            self.payments[payment_id] = dict(body, owner=info["sub"])
            return "201 paid %s %s to %s" % (body["amount"], body["currency"], body["creditor"])

        if method == "GET" and path.startswith("/payments/"):
            if "payments:write" not in scopes and \
                    not any("status" in d["actions"] for d in granted):
                return '403 Bearer error="insufficient_scope"'
            payment = self.payments.get(path[len("/payments/"):])
            if payment is None:
                return "404 not found"
            # Module 9: the owner comes from the stored object, and a
            # payment the caller may not see looks like one that is absent.
            if self.check_owner and payment["owner"] != info["sub"]:
                return "404 not found"
            return "200 %s %s to %s, owned by %s" % (
                payment["amount"], payment["currency"], payment["creditor"], payment["owner"])
        return "404 not found"

    def _covers(self, granted, body):
        for d in granted:
            if "initiate" not in d["actions"]:
                continue
            if self.enforce == "type-only":
                return True
            if d["creditorAccount"] == body["creditor"] \
                    and d["instructedAmount"].get("amount") == body["amount"] \
                    and d["instructedAmount"].get("currency") == body["currency"]:
                return True
        return False


# ---------------------------------------------------------------------------
# The client, ExamplePay.
# ---------------------------------------------------------------------------

def claims_for(client_id, aud, now, lifetime=ASSERTION_LIFETIME):
    """The claims of a client assertion (RFC 7523 section 3)."""
    return {"iss": client_id, "sub": client_id, "aud": aud, "iat": now,
            "exp": now + lifetime, "jti": secrets.token_urlsafe(16)}


def assertion_form(assertion, **extra):
    return {"headers": {}, "form": dict(extra, client_assertion=assertion,
                                        client_assertion_type=JWT_BEARER)}


def parse_challenge(line):
    """Reads error, acr_values, max_age and scope out of a Bearer challenge.
    Covers the shape this lab's resource server emits."""
    found = {}
    for piece in line.split("Bearer ", 1)[1].split(", "):
        name, _, value = piece.partition("=")
        found[name] = value.strip('"')
    return found


def run_flow(server, key, user, extra, use_par=True, edit=None, conn_key=None,
             client_id="examplepay", expected_iss=ISSUER, forge_iss=None):
    """One authorization code flow. Returns a dict describing how it ended.

    edit       a function applied to the front-channel parameters, standing
               in for whoever can change the URL in the browser
    forge_iss  replaces the iss the client receives, standing in for a
               response that came from a different authorization server
    """
    verifier = secrets.token_urlsafe(32)
    params = dict({"response_type": "code", "redirect_uri": REDIRECT,
                   "state": secrets.token_urlsafe(8), "code_challenge": s256(verifier),
                   "code_challenge_method": "S256"}, **extra)

    def assertion():
        return jwt_es256(key, claims_for(client_id, server.issuer, server.clock.now))

    if use_par:
        status, body = server.par(assertion_form(assertion(), **params))
        if status != 201:
            return {"ended": "par", "error": body["error"]}
        front = {"client_id": client_id, "request_uri": body["request_uri"]}
    else:
        front = dict(params, client_id=client_id)
    if edit is not None:
        edit(front)
    response = server.authorize(front, user)
    if forge_iss is not None:
        response = dict(response, iss=forge_iss)
    # RFC 9207 section 2.4: compare iss with the server the request went to.
    if response.get("iss") != expected_iss:
        return {"ended": "client", "error": "client refused: iss is not the expected issuer"}
    if "error" in response:
        return {"ended": "authorize", "error": response["error"]}
    status, body = server.token(
        assertion_form(assertion(), grant_type="authorization_code",
                       code=response["code"], code_verifier=verifier),
        conn_key=conn_key)
    if status != 200:
        return {"ended": "token", "error": body["error"]}
    return {"ended": "token issued", "token": body["access_token"], "response": body,
            "asked": params}


def summary(flow):
    return flow["ended"] if "error" not in flow else flow["error"]


def outcome(response):
    """One word for what the authorization endpoint sent back."""
    return "code issued" if "code" in response else response["error"]


def payment_details(amount="45.00", creditor="acct-exampleair", name="ExampleAir",
                    actions=("initiate", "status"), **extra):
    item = dict({"type": "payment_initiation", "actions": list(actions),
                 "locations": [API + "/payments"], "creditorName": name,
                 "creditorAccount": creditor,
                 "instructedAmount": {"currency": "EUR", "amount": amount}}, **extra)
    return json.dumps([item], sort_keys=True)


def new_user(clock, factors=("pwd", "otp"), acr=ACR_PWD, age=7200):
    """A customer whose current session began `age` seconds ago."""
    return {"sub": "customer-17", "factors": list(factors), "seen": [],
            "session": {"acr": acr, "auth_time": clock.now - age}}


def forge_from_store(server, client_id):
    """Can whoever holds the server's client record mint an assertion?

    A stored shared secret signs. A stored public key does not: it has no
    sign method, which is the whole point.
    """
    client = server.clients[client_id]
    claims = claims_for(client_id, server.issuer, server.clock.now)
    if "secret" in client:
        return jwt_hs256(client["secret"], claims)
    if hasattr(client.get("public_key"), "sign"):
        return jwt_es256(client["public_key"], claims)
    return None


def main():
    clock = Clock(START)
    pay_key = ec.generate_private_key(ec.SECP256R1())       # ExamplePay's key
    reader_key = ec.generate_private_key(ec.SECP256R1())    # a second client
    attacker_key = ec.generate_private_key(ec.SECP256R1())
    basic_secret = secrets.token_urlsafe(32)
    hmac_secret = secrets.token_bytes(32)

    def registry():
        return {
            "examplepay": {"client_id": "examplepay", "method": "private_key_jwt",
                           "public_key": pay_key.public_key(), "redirect_uris": [REDIRECT],
                           "scopes": ["accounts:read", "payments:write"],
                           "detail_types": ["payment_initiation"]},
            "examplereader": {"client_id": "examplereader", "method": "private_key_jwt",
                              "public_key": reader_key.public_key(),
                              "redirect_uris": [REDIRECT], "scopes": ["accounts:read"],
                              "detail_types": []},
            "legacy-basic": {"client_id": "legacy-basic", "method": "client_secret_basic",
                             "secret_hash": hashlib.sha256(basic_secret.encode()).digest(),
                             "redirect_uris": [REDIRECT], "scopes": ["accounts:read"],
                             "detail_types": []},
            "legacy-hmac": {"client_id": "legacy-hmac", "method": "client_secret_jwt",
                            "secret": hmac_secret, "redirect_uris": [REDIRECT],
                            "scopes": ["accounts:read"], "detail_types": []}}

    print("ExampleBank, ExamplePay and ExampleAir are fictional. "
          "No key, secret, assertion or token is printed.")

    # ---------------- Part A -------------------------------------------
    section("Part A: client authentication. Who can act as the client?")
    server = AuthorizationServer(clock, registry())
    proxy_log = []      # what a TLS-terminating proxy in front of the server saw

    def send(request):
        proxy_log.append(request)
        return server.authenticate(request)[1]

    record("client_secret_basic, the real client", "authenticated",
           send({"headers": {"authorization": basic("legacy-basic", basic_secret)},
                 "form": {}}))
    clock.advance(3600)
    replayed = {"headers": dict(proxy_log[0]["headers"]), "form": {}}
    record("  the header copied from the proxy log, an hour later", "authenticated",
           server.authenticate(replayed)[1])
    record("client_secret_jwt, the real client", "authenticated",
           send(assertion_form(jwt_hs256(hmac_secret,
                                         claims_for("legacy-hmac", ISSUER, clock.now)))))
    forged = forge_from_store(server, "legacy-hmac")
    record("  an assertion minted from the server's own client record", "authenticated",
           server.authenticate(assertion_form(forged))[1])

    good = jwt_es256(pay_key, claims_for("examplepay", ISSUER, clock.now))
    record("private_key_jwt, the real client", "authenticated",
           send(assertion_form(good)))
    forged = forge_from_store(server, "examplepay")
    record("  an assertion minted from the server's own client record",
           "the record holds no signing key",
           "the record holds no signing key" if forged is None
           else server.authenticate(assertion_form(forged))[1])
    record("  signed with the attacker's own key", "invalid_client: signature",
           server.authenticate(assertion_form(
               jwt_es256(attacker_key, claims_for("examplepay", ISSUER, clock.now))))[1])
    confused = jwt_hs256(public_bytes(pay_key.public_key()),
                         claims_for("examplepay", ISSUER, clock.now))
    record("  HS256, keyed with the client's public key",
           "invalid_client: alg is not the registered one",
           server.authenticate(assertion_form(confused))[1])

    record("  jti values recorded for ExamplePay after checks 5 to 8", 1,
           len([k for k in server.seen_jti if k[0] == "examplepay"]))

    copied = proxy_log[-1]      # the request that carried check 5's assertion
    record("that assertion, copied from the proxy log and sent again",
           "invalid_client: jti already used", server.authenticate(copied)[1])
    forgetful = AuthorizationServer(clock, registry(), track_jti=False)
    forgetful.authenticate(copied)
    record("  to a server that does not track jti", "authenticated",
           forgetful.authenticate(copied)[1])
    record("an assertion addressed to another server", "invalid_client: audience",
           server.authenticate(assertion_form(jwt_es256(
               pay_key, claims_for("examplepay", "https://auth.other.example", clock.now))))[1])
    stale = jwt_es256(pay_key, claims_for("examplepay", ISSUER, clock.now))
    clock.advance(ASSERTION_LIFETIME)
    record("an assertion presented at its exp", "invalid_client: expired",
           server.authenticate(assertion_form(stale))[1])
    record("an assertion that would stay valid for a day",
           "invalid_client: lifetime too long",
           server.authenticate(assertion_form(jwt_es256(
               pay_key, claims_for("examplepay", ISSUER, clock.now, lifetime=86400))))[1])
    # Any later authentication prunes the record. Another client's will do.
    server.authenticate(assertion_form(jwt_es256(
        reader_key, claims_for("examplereader", ISSUER, clock.now))))
    record("jti values still recorded for ExamplePay, its assertions having expired", 0,
           len([k for k in server.seen_jti if k[0] == "examplepay"]))
    to_token_url = assertion_form(jwt_es256(
        pay_key, claims_for("examplepay", ISSUER + "/token", clock.now)))
    record("aud is the token endpoint URL: RFC 9126 policy", "authenticated",
           server.authenticate(to_token_url)[1])
    strict = AuthorizationServer(clock, registry(), aud_policy="issuer-string")
    record("  the same assertion: issuer-only policy", "invalid_client: audience",
           strict.authenticate(to_token_url)[1])
    both = assertion_form(jwt_es256(pay_key, claims_for("examplepay", ISSUER, clock.now)))
    both["headers"]["authorization"] = basic("legacy-basic", basic_secret)
    record("an assertion and a Basic header in one request",
           "invalid_client: more than one method", server.authenticate(both)[1])

    # ---------------- Part B -------------------------------------------
    section("Part B: pushed authorization requests. Who can change the request?")
    server = AuthorizationServer(clock, registry())
    user = new_user(clock)

    def widen(front):
        front["scope"] = "accounts:read payments:write"

    flow = run_flow(server, pay_key, user, {"scope": "accounts:read"},
                    use_par=False, edit=widen)
    record("the client asks for, on the front channel", "accounts:read",
           flow["asked"]["scope"])
    record("  the URL is edited in the browser; the token carries",
           "accounts:read payments:write", flow["response"]["scope"])
    record("  what the user was shown and approved",
           "read your balance; make payments from your account", user["seen"][-1])

    user = new_user(clock)
    flow = run_flow(server, pay_key, user, {"scope": "accounts:read"}, edit=widen)
    record("the same request pushed, the same edit; the token carries", "accounts:read",
           flow["response"]["scope"])

    def push(key=pay_key, client_id="examplepay", **extra):
        verifier = secrets.token_urlsafe(32)
        form = dict({"response_type": "code", "redirect_uri": REDIRECT,
                     "code_challenge": s256(verifier), "code_challenge_method": "S256",
                     "scope": "accounts:read"}, **extra)
        return server.par(assertion_form(
            jwt_es256(key, claims_for(client_id, ISSUER, clock.now)), **form))

    status, pushed = push()
    record("a pushed request is answered with", [201, ["expires_in", "request_uri"]],
           [status, sorted(pushed)])
    record("  expires_in, in seconds", 60, pushed["expires_in"])
    reference = pushed["request_uri"][len(URN):]
    record("  random bits in the request_uri", 256, len(b64u_decode(reference)) * 8)
    front = {"client_id": "examplepay", "request_uri": pushed["request_uri"]}
    record("  first use at the authorization endpoint", "code issued",
           outcome(server.authorize(front, new_user(clock))))
    record("  second use of the same request_uri",
           "invalid_request: request_uri already used",
           outcome(server.authorize(front, new_user(clock))))
    status, pushed = push()
    clock.advance(REQUEST_URI_LIFETIME)
    record("a request_uri presented when its lifetime has passed",
           "invalid_request: request_uri expired",
           outcome(server.authorize({"client_id": "examplepay",
                                     "request_uri": pushed["request_uri"]},
                                    new_user(clock))))
    record("a guessed request_uri", "invalid_request: unknown request_uri",
           outcome(server.authorize({"client_id": "examplepay",
                                     "request_uri": URN + "guess-0001"},
                                    new_user(clock))))
    status, pushed = push()
    record("another client presents ExamplePay's request_uri",
           "invalid_request: request_uri belongs to another client",
           outcome(server.authorize({"client_id": "examplereader",
                                     "request_uri": pushed["request_uri"]},
                                    new_user(clock))))
    record("  and ExamplePay can still use it", "code issued",
           outcome(server.authorize({"client_id": "examplepay",
                                     "request_uri": pushed["request_uri"]},
                                    new_user(clock))))
    status, body = server.par({"headers": {}, "form": {
        "client_id": "examplepay", "response_type": "code", "redirect_uri": REDIRECT,
        "code_challenge": s256("x"), "code_challenge_method": "S256"}})
    record("a push with no client authentication",
           [401, "invalid_client: no client authentication"], [status, body.get("error")])
    status, body = push(request_uri=URN + "anything")
    record("a push that itself carries a request_uri",
           [400, "invalid_request: request_uri is not allowed here"],
           [status, body.get("error")])
    status, body = push(key=reader_key, client_id="examplereader",
                        scope="accounts:read payments:write")
    record("a push for a scope the client is not registered for",
           [400, "invalid_scope"], [status, body.get("error")])
    par_only = AuthorizationServer(clock, registry(), require_par=True)
    record("require_pushed_authorization_requests: a request that was not pushed",
           "invalid_request: a pushed authorization request is required",
           summary(run_flow(par_only, pay_key, new_user(clock),
                            {"scope": "accounts:read"}, use_par=False)))

    # ---------------- Part C -------------------------------------------
    section("Part C: rich authorization requests. What exactly was granted?")
    server = AuthorizationServer(clock, registry(), require_par=True)
    api = PaymentsAPI(server)
    booking = {"creditor": "acct-exampleair", "amount": "45.00", "currency": "EUR"}
    theft = {"creditor": "acct-attacker", "amount": "9000.00", "currency": "EUR"}

    coarse = run_flow(server, pay_key, new_user(clock), {"scope": "payments:write"})
    record("scope payments:write: the booking payment",
           "201 paid 45.00 EUR to acct-exampleair",
           api.handle("POST", "/payments", coarse["token"], booking))
    record("  the same token: 9000.00 to another account",
           "201 paid 9000.00 EUR to acct-attacker",
           api.handle("POST", "/payments", coarse["token"], theft))

    user = new_user(clock)
    rich = run_flow(server, pay_key, user, {"authorization_details": payment_details()})
    record("authorization_details: what the user was shown and approved",
           "pay 45.00 EUR to ExampleAir (acct-exampleair)", user["seen"][-1])
    granted = json.loads(payment_details())
    record("  the token response returns what was granted", True,
           rich["response"].get("authorization_details") == granted)
    record("  and so does introspection, for the resource server", True,
           server.introspect(rich["token"]).get("authorization_details") == granted)
    record("  the booking payment", "201 paid 45.00 EUR to acct-exampleair",
           api.handle("POST", "/payments", rich["token"], booking))
    record("  9000.00 to another account", '403 Bearer error="insufficient_scope"',
           api.handle("POST", "/payments", rich["token"], theft))
    record("  the right account, a larger amount", '403 Bearer error="insufficient_scope"',
           api.handle("POST", "/payments", rich["token"], dict(booking, amount="450.00")))
    careless = PaymentsAPI(server, enforce="type-only")
    record("a resource server that checks only the type: 9000.00",
           "201 paid 9000.00 EUR to acct-attacker",
           careless.handle("POST", "/payments", rich["token"], theft))

    record("a request for a type the server does not define",
           "invalid_authorization_details: unknown type",
           summary(run_flow(server, pay_key, new_user(clock), {
               "authorization_details": json.dumps([{"type": "account_closure"}])})))
    record("a known type with a field its definition does not have",
           "invalid_authorization_details: unknown field recurring",
           summary(run_flow(server, pay_key, new_user(clock), {
               "authorization_details": payment_details(recurring=True)})))
    record("a type this client is not allowed to request",
           "invalid_authorization_details: type not allowed for this client",
           summary(run_flow(server, reader_key, new_user(clock),
                            {"authorization_details": payment_details()},
                            client_id="examplereader")))

    def cheaper(front):
        front["authorization_details"] = payment_details(amount="0.45")

    open_server = AuthorizationServer(clock, registry())
    edited = run_flow(open_server, pay_key, new_user(clock),
                      {"authorization_details": payment_details()},
                      use_par=False, edit=cheaper)
    record("details sent on the front channel, amount edited: granted", "0.45",
           edited["response"]["authorization_details"][0]["instructedAmount"]["amount"])
    record("  the client compares the token response with what it asked",
           "not what was asked",
           "as asked" if edited["response"]["authorization_details"]
           == json.loads(edited["asked"]["authorization_details"]) else "not what was asked")

    # ---------------- Part D -------------------------------------------
    section("Part D: step-up authentication. How was the user authenticated, and when?")
    server = AuthorizationServer(clock, registry(), require_par=True)
    api = PaymentsAPI(server, step_up=True)
    ask = {"scope": "accounts:read", "authorization_details": payment_details()}

    user = new_user(clock)       # signed in with a password two hours ago
    old = run_flow(server, pay_key, user, ask)
    record("the token's acr and the age of its auth_time", [ACR_PWD, 7200],
           [server.introspect(old["token"])["acr"],
            clock.now - server.introspect(old["token"])["auth_time"]])
    record("  reading the balance with it", "200 balance of customer-17",
           api.handle("GET", "/accounts", old["token"]))
    challenge = api.handle("POST", "/payments", old["token"], booking)
    record("  paying with it",
           '401 Bearer error="insufficient_user_authentication", '
           'acr_values="%s", max_age="300"' % ACR_MFA, challenge)
    asked = parse_challenge(challenge)
    record("  what the client reads from the challenge",
           ["insufficient_user_authentication", ACR_MFA, "300"],
           [asked.get("error"), asked.get("acr_values"), asked.get("max_age")])
    fresh = run_flow(server, pay_key, user, dict(
        ask, acr_values=asked["acr_values"], max_age=asked["max_age"]))
    record("  a new request with those values: acr and age", [ACR_MFA, 0],
           [server.introspect(fresh["token"])["acr"],
            clock.now - server.introspect(fresh["token"])["auth_time"]])
    record("  the payment, retried with the new token",
           "201 paid 45.00 EUR to acct-exampleair",
           api.handle("POST", "/payments", fresh["token"], booking))

    aged = run_flow(server, pay_key, new_user(clock, acr=ACR_MFA, age=1800), ask)
    record("strong authentication, 30 minutes old",
           '401 Bearer error="insufficient_user_authentication", '
           'acr_values="%s", max_age="300"' % ACR_MFA,
           api.handle("POST", "/payments", aged["token"], booking))
    weak = run_flow(server, pay_key, new_user(clock, age=10), ask)
    record("password only, 10 seconds old",
           '401 Bearer error="insufficient_user_authentication", '
           'acr_values="%s", max_age="300"' % ACR_MFA,
           api.handle("POST", "/payments", weak["token"], booking))
    record("a user with no second factor asks for the stronger acr",
           "unmet_authentication_requirements",
           summary(run_flow(server, pay_key, new_user(clock, factors=("pwd",)),
                            dict(ask, acr_values=ACR_MFA, max_age="300"))))
    no_scope = run_flow(server, pay_key, new_user(clock),
                        {"authorization_details": payment_details()})
    record("a different refusal: a token without accounts:read reads the balance",
           '403 Bearer error="insufficient_scope", scope="accounts:read"',
           api.handle("GET", "/accounts", no_scope["token"]))
    record("an unknown token is not told the policy", '401 Bearer error="invalid_token"',
           api.handle("POST", "/payments", "not-a-token", booking))

    # ---------------- Part E -------------------------------------------
    section("Part E: the controls together, and what they still do not decide.")
    fapi = AuthorizationServer(clock, registry(), aud_policy="issuer-string",
                               require_par=True, require_bound_tokens=True,
                               allowed_methods=("private_key_jwt",))
    api = PaymentsAPI(fapi, step_up=True, check_owner=False)
    ask = {"authorization_details": payment_details(),
           "acr_values": ACR_MFA, "max_age": "300"}
    bound_key = pay_key.public_key()

    flow = run_flow(fapi, pay_key, new_user(clock), ask, conn_key=bound_key)
    record("pushed, private_key_jwt, PKCE S256, details, step-up, bound key",
           "token issued", summary(flow))
    record("  the payment it was issued for", "201 paid 45.00 EUR to acct-exampleair",
           api.handle("POST", "/payments", flow["token"], booking, conn_key=bound_key))
    record("  the same token from a connection without the client's key",
           '401 Bearer error="invalid_token"',
           api.handle("POST", "/payments", flow["token"], booking,
                      conn_key=attacker_key.public_key()))
    record("a response whose iss names another server",
           "client refused: iss is not the expected issuer",
           summary(run_flow(fapi, pay_key, new_user(clock), ask, conn_key=bound_key,
                            forge_iss="https://auth.attacker.example")))
    record("the same request without a key to bind the token to",
           "invalid_request: no key to bind the token to",
           summary(run_flow(fapi, pay_key, new_user(clock), ask)))
    record("this server and a client secret",
           "invalid_client: method not accepted by this server",
           fapi.authenticate({"headers": {"authorization": basic("legacy-basic", basic_secret)},
                              "form": {}})[1])
    record("  response_type=token", "unsupported_response_type",
           summary(run_flow(fapi, pay_key, new_user(clock),
                            dict(ask, response_type="token"), conn_key=bound_key)))
    record("  code_challenge_method=plain", "invalid_request: PKCE with S256 is required",
           summary(run_flow(fapi, pay_key, new_user(clock),
                            dict(ask, code_challenge_method="plain"), conn_key=bound_key)))
    status, body = fapi.token(assertion_form(
        jwt_es256(pay_key, claims_for("examplepay", ISSUER, clock.now)),
        grant_type="password", username="customer-17", password="<the user's password>"))
    record("  grant_type=password", [400, "unsupported_grant_type"], [status, body.get("error")])

    record("every check above passed; the same token reads pay-7002",
           "200 310.00 EUR to acct-landlord, owned by customer-42",
           api.handle("GET", "/payments/pay-7002", flow["token"], conn_key=bound_key))
    owner_checked = PaymentsAPI(fapi, step_up=True, check_owner=True)
    record("  with an ownership check at the resource server", "404 not found",
           owner_checked.handle("GET", "/payments/pay-7002", flow["token"],
                                conn_key=bound_key))

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
