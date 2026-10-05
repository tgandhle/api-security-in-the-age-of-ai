#!/usr/bin/env python3
"""Module 35 lab: OpenID Connect and ID tokens.

Python 3, standard library only. On Windows use `py -3` wherever the page
shows `python3`.

Nothing here opens a socket, starts a thread or a process, writes a file or
reads a clock. The OpenID provider, the clients, the API and the browser
sessions are Python objects, a request is a method call, and the time is a
number the lab sets. Secrets are random on every run and are never printed.
Token values are never printed either. The output is the same bytes on every
run.

Who is in it (all fictional):

  https://login.exampleair.example     the OpenID provider (OP)
  https://login.examplehotels.example  a second provider the web app also
                                       accepts logins from
  exampleair-web                       ExampleAir's web app, a confidential
                                       client. It exists twice: once with the
                                       naive validator, once with the correct
                                       one.
  exampleair-offers                    a second confidential client at the
                                       same provider, a low-value offers site
  exampleair-legacy                    a client registered for unsigned ID
                                       tokens, for Part I only
  https://api.exampleair.example       the bookings API

  Part A  discovery, registration, and one honest login.
  Part B  the wrong kind of token: an ID token at the API, an access token at
          the client.
  Part C  an ID token for another client, and one from another issuer.
  Part D  a stolen authorization code replayed in another browser session:
          nonce.
  Part E  time: exp, iat, auth_time with max_age, and acr.
  Part F  several audiences, and azp.
  Part G  tokens in the redirect (the hybrid flow): at_hash and c_hash.
  Part H  UserInfo: the sub comparison.
  Part I  alg none and a wrong key.
  Part J  the ten attacks counted, and what a signature alone would stop.

How the signing is modelled, and why:

  * ID tokens are signed HS256. OpenID Connect Core 1.0 section 10.1 says
    the MAC key is "the octets of the UTF-8 representation of the
    client_secret value", and section 3.1.3.7 says the secret is the one for
    the client_id in the aud claim. The lab does exactly that, so each client
    has its own key. Section 16.19 requires at least 32 octets for HS256, and
    section 10.1 forbids symmetric signatures for public clients.
  * A real provider signs with an asymmetric key, as module 5 teaches. Core
    section 15.1 requires providers to support RS256, with one narrow
    exception. This provider signs HS256 only, because the standard library
    has no asymmetric primitive. It is not a conformant provider.
  * Access tokens are HS256 too, with a key the provider shares with the API.
    RFC 9068 recommends an asymmetric algorithm. The shared key is a stand-in.
  * With an asymmetric key, every client and every API verifies with the same
    public key, so a signature check passes for any token the provider
    signed. To model that with MAC keys, the naive validators hold a key ring:
    every key ExampleAir's platform has. Part J shows what happens when each
    verifier holds only its own key.
  * Core says that for MAC algorithms "the behavior is unspecified if the aud
    is multi-valued". This lab signs such a token with the secret of the
    client it was issued to. That choice is the lab's own.

Other deliberate simplifications:

  * The discovery document holds four members. A real one has more, and some
    that Discovery requires (jwks_uri, for one) are left out because there
    are no public keys here.
  * The provider trusts a "person" object for who is at the browser. Real
    user authentication is module 27.
  * No PKCE. Module 4 teaches it, and with it the provider would refuse the
    stolen code in Part D before the client ever saw a token.
  * Access tokens name two audiences, the API and UserInfo, to keep one
    token per login.
  * The acr values are URLs made up for this lab.

Exit codes: 0 every check matched, 1 at least one did not.
"""

import base64
import hashlib
import hmac
import json
import secrets
import sys

START = 1790000000          # a fixed reference time; nothing reads a clock
LEEWAY = 60                 # seconds of clock skew allowed on exp and iat
MAX_TOKEN_AGE = 600         # an ID token older than this (by iat) is refused

ISSUER = "https://login.exampleair.example"
OTHER_ISSUER = "https://login.examplehotels.example"
LOOKALIKE = "https://login.exampleair.example.attacker.example"
API = "https://api.exampleair.example"
WEB = "exampleair-web"
OFFERS = "exampleair-offers"
LEGACY = "exampleair-legacy"
REDIRECT = {WEB: "https://www.exampleair.example/callback",
            OFFERS: "https://offers.exampleair.example/callback",
            LEGACY: "https://old.exampleair.example/callback"}
ACR_PASSWORD = ISSUER + "/acr/password"
ACR_MFA = ISSUER + "/acr/mfa"

PROFILES = {"u-alice": {"email": "alice@customer.example"},
            "u-mallory": {"email": "mallory@customer.example"}}
BOOKINGS = {"u-alice": ["bkg-1001", "bkg-1002"], "u-mallory": ["bkg-2001"]}
# Core section 5.7: only iss and sub together identify a user.
ACCOUNTS = {(ISSUER, "u-alice"): "acct-alice",
            (ISSUER, "u-mallory"): "acct-mallory"}

RESULTS = []
CHECKS = 0
ATTACKS = []   # (name, naive accepted, correct refused, ID token, own key)


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
# JWT by hand: encode, decode, HS256, and the half hash at_hash and c_hash use
# ---------------------------------------------------------------------------

def b64(raw):
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def unb64(text):
    raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if b64(raw) != text:       # one value has one spelling
        raise ValueError("not canonical base64url")
    return raw


def encode(header, claims, key):
    def part(obj):
        return b64(json.dumps(obj, separators=(",", ":"),
                              sort_keys=True).encode("utf-8"))
    signing_input = part(header) + "." + part(claims)
    if header["alg"] == "none":
        return signing_input + "."        # an Unsecured JWS: empty signature
    mac = hmac.new(key, signing_input.encode("ascii"), hashlib.sha256)
    return signing_input + "." + b64(mac.digest())


def decode(token):
    """(header, claims, signing input, signature) or None. Nothing is
    verified here."""
    parts = token.split(".") if isinstance(token, str) else []
    if len(parts) != 3:
        return None
    try:
        header = json.loads(unb64(parts[0]))
        claims = json.loads(unb64(parts[1]))
    except ValueError:
        return None
    if not isinstance(header, dict) or not isinstance(claims, dict):
        return None
    return header, claims, parts[0] + "." + parts[1], parts[2]


def hs256_ok(signing_input, signature, key):
    expected = hmac.new(key, signing_input.encode("ascii"),
                        hashlib.sha256).digest()
    try:
        return hmac.compare_digest(unb64(signature), expected)
    except ValueError:
        return False


def half_hash(value):
    """Core section 3.1.3.6: the left-most half of the hash of the ASCII
    octets, base64url encoded. For HS256 the hash is SHA-256, so 16 octets."""
    return b64(hashlib.sha256(value.encode("ascii")).digest()[:16])


def same(a, b):
    return isinstance(a, str) and isinstance(b, str) \
        and hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def nonce_of(session_secret):
    """Core section 15.5.2: keep a random value in the browser session and
    send a hash of it as the nonce."""
    return b64(hashlib.sha256(session_secret.encode("ascii")).digest())


# ---------------------------------------------------------------------------
# The validators
# ---------------------------------------------------------------------------

def naive_claims(token, key_ring):
    """NOT a validator to copy. It lets the token's header choose the
    operation, tries every key it holds, and checks no claim at all."""
    parsed = decode(token)
    if parsed is None:
        return None
    header, claims, signing_input, signature = parsed
    if header.get("alg") == "none":
        return claims
    for key in key_ring:
        if hs256_ok(signing_input, signature, key):
            return claims
    return None


def signature_only(token, key):
    """Part J: one key, always HS256, and nothing else."""
    parsed = decode(token)
    if parsed is None or not hs256_ok(parsed[2], parsed[3], key):
        return "reject"
    return "accept"


def validate_id_token(token, issuer, client_id, key, now, source,
                      algorithm="HS256", nonce=None, max_age=None,
                      acr_values=None, trusted_audiences=(),
                      access_token=None, code=None):
    """OpenID Connect Core 1.0 section 3.1.3.7, with the differences sections
    3.2.2.11 and 3.3.2.12 make for an ID token that arrived in a redirect.
    `source` is "token endpoint" or "redirect". Everything it compares against
    comes from the client's configuration or its browser session, never from
    the token. Returns (verdict, claims or None)."""
    parsed = decode(token)
    if parsed is None:
        return "reject: malformed token", None
    header, claims, signing_input, signature = parsed

    # The algorithm is the one registered for this client. The header is
    # compared with it and never selects the operation (module 5).
    if header.get("alg") != algorithm:
        return "reject: algorithm not allowed", None
    if algorithm == "none" and (source != "token endpoint" or signature):
        return "reject: unsigned token outside the token endpoint", None

    for name in ("iss", "sub", "aud", "exp", "iat"):
        if name not in claims:
            return "reject: missing claim " + name, None
    for name in ("exp", "iat", "auth_time"):
        if name in claims and type(claims[name]) not in (int, float):
            return "reject: malformed claim " + name, None

    # The step numbers in the comments below count the items of Core section
    # 3.1.3.7 from 1. Item 1 is decryption, which this lab leaves out, and
    # item 7, the algorithm, was applied first, above. The page numbers its
    # own shorter list differently.
    if claims["iss"] != issuer:                              # step 2
        return "reject: issuer mismatch", None
    audiences = claims["aud"] if isinstance(claims["aud"], list) \
        else [claims["aud"]]
    if client_id not in audiences:                           # step 3
        return "reject: audience mismatch", None
    if any(a != client_id and a not in trusted_audiences for a in audiences):
        return "reject: untrusted additional audience", None
    if "azp" in claims and claims["azp"] != client_id:       # steps 4 and 5
        return "reject: azp names another client", None

    if algorithm != "none" \
            and not hs256_ok(signing_input, signature, key):  # steps 6 to 8
        return "reject: signature check failed", None

    if now >= claims["exp"] + LEEWAY:                        # step 9
        return "reject: expired", None
    if now - claims["iat"] > MAX_TOKEN_AGE:                  # step 10
        return "reject: issued too long ago", None
    if claims["iat"] > now + LEEWAY:
        return "reject: issued in the future", None

    if nonce is not None:                                    # step 11
        if "nonce" not in claims:
            return "reject: nonce missing", None
        if not same(claims["nonce"], nonce):
            return "reject: nonce mismatch", None
    if acr_values and claims.get("acr") not in acr_values:   # step 12
        return "reject: acr not acceptable", None
    if max_age is not None:                                  # step 13
        if "auth_time" not in claims:
            return "reject: auth_time missing", None
        if now - claims["auth_time"] > max_age:
            return "reject: authentication too old", None

    # Sections 3.2.2.9 and 3.3.2.10. Required beside a token or code that
    # came in a redirect. From the token endpoint, checked when present.
    for name, value in (("at_hash", access_token), ("c_hash", code)):
        if value is None:
            continue
        if name in claims:
            if not same(claims[name], half_hash(value)):
                return "reject: %s mismatch" % name, None
        elif source == "redirect":
            return "reject: %s missing" % name, None
    return "accept", claims


def validate_access_token(token, issuer, audience, key, now, check_typ=True):
    """RFC 9068 section 4, for the resource server."""
    parsed = decode(token)
    if parsed is None:
        return "malformed token", None
    header, claims, signing_input, signature = parsed
    if header.get("alg") != "HS256":
        return "algorithm not allowed", None
    if check_typ and str(header.get("typ")).lower() not in (
            "at+jwt", "application/at+jwt"):
        return "wrong token type", None
    if claims.get("iss") != issuer:
        return "issuer mismatch", None
    audiences = claims.get("aud")
    audiences = audiences if isinstance(audiences, list) else [audiences]
    if audience not in audiences:
        return "audience mismatch", None
    if not hs256_ok(signing_input, signature, key):
        return "signature check failed", None
    if type(claims.get("exp")) not in (int, float) \
            or now >= claims["exp"] + LEEWAY:
        return "expired", None
    return "accept", claims


def discover(issuer, documents):
    """OpenID Connect Discovery 1.0 sections 4.1 and 4.3. `documents` stands
    in for HTTPS: a dict from URL to the JSON document served there."""
    url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    document = documents.get(url)
    if document is None:
        return "reject: no configuration document"
    if document.get("issuer") != issuer:
        return "reject: issuer mismatch"
    return "accept"


# ---------------------------------------------------------------------------
# The OpenID provider
# ---------------------------------------------------------------------------

class Provider:
    def __init__(self, issuer, clock):
        self.issuer = issuer
        self.clock = clock
        self.clients = {}
        self.codes = {}
        self.serial = 0
        self.access_key = secrets.token_bytes(32)   # shared with the API
        self.front_channel_access_tokens = True     # the legacy setting

    def metadata(self):
        return {"issuer": self.issuer,
                "authorization_endpoint": self.issuer + "/authorize",
                "token_endpoint": self.issuer + "/token",
                "userinfo_endpoint": self.issuer + "/userinfo"}

    def register(self, client_id, client_type="confidential",
                 id_token_alg="HS256"):
        """Returns (client secret or None, verdict)."""
        if id_token_alg.startswith("HS") and client_type != "confidential":
            return None, "refused: a public client cannot keep the MAC key"
        secret = secrets.token_urlsafe(32) \
            if client_type == "confidential" else None
        self.clients[client_id] = {"secret": secret, "alg": id_token_alg,
                                   "redirect_uri": REDIRECT.get(client_id)}
        return secret, "registered"

    def id_token(self, client_id, sub, nonce=None, auth_time=None, acr=None,
                 lifetime=300, audience=None, azp=None, access_token=None,
                 code=None):
        """Signed with the secret of the client it is issued to."""
        client = self.clients[client_id]
        now = self.clock.now
        claims = {"iss": self.issuer, "sub": sub,
                  "aud": audience or client_id, "iat": now,
                  "exp": now + lifetime,
                  "auth_time": now if auth_time is None else auth_time,
                  "acr": acr or ACR_PASSWORD}
        for name, value in (("nonce", nonce), ("azp", azp)):
            if value is not None:
                claims[name] = value
        if access_token is not None:
            claims["at_hash"] = half_hash(access_token)
        if code is not None:
            claims["c_hash"] = half_hash(code)
        if client["alg"] == "none":
            return encode({"alg": "none", "typ": "JWT"}, claims, None)
        return encode({"alg": "HS256", "typ": "JWT"}, claims,
                      client["secret"].encode("utf-8"))

    def access_token(self, client_id, sub, scope="openid bookings:read"):
        self.serial += 1
        now = self.clock.now
        claims = {"iss": self.issuer, "sub": sub, "client_id": client_id,
                  "aud": [API, self.issuer + "/userinfo"], "iat": now,
                  "exp": now + 300, "jti": "at-%04d" % self.serial,
                  "scope": scope}
        return encode({"alg": "HS256", "typ": "at+jwt"}, claims,
                      self.access_key)

    def authorize(self, request, person):
        """The authorization endpoint. Returns the parameters the redirect
        back to the client carries, which the browser can read and change."""
        client = self.clients.get(request.get("client_id"))
        if client is None \
                or request.get("redirect_uri") != client["redirect_uri"]:
            return {"error": "invalid_request"}      # and no redirect at all
        types = request.get("response_type", "").split()
        scope = request.get("scope", "")
        openid = "openid" in scope.split()
        failure = None
        if "token" in types and not self.front_channel_access_tokens:
            failure = "unsupported_response_type"
        elif "id_token" in types and (
                not openid or not request.get("nonce")
                or client["alg"] == "none"):
            failure = "invalid_request"
        elif "max_age" in request and \
                self.clock.now - person["auth_time"] > request["max_age"]:
            if person["can_reauthenticate"]:
                person["auth_time"] = self.clock.now
            else:
                failure = "login_required"
        if failure:
            return {"error": failure, "state": request.get("state")}

        response = {"state": request.get("state")}
        code = access_token = None
        if "code" in types:
            code = secrets.token_urlsafe(16)
            self.codes[code] = {
                "client_id": request["client_id"], "sub": person["sub"],
                "redirect_uri": request["redirect_uri"], "scope": scope,
                "nonce": request.get("nonce"), "acr": person["acr"],
                "auth_time": person["auth_time"], "used": False,
                "expires": self.clock.now + 60}
            response["code"] = code
        if "token" in types:
            access_token = self.access_token(request["client_id"],
                                             person["sub"], scope)
            response["access_token"] = access_token
            response["token_type"] = "Bearer"
        if "id_token" in types:
            response["id_token"] = self.id_token(
                request["client_id"], person["sub"], request.get("nonce"),
                person["auth_time"], person["acr"],
                access_token=access_token, code=code)
        return response

    def token(self, client_id, client_secret, code, redirect_uri):
        """The token endpoint: a direct call from the client's server."""
        client = self.clients.get(client_id)
        if client is None or not same(client["secret"], client_secret):
            return {"error": "invalid_client"}
        grant = self.codes.get(code)
        if grant is None or grant["used"] \
                or grant["client_id"] != client_id \
                or grant["redirect_uri"] != redirect_uri \
                or self.clock.now > grant["expires"]:
            return {"error": "invalid_grant"}
        grant["used"] = True
        access_token = self.access_token(client_id, grant["sub"],
                                         grant["scope"])
        response = {"access_token": access_token, "token_type": "Bearer",
                    "expires_in": 300}
        if "openid" in grant["scope"].split():
            response["id_token"] = self.id_token(
                client_id, grant["sub"], grant["nonce"], grant["auth_time"],
                grant["acr"], access_token=access_token)
        return response

    def userinfo(self, bearer):
        verdict, claims = validate_access_token(
            bearer, self.issuer, self.issuer + "/userinfo", self.access_key,
            self.clock.now)
        if verdict != "accept":
            return {"error": "invalid_token"}
        if "openid" not in claims.get("scope", "").split():
            return {"error": "insufficient_scope"}
        profile = dict(PROFILES[claims["sub"]])
        profile["sub"] = claims["sub"]    # Core 5.3.2: always returned
        return profile


# ---------------------------------------------------------------------------
# The API and the two builds of the web client
# ---------------------------------------------------------------------------

class BookingsApi:
    def __init__(self, provider, clock, key_ring):
        self.provider, self.clock, self.key_ring = provider, clock, key_ring

    def answer(self, sub):
        return "200 %s: %d bookings" % (sub, len(BOOKINGS[sub]))

    def naive_get(self, bearer):
        claims = naive_claims(bearer, self.key_ring)
        if claims is None:
            return "401 invalid_token"
        return self.answer(claims["sub"])

    def get(self, bearer, check_typ=True):
        verdict, claims = validate_access_token(
            bearer, self.provider.issuer, API, self.provider.access_key,
            self.clock.now, check_typ)
        if verdict != "accept":
            return "401 invalid_token: " + verdict
        if "bookings:read" not in claims.get("scope", "").split():
            return "403 insufficient_scope"
        return self.answer(claims["sub"])


class RelyingParty:
    """The correct client. `providers` maps an issuer to the provider object
    (standing in for its endpoints) and the client secret it issued."""

    def __init__(self, client_id, providers, clock, trusted_audiences=(),
                 algorithm="HS256"):
        self.client_id, self.providers = client_id, providers
        self.clock = clock
        self.trusted_audiences = trusted_audiences
        self.algorithm = algorithm

    def begin(self, session, issuer, response_type="code", max_age=None,
              acr_values=None, scope="openid bookings:read"):
        """Starts a login in this browser session and returns the
        authentication request."""
        session["pending"] = {"issuer": issuer, "max_age": max_age,
                              "state": secrets.token_urlsafe(16),
                              "nonce_secret": secrets.token_urlsafe(32),
                              "acr_values": acr_values}
        request = {"response_type": response_type, "scope": scope,
                   "client_id": self.client_id,
                   "redirect_uri": REDIRECT[self.client_id],
                   "state": session["pending"]["state"],
                   "nonce": nonce_of(session["pending"]["nonce_secret"])}
        if max_age is not None:
            request["max_age"] = max_age
        if acr_values:
            request["acr_values"] = " ".join(acr_values)
        return request

    def check(self, token, session_nonce, pending, source, **binding):
        config = self.providers[pending["issuer"]]
        key = (config["secret"] or "").encode("utf-8")
        return validate_id_token(
            token, pending["issuer"], self.client_id, key, self.clock.now,
            source, algorithm=self.algorithm, nonce=session_nonce,
            max_age=pending["max_age"], acr_values=pending["acr_values"],
            trusted_audiences=self.trusted_audiences, **binding)

    def callback(self, session, response):
        pending = session.get("pending")
        if pending is None:
            return "reject: no login in progress"
        if not same(response.get("state"), pending["state"]):
            return "reject: state mismatch"
        del session["pending"]                    # one login, one response
        nonce = nonce_of(pending["nonce_secret"])
        if "error" in response:
            return "reject: provider error " + response["error"]
        config = self.providers[pending["issuer"]]
        front = None
        if "id_token" in response:
            verdict, front = self.check(
                response["id_token"], nonce, pending, "redirect",
                access_token=response.get("access_token"),
                code=response.get("code"))
            if verdict != "accept":
                return verdict
        tokens = config["op"].token(self.client_id, config["secret"],
                                    response.get("code"),
                                    REDIRECT[self.client_id])
        if "error" in tokens:
            return "reject: token endpoint error " + tokens["error"]
        # RFC 9700 section 4.5.3.2: the nonce in the ID token from the token
        # endpoint is checked even when the redirect carried one too.
        verdict, claims = self.check(tokens["id_token"], nonce, pending,
                                     "token endpoint",
                                     access_token=tokens["access_token"])
        if verdict != "accept":
            return verdict
        if front is not None and (front["iss"], front["sub"]) != (
                claims["iss"], claims["sub"]):    # Core section 3.3.3.6
            return "reject: the two ID tokens name different users"
        session["user"] = (claims["iss"], claims["sub"])
        session["access_token"] = tokens["access_token"]
        return "accept"

    def profile(self, session, access_token):
        """Core section 5.3.2: the sub in the UserInfo response must exactly
        match the sub in the ID token, or the response is not used."""
        info = self.providers[session["user"][0]]["op"].userinfo(access_token)
        if info.get("sub") != session["user"][1]:
            return "reject: UserInfo sub is not the ID token sub"
        return info["email"]


class NaiveRelyingParty(RelyingParty):
    """The same registered client with a careless build. It does check
    state. It accepts any ID token one of its keys verifies."""

    def __init__(self, client_id, providers, clock, key_ring):
        RelyingParty.__init__(self, client_id, providers, clock)
        self.key_ring = key_ring
        self.last_id_token = None

    def accept(self, token):
        claims = naive_claims(token, self.key_ring)
        if claims is None:
            return "reject"
        self.last_id_token = token
        return "accept as " + str(claims.get("sub"))

    def callback(self, session, response):
        pending = session.get("pending")
        if pending is None or not same(response.get("state"),
                                       pending["state"]):
            return "reject: state mismatch"
        del session["pending"]
        token = response.get("id_token")
        if token is None:
            config = self.providers[pending["issuer"]]
            token = config["op"].token(
                self.client_id, config["secret"], response.get("code"),
                REDIRECT[self.client_id]).get("id_token")
        verdict = self.accept(token)
        if verdict != "reject":
            session["user"] = (None, decode(token)[1]["sub"])   # sub alone
        return verdict

    def profile(self, session, access_token):
        info = self.providers[ISSUER]["op"].userinfo(access_token)
        return info.get("email", "no profile")


def person(sub, clock, age=0, acr=ACR_PASSWORD, can_reauthenticate=True):
    """Who is at the browser, and the state of their session at the
    provider: when they last authenticated and how."""
    return {"sub": sub, "auth_time": clock.now - age, "acr": acr,
            "can_reauthenticate": can_reauthenticate}


def attack(name, naive_result, correct_result, token, own_key):
    naive_accepted = naive_result.startswith(("accept", "200", "alice@"))
    correct_refused = correct_result.startswith(("reject", "401"))
    ATTACKS.append((name, naive_accepted, correct_refused, token, own_key))


# ===========================================================================

def main():
    clock = Clock(START)
    op = Provider(ISSUER, clock)
    other_op = Provider(OTHER_ISSUER, clock)
    web_secret, _ = op.register(WEB)
    offers_secret, _ = op.register(OFFERS)
    other_secret, _ = other_op.register(WEB)
    legacy_secret, _ = op.register(LEGACY, id_token_alg="none")
    web_key = web_secret.encode("utf-8")
    # Everything ExampleAir's platform holds. See the docstring.
    key_ring = [web_key, offers_secret.encode("utf-8"),
                other_secret.encode("utf-8"), op.access_key]

    providers = {ISSUER: {"op": op, "secret": web_secret},
                 OTHER_ISSUER: {"op": other_op, "secret": other_secret}}
    web = RelyingParty(WEB, providers, clock)
    naive = NaiveRelyingParty(WEB, providers, clock, key_ring)
    api = BookingsApi(op, clock, key_ring)

    def direct(token, **options):
        """One token given straight to the correct validator, as the web
        client configured for the ExampleAir provider."""
        settings = {"issuer": ISSUER, "client_id": WEB, "key": web_key,
                    "now": clock.now, "source": "redirect"}
        settings.update(options)
        return validate_id_token(token, **settings)[0]

    def login(client, who, session=None, **options):
        """A whole login: begin, the provider, the callback."""
        session = {} if session is None else session
        request = client.begin(session, ISSUER, **options)
        return client.callback(session, op.authorize(request, who))

    print("secrets are random for this run; no secret and no token is printed")

    # ---------------- Part A -------------------------------------------
    section("Part A: discovery, registration, and one honest login.")

    documents = {
        ISSUER + "/.well-known/openid-configuration": op.metadata(),
        # The look-alike host serves a document that names the real issuer
        # and, in a real attack, its own endpoints and keys.
        LOOKALIKE + "/.well-known/openid-configuration": op.metadata()}
    record("discovery: the document names the issuer it was fetched from",
           "accept", discover(ISSUER, documents))
    record("  a look-alike host whose document names the real issuer",
           "reject: issuer mismatch", discover(LOOKALIKE, documents))
    record("a public client asks for HS256 ID tokens",
           "refused: a public client cannot keep the MAC key",
           op.register("exampleair-spa", client_type="public")[1])
    record("octets in the client secret that keys HS256 (32 is the minimum)",
           43, len(web_key))

    def token_response_members(scope):
        session = {}
        request = web.begin(session, ISSUER, scope=scope)
        code = op.authorize(request, person("u-alice", clock))["code"]
        return sorted(op.token(WEB, web_secret, code, REDIRECT[WEB]))

    record("token response when the scope includes openid",
           ["access_token", "expires_in", "id_token", "token_type"],
           token_response_members("openid bookings:read"))
    record("  the same request without openid: plain OAuth",
           ["access_token", "expires_in", "token_type"],
           token_response_members("bookings:read"))

    record("honest login by Alice: naive client", "accept as u-alice",
           login(naive, person("u-alice", clock)))
    alice_session = {}
    record("  correct client", "accept",
           login(web, person("u-alice", clock), alice_session))
    record("  the account that (iss, sub) selects", "acct-alice",
           ACCOUNTS.get(alice_session["user"], "no such account"))

    # ---------------- Part B -------------------------------------------
    section("Part B: the wrong kind of token.")

    alice_id_token = op.id_token(WEB, "u-alice")
    result = api.naive_get(alice_id_token)
    record("Alice's ID token sent to the API as a bearer token: naive API",
           "200 u-alice: 2 bookings", result)
    refused = api.get(alice_id_token)
    record("  the API that validates access tokens",
           "401 invalid_token: wrong token type", refused)
    attack("api", result, refused, alice_id_token, op.access_key)
    record("  with its typ check switched off, a second check refuses",
           "401 invalid_token: audience mismatch",
           api.get(alice_id_token, check_typ=False))
    record("a real access token at that API", "200 u-alice: 2 bookings",
           api.get(alice_session["access_token"]))
    offers_access_token = op.access_token(OFFERS, "u-alice")
    record("an access token issued to the offers site, used as a login: naive",
           "accept as u-alice", naive.accept(offers_access_token))
    record("  the same token given to the ID token validator",
           "reject: audience mismatch", direct(offers_access_token))

    # ---------------- Part C -------------------------------------------
    section("Part C: a token for another client, and from another issuer.")

    for_offers = op.id_token(OFFERS, "u-alice")
    result = naive.accept(for_offers)
    record("Alice's ID token for the offers site, replayed: naive client",
           "accept as u-alice", result)
    refused = direct(for_offers)
    record("  correct client", "reject: audience mismatch", refused)
    attack("other client", result, refused, for_offers, web_key)

    from_other = other_op.id_token(WEB, "u-alice")
    result = naive.accept(from_other)
    record("ID token from the other provider that reuses Alice's sub: naive",
           "accept as u-alice", result)
    refused = direct(from_other)
    record("  correct client, in a login started at the ExampleAir provider",
           "reject: issuer mismatch", refused)
    attack("other issuer", result, refused, from_other, web_key)
    verdict, claims = validate_id_token(
        from_other, OTHER_ISSUER, WEB, other_secret.encode("utf-8"),
        clock.now, "token endpoint")
    record("  in a login started at the other provider", "accept", verdict)
    record("    the account that (iss, sub) selects", "no such account",
           ACCOUNTS.get((claims["iss"], claims["sub"]), "no such account"))

    # ---------------- Part D -------------------------------------------
    section("Part D: a stolen code replayed in another browser session.")

    def stolen_response(client):
        """Alice starts a login. Her redirect back to the client leaks
        before the client redeems the code."""
        request = client.begin({}, ISSUER)
        return op.authorize(request, person("u-alice", clock))

    def injected_callback(client):
        """Mallory starts her own login in her own browser, then swaps the
        code in her redirect for Alice's."""
        stolen = stolen_response(client)
        session = {}
        request = client.begin(session, ISSUER)
        response = op.authorize(request, person("u-mallory", clock))
        response["code"] = stolen["code"]
        # The client's own state check, measured both ways: it refuses this
        # response when it carries the state of Alice's session, and it does
        # not refuse it for the state that Mallory's own session holds.
        control = {"pending": dict(session["pending"])}
        refuses_other = client.callback(
            control, dict(response, state=stolen["state"])) \
            == "reject: state mismatch"
        verdict = client.callback(session, response)
        return verdict, refuses_other and verdict != "reject: state mismatch"

    result, naive_state_passes = injected_callback(naive)
    record("Alice's code in Mallory's session: naive client",
           "accept as u-alice", result)
    nonce_token = naive.last_id_token
    refused, state_passes = injected_callback(web)
    record("  the state in that callback is Mallory's own, so the state check",
           "passes",
           "passes" if state_passes and naive_state_passes else "fails")
    record("  correct client", "reject: nonce mismatch", refused)
    attack("nonce", result, refused, nonce_token, web_key)

    record("a response sent to a browser session that started no login",
           "reject: no login in progress",
           web.callback({}, stolen_response(web)))
    session = {}
    response = op.authorize(web.begin(session, ISSUER),
                            person("u-alice", clock))
    record("one honest response delivered twice to the same session",
           ["accept", "reject: no login in progress"],
           [web.callback(session, response), web.callback(session, response)])
    record("an ID token with no nonce although the request sent one",
           "reject: nonce missing",
           direct(op.id_token(WEB, "u-alice"), nonce=nonce_of("x")))

    # ---------------- Part E -------------------------------------------
    section("Part E: time. exp, iat, auth_time with max_age, and acr.")

    result = naive.accept(alice_id_token)
    record("an ID token used two hours after it was issued: naive client",
           "accept as u-alice", result)
    refused = direct(alice_id_token, now=clock.now + 7200)
    record("  correct client", "reject: expired", refused)
    attack("expired", result, refused, alice_id_token, web_key)
    record("  30 seconds past exp, inside the 60 second leeway", "accept",
           direct(alice_id_token, now=clock.now + 330))
    record("a 24 hour ID token, two hours old: before exp, but",
           "reject: issued too long ago",
           direct(op.id_token(WEB, "u-alice", lifetime=86400),
                  now=clock.now + 7200))

    def step_up(client, who, strip=False, **options):
        session = {}
        request = client.begin(session, ISSUER, **options)
        if strip:                       # edited in the browser's address bar
            del request["max_age"]
        response = op.authorize(request, who)
        return response.get("error") or client.callback(session, response)

    def stale():       # someone at an unlocked browser, two hours after login
        return person("u-alice", clock, age=7200, can_reauthenticate=False)

    record("max_age=300, session two hours old, nobody can re-authenticate",
           "login_required", step_up(web, stale(), max_age=300))
    result = step_up(naive, stale(), strip=True, max_age=300)
    record("  max_age deleted from the request in the browser: naive client",
           "accept as u-alice", result)
    refused = step_up(web, stale(), strip=True, max_age=300)
    record("  correct client", "reject: authentication too old", refused)
    attack("max_age", result, refused, naive.last_id_token, web_key)
    record("  the real user, who re-authenticates when asked", "accept",
           step_up(web, person("u-alice", clock, age=7200), max_age=300))
    record("acr_values asks for MFA, the provider reports a password: naive",
           "accept as u-alice",
           login(naive, person("u-alice", clock), acr_values=[ACR_MFA]))
    record("  correct client", "reject: acr not acceptable",
           login(web, person("u-alice", clock), acr_values=[ACR_MFA]))

    # ---------------- Part F -------------------------------------------
    section("Part F: several audiences, and azp.")

    issued_to_offers = op.id_token(OFFERS, "u-alice", audience=[WEB, OFFERS],
                                   azp=OFFERS)
    result = naive.accept(issued_to_offers)
    record("aud lists web and offers, azp is offers: naive client",
           "accept as u-alice", result)
    refused = direct(issued_to_offers)
    record("  correct client, which trusts no audience but itself",
           "reject: untrusted additional audience", refused)
    attack("azp", result, refused, issued_to_offers, web_key)
    record("  a client told to trust offers as a second audience",
           "reject: azp names another client",
           direct(issued_to_offers, trusted_audiences=(OFFERS,)))
    record("  that client, same audiences, token issued to web (azp is web)",
           "accept",
           direct(op.id_token(WEB, "u-alice", audience=[WEB, OFFERS],
                              azp=WEB), trusted_audiences=(OFFERS,)))

    # ---------------- Part G -------------------------------------------
    section("Part G: tokens in the redirect. at_hash and c_hash.")

    def redirect_members(response_type):
        request = web.begin({}, ISSUER, response_type=response_type)
        return sorted(op.authorize(request, person("u-alice", clock)))

    record("what the browser sees for response_type code",
           ["code", "state"], redirect_members("code"))
    record("  code id_token", ["code", "id_token", "state"],
           redirect_members("code id_token"))
    record("  code id_token token",
           ["access_token", "code", "id_token", "state", "token_type"],
           redirect_members("code id_token token"))
    record("  id_token token (the implicit flow)",
           ["access_token", "id_token", "state", "token_type"],
           redirect_members("id_token token"))

    def hybrid(client, change=None):
        """Mallory logs in as herself with the hybrid flow and may change
        one parameter of her own redirect before the client reads it."""
        session = {}
        request = client.begin(session, ISSUER,
                               response_type="code id_token token")
        response = op.authorize(request, person("u-mallory", clock))
        if change == "access_token":
            response["access_token"] = alice_session["access_token"]
        if change == "code":
            response["code"] = stolen_response(client)["code"]
        return session, response

    session, response = hybrid(naive, "access_token")
    # The naive client takes the user from the ID token in the redirect, and
    # then uses the access token that arrived beside it at the API.
    accepted = naive.callback(session, response)
    result = api.get(response["access_token"]) \
        if accepted == "accept as u-mallory" else accepted
    record("access token swapped for Alice's: naive [ID token sub, API]",
           ["u-mallory", "200 u-alice: 2 bookings"],
           [session.get("user", (None, None))[1], result])
    session, swapped = hybrid(web, "access_token")
    refused = web.callback(session, swapped)
    record("  correct client", "reject: at_hash mismatch", refused)
    attack("at_hash", result, refused, response["id_token"], web_key)
    record("code swapped for Alice's stolen code: correct client",
           "reject: c_hash mismatch", web.callback(*hybrid(web, "code")))
    session, response = hybrid(web)
    front_token, front_access = response["id_token"], response["access_token"]
    record("an untouched hybrid response", "accept",
           web.callback(session, response))
    record("an ID token in a redirect beside an access token, no at_hash",
           "reject: at_hash missing",
           direct(op.id_token(WEB, "u-mallory"), access_token=front_access))
    clock.advance(600)
    record("ten minutes later: [at_hash still matches, API answers]",
           [True, "401 invalid_token: expired"],
           [decode(front_token)[1]["at_hash"] == half_hash(front_access),
            api.get(front_access)])
    op.front_channel_access_tokens = False
    record("provider told to keep access tokens out of the redirect",
           "unsupported_response_type",
           op.authorize(web.begin({}, ISSUER,
                                  response_type="code id_token token"),
                        person("u-alice", clock)).get("error"))

    # ---------------- Part H -------------------------------------------
    section("Part H: UserInfo.")

    alice_access = op.access_token(OFFERS, "u-alice")
    naive_session, web_session = {}, {}
    login(naive, person("u-mallory", clock), naive_session)
    login(web, person("u-mallory", clock), web_session)
    result = naive.profile(naive_session, alice_access)
    record("Mallory is logged in, the access token is Alice's: naive profile",
           "alice@customer.example", result)
    refused = web.profile(web_session, alice_access)
    record("  correct client",
           "reject: UserInfo sub is not the ID token sub", refused)
    attack("userinfo", result, refused, naive.last_id_token, web_key)
    record("  correct client, Mallory's own access token",
           "mallory@customer.example",
           web.profile(web_session, web_session["access_token"]))
    record("an ID token as the bearer token at UserInfo", "invalid_token",
           op.userinfo(op.id_token(WEB, "u-alice")).get("error"))

    # ---------------- Part I -------------------------------------------
    section("Part I: alg none, and a wrong key.")

    forged_claims = {"iss": ISSUER, "sub": "u-alice", "aud": WEB,
                     "iat": clock.now, "exp": clock.now + 300}
    unsigned = encode({"alg": "none", "typ": "JWT"}, forged_claims, None)
    result = naive.accept(unsigned)
    record("an unsigned token that names Alice, alg none: naive client",
           "accept as u-alice", result)
    refused = direct(unsigned)
    record("  correct client", "reject: algorithm not allowed", refused)
    attack("none", result, refused, unsigned, web_key)
    guessed = encode({"alg": "HS256", "typ": "JWT"}, forged_claims,
                     b"not the client secret")
    record("the same claims signed HS256 with a key the client never had",
           ["reject", "reject: signature check failed"],
           [naive.accept(guessed), direct(guessed)])

    # Core section 2 lets a client register for alg none when no ID token
    # comes back from the authorization endpoint. The client still
    # authenticates to the token endpoint with its secret.
    legacy = RelyingParty(LEGACY,
                          {ISSUER: {"op": op, "secret": legacy_secret}},
                          clock, algorithm="none")
    record("a client registered for none: a login through the token endpoint",
           "accept", login(legacy, person("u-alice", clock)))
    record("  an unsigned token for that client arriving in a redirect",
           "reject: unsigned token outside the token endpoint",
           validate_id_token(op.id_token(LEGACY, "u-alice"), ISSUER, LEGACY,
                             b"", clock.now, "redirect", algorithm="none")[0])
    record("  that client asks the provider for code id_token",
           "invalid_request",
           op.authorize(legacy.begin({}, ISSUER,
                                     response_type="code id_token"),
                        person("u-alice", clock)).get("error"))

    # ---------------- Part J -------------------------------------------
    section("Part J: the ten attacks, and what a signature alone would stop.")

    record("attacks run in Parts B to I", 10, len(ATTACKS))
    record("  accepted by the naive validators", 10,
           sum(1 for a in ATTACKS if a[1]))
    record("  refused by the correct ones", 10,
           sum(1 for a in ATTACKS if a[2]))
    record("  still accepted by a signature check with the verifier's one key",
           ["nonce", "expired", "max_age", "at_hash", "userinfo"],
           [a[0] for a in ATTACKS if signature_only(a[3], a[4]) == "accept"])

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
