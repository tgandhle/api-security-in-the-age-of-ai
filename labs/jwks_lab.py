#!/usr/bin/env python3
"""Module 6 lab: JWKS, revocation and introspection.

Three things break here, and none of them is the signature check.

Part A: choosing a key. Unknown and ambiguous key identifiers, keys served for
the wrong purpose, and a key location taken from the token itself.

Part B: the cache as a state machine. Which refresh outcomes are authoritative
and replace what you hold, and which are retrieval failures that must not.

Part C: revocation. A self-contained token stays verifiable after the grant is
withdrawn, and an introspection cache extends that window further.

The issuer's key endpoint and the introspection endpoint are stubs in this
process. No sockets are opened. The clock is a variable, so every run prints the
same thing.

This lab needs one package, because Python has no asymmetric cryptography:
    python3 -m pip install cryptography==50.0.1
On Windows use py -3 in place of python3.

Exit codes: 0 all checks matched, 1 a check did not match, 2 the package is
missing so nothing ran.
"""
import base64
import hashlib
import hmac
import json
import sys

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
except ImportError:
    print("This lab needs the cryptography package, because Python has no")
    print("asymmetric cryptography in its standard library.")
    print()
    print("    python3 -m pip install cryptography==50.0.1")
    print("    py -3 -m pip install cryptography==50.0.1   (Windows)")
    print()
    print("Modules 1, 2 and 4 still need nothing beyond Python 3.")
    sys.exit(2)

NOW = 1790000000
ISSUER = "https://auth.hotel.example"
AUDIENCE = "https://api.hotel.example"


def b64(raw):
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def unb64(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def to_jwk(public_key, kid, use="sig"):
    numbers = public_key.public_numbers()
    size = (numbers.n.bit_length() + 7) // 8
    return {
        "kty": "RSA", "kid": kid, "use": use, "alg": "RS256",
        "n": b64(numbers.n.to_bytes(size, "big")),
        "e": b64(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
    }


def make_token(private_key, kid, extra_header=None, **claims):
    header = {"alg": "RS256", "typ": "at+jwt", "kid": kid}
    header.update(extra_header or {})
    payload = {"iss": ISSUER, "aud": AUDIENCE, "sub": "app-exampleair",
               "client_id": "app-exampleair", "iat": NOW - 30, "exp": NOW + 3600,
               "jti": "t-0001"}
    payload.update(claims)
    part = lambda obj: b64(json.dumps(obj, separators=(",", ":"), sort_keys=True).encode())
    body = (part(header) + "." + part(payload)).encode("ascii")
    return body.decode("ascii") + "." + b64(private_key.sign(body, padding.PKCS1v15(), hashes.SHA256()))


def header_of(token):
    return json.loads(unb64(token.split(".")[0]))


def claims_of(token):
    return json.loads(unb64(token.split(".")[1]))


def signature_ok(token, public_key):
    head, body, signature = token.split(".")
    try:
        public_key.verify(unb64(signature), (head + "." + body).encode("ascii"),
                          padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False


class KeyEndpoint:
    """The issuer's jwks_uri. Its response is scripted: entries are served in order, and the last one repeats."""

    def __init__(self):
        self.script = []
        self.fetches = 0

    def serve(self, response):
        self.script.append(response)

    def fetch(self):
        self.fetches += 1
        response = self.script[-1] if len(self.script) == 1 else self.script.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class KeyCache:
    """The state machine. Which outcomes are authoritative, and which are not.

    The set is refreshed on a schedule once it passes max_age, and on demand
    when a kid is missing, with a cooldown so an unknown kid cannot drive a
    fetch storm. Without the scheduled refresh, a key removed by the issuer
    keeps verifying for as long as its kid stays in the cache.

    A refresh attempt that fails, scheduled or on demand, starts a back-off.
    No fetch is made until it has passed, so a failing endpoint is asked once
    per back-off, not once per request. failed_at is the time of the last
    failed attempt and loaded_at is the time of the last successful one. A
    healthy endpoint never sets failed_at, so its schedule is not delayed.

    While the endpoint is down the stale set stays in use. A key the issuer
    removed keeps verifying for the whole outage, and for up to one back-off
    after the endpoint is back.

    Project baseline, stated because no specification settles it:
      - A successful, well-formed set is authoritative. It replaces what we
        hold, even when it contains zero usable signing keys.
      - A malformed, truncated or failed retrieval is not authoritative. It
        leaves the last known good set in place. A request for a kid that is
        not in that set still fails; a request for a kid that is in it is
        served from the stale set.
    """

    max_age = 600
    cooldown = 300
    backoff = 60

    def __init__(self, endpoint, clock):
        self.endpoint = endpoint
        self.clock = clock
        self.keys = {}
        self.loaded_at = None
        self.last_attempt = None
        self.failed_at = None

    @property
    def loaded(self):
        return self.loaded_at is not None

    def _absorb(self, document):
        keys = {}
        seen = set()
        for jwk in document["keys"]:
            # RFC 7517 section 5: ignore a JWK whose key type is not
            # understood or that is missing required members.
            if (jwk.get("kty") != "RSA" or not isinstance(jwk.get("n"), str)
                    or not isinstance(jwk.get("e"), str)):
                continue
            kid = jwk.get("kid")
            if kid in seen:
                keys[kid] = "ambiguous"
                continue
            seen.add(kid)
            keys[kid] = jwk
        self.keys = keys
        self.loaded_at = self.clock[0]

    def _refresh(self, scheduled=False):
        """scheduled refreshes are ours; on-demand ones are triggered by input."""
        now = self.clock[0]
        if self.failed_at is not None and now - self.failed_at < self.backoff:
            return "backoff"
        if not scheduled and self.last_attempt is not None and now - self.last_attempt < self.cooldown:
            return "cooldown"
        self.last_attempt = now
        try:
            document = self.endpoint.fetch()
        except Exception:
            self.failed_at = now
            return "retrieval failed"
        if (not isinstance(document, dict) or not isinstance(document.get("keys"), list)
                or not all(isinstance(jwk, dict) for jwk in document["keys"])):
            self.failed_at = now
            return "malformed"
        self._absorb(document)
        self.failed_at = None
        return "ok"

    def resolve(self, kid):
        """Return (jwk, reason). Exactly one is None."""
        stale = self.loaded and self.clock[0] - self.loaded_at >= self.max_age
        if not self.loaded or stale:
            outcome = self._refresh(scheduled=True)
            if outcome != "ok" and not self.loaded:
                return None, "key set refresh failed"
        if kid not in self.keys:
            outcome = self._refresh()
            if outcome in ("malformed", "retrieval failed"):
                return None, "key set refresh failed"
            if kid not in self.keys:
                return None, "unknown kid"
        entry = self.keys[kid]
        if entry == "ambiguous":
            return None, "ambiguous kid"
        if entry.get("use") not in (None, "sig"):
            return None, "key not for signatures"
        return entry, None


def public_key_from(jwk):
    n = int.from_bytes(unb64(jwk["n"]), "big")
    e = int.from_bytes(unb64(jwk["e"]), "big")
    return rsa.RSAPublicNumbers(e, n).public_key()


class Verifier:
    """Local validation only. It can prove the token, not the grant."""

    def __init__(self, cache):
        self.cache = cache

    def verify(self, token, clock):
        header = header_of(token)
        if header.get("alg") != "RS256":
            return "reject: algorithm not allowed"
        # A key location in the token header is attacker-controlled input.
        jwk, reason = self.cache.resolve(header.get("kid"))
        if jwk is None:
            return "reject: " + reason
        if not signature_ok(token, public_key_from(jwk)):
            return "reject: signature check failed"
        claims = claims_of(token)
        if claims["iss"] != ISSUER or AUDIENCE not in [claims["aud"]]:
            return "reject: issuer or audience mismatch"
        if clock[0] >= claims["exp"]:      # RFC 7519 4.1.4: must be before exp
            return "reject: expired"
        return "accept"


class Introspection:
    """RFC 7662 endpoint. Answers for the moment it is asked."""

    def __init__(self, clock):
        self.clock = clock
        self.revoked = set()
        self.calls = 0

    def revoke(self, jti):
        self.revoked.add(jti)

    def introspect(self, jti):
        self.calls += 1
        return {"active": jti not in self.revoked}


class ResourceServer:
    """Local validation, then an active-state check with a cache in front."""

    def __init__(self, verifier, introspection, clock, cache_ttl=0):
        self.verifier = verifier
        self.introspection = introspection
        self.clock = clock
        self.cache_ttl = cache_ttl
        self.cache = {}

    def call(self, token, consult=True):
        local = self.verifier.verify(token, self.clock)
        if local != "accept" or not consult:
            return local
        jti = claims_of(token)["jti"]
        cached = self.cache.get(jti)
        if cached and self.clock[0] - cached[1] < self.cache_ttl:
            active = cached[0]
        else:
            active = self.introspection.introspect(jti)["active"]
            self.cache[jti] = (active, self.clock[0])
        return "accept" if active else "reject: token not active"


RESULTS = []


def check(label, expected, actual):
    RESULTS.append((label, expected, actual))
    print("%2d. %-43s %s" % (len(RESULTS), label, actual))


def main():
    clock = [NOW]
    key_a = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_b = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    enc_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    jwk_a = to_jwk(key_a.public_key(), "hotel-a")
    jwk_b = to_jwk(key_b.public_key(), "hotel-b")
    jwk_enc = to_jwk(enc_key.public_key(), "hotel-enc", use="enc")

    token_a = make_token(key_a, "hotel-a")
    token_b = make_token(key_b, "hotel-b")

    print("key source: RSA generated for this run; keys and tokens never printed")
    print()
    print("Part A: choosing a key.")

    endpoint = KeyEndpoint()
    endpoint.serve({"keys": [jwk_a]})
    cache = KeyCache(endpoint, clock)
    verifier = Verifier(cache)
    check("token signed by the key in the set", "accept", verifier.verify(token_a, clock))

    endpoint.script = [{"keys": [jwk_a, jwk_b]}]
    clock[0] += 400
    check("unknown kid, one bounded refresh finds it", "accept", verifier.verify(token_b, clock))

    missing = make_token(key_a, "hotel-gone")
    before = endpoint.fetches
    check("unknown kid again, inside the cooldown", "reject: unknown kid", verifier.verify(missing, clock))
    check("no second fetch during the cooldown", "pass: fetches unchanged",
          "pass: fetches unchanged" if endpoint.fetches == before else "fail: refetched")

    dup_endpoint = KeyEndpoint()
    dup_endpoint.serve({"keys": [jwk_a, dict(jwk_b, kid="hotel-a")]})
    dup = Verifier(KeyCache(dup_endpoint, clock))
    check("two keys sharing one kid in the set", "reject: ambiguous kid", dup.verify(token_a, clock))

    enc_endpoint = KeyEndpoint()
    enc_endpoint.serve({"keys": [jwk_enc]})
    enc = Verifier(KeyCache(enc_endpoint, clock))
    check("kid names a key marked use=enc", "reject: key not for signatures",
          enc.verify(make_token(enc_key, "hotel-enc"), clock))

    hostile = make_token(key_b, "hotel-b", extra_header={"jku": "https://attacker.example/keys"})
    solo = KeyEndpoint()
    solo.serve({"keys": [jwk_a]})
    check("jku in the header is ignored", "reject: unknown kid", Verifier(KeyCache(solo, clock)).verify(hostile, clock))

    print()
    print("Part B: the cache as a state machine.")

    rot = KeyEndpoint()
    rot.serve({"keys": [jwk_a]})
    rot_cache = KeyCache(rot, clock)
    rot_verifier = Verifier(rot_cache)
    check("initial load, token verifies", "accept", rot_verifier.verify(token_a, clock))

    rot.script = [{"keys": [jwk_a, jwk_b]}]
    clock[0] += 700
    rot_verifier.verify(token_b, clock)
    check("rotation overlap, old token still works", "accept", rot_verifier.verify(token_a, clock))

    rot.script = [{"keys": [jwk_b]}]
    clock[0] += 700
    check("old key removed after the overlap", "reject: unknown kid", rot_verifier.verify(token_a, clock))

    empty = KeyEndpoint()
    empty.serve({"keys": [jwk_a]})
    empty_cache = KeyCache(empty, clock)
    empty_verifier = Verifier(empty_cache)
    empty_verifier.verify(token_a, clock)
    empty.script = [{"keys": []}]
    clock[0] += 700
    check("a successful empty set evicts the old key", "reject: unknown kid", empty_verifier.verify(token_a, clock))

    bad = KeyEndpoint()
    bad.serve({"keys": [jwk_a]})
    bad_cache = KeyCache(bad, clock)
    bad_verifier = Verifier(bad_cache)
    bad_verifier.verify(token_a, clock)
    bad.script = ["<html>502 Bad Gateway</html>"]
    clock[0] += 400
    check("malformed refresh, the request needing it", "reject: key set refresh failed",
          bad_verifier.verify(token_b, clock))
    check("malformed refresh kept the last good set", "accept",
          bad_verifier.verify(token_a, clock))

    down = KeyEndpoint()
    down.serve({"keys": [jwk_a]})
    down_cache = KeyCache(down, clock)
    down_verifier = Verifier(down_cache)
    down_verifier.verify(token_a, clock)
    down.script = [TimeoutError("connect timed out")]
    clock[0] += 400
    check("transport failure, the request needing it", "reject: key set refresh failed",
          down_verifier.verify(token_b, clock))
    check("transport failure kept the last good set", "accept",
          down_verifier.verify(token_a, clock))

    # The shared clock has moved 3300 seconds by now, so this scenario signs
    # its own tokens. The first two would be past exp before it ends.
    late = {"iat": clock[0] - 30, "exp": clock[0] + 3600}
    late_a = make_token(key_a, "hotel-a", **late)
    late_b = make_token(key_b, "hotel-b", **late)
    out = KeyEndpoint()
    out.serve({"keys": [jwk_a]})
    out_cache = KeyCache(out, clock)
    out_verifier = Verifier(out_cache)
    out_verifier.verify(late_a, clock)
    # The issuer removes key a, and its endpoint goes down before we learn it.
    out.script = [TimeoutError("connect timed out")]
    clock[0] += 700
    before = out.fetches
    check("outage, stale set, kid still in the set", "accept", out_verifier.verify(late_a, clock))
    for kid in ("hotel-a", "hotel-x1", "hotel-a", "hotel-x2"):
        clock[0] += 10
        out_verifier.verify(make_token(key_a, kid, **late), clock)
    check("5 requests inside the back-off", "fetches: 1", "fetches: %d" % (out.fetches - before))
    clock[0] += 20
    out_verifier.verify(late_a, clock)
    check("back-off over, the next request retries", "fetches: 2", "fetches: %d" % (out.fetches - before))
    out.script = [{"keys": [jwk_b]}]
    clock[0] += 60
    check("endpoint back, the removed key", "reject: unknown kid", out_verifier.verify(late_a, clock))
    check("endpoint back, the new key", "accept", out_verifier.verify(late_b, clock))

    print()
    print("Part C: revocation.")

    clock = [NOW]
    live = KeyEndpoint()
    live.serve({"keys": [jwk_a]})
    live_verifier = Verifier(KeyCache(live, clock))
    introspection = Introspection(clock)
    plain = ResourceServer(live_verifier, introspection, clock, cache_ttl=0)

    check("before revocation", "accept", plain.call(token_a))
    introspection.revoke("t-0001")
    check("after revocation, local validation only", "accept", plain.call(token_a, consult=False))
    check("after revocation, active state consulted", "reject: token not active", plain.call(token_a))

    cached = ResourceServer(live_verifier, Introspection(clock), clock, cache_ttl=300)
    check("first call fills the active-state cache", "accept", cached.call(token_a))
    cached.introspection.revoke("t-0001")
    clock[0] += 60
    check("revoked, but inside the cache window", "accept", cached.call(token_a))
    clock[0] += 300
    check("the same token once the cache expires", "reject: token not active", cached.call(token_a))

    # Exact comparison. A prefix match would let a check pass for the wrong
    # reason, which is the bug this lab is about.
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
