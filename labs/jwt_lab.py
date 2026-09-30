#!/usr/bin/env python3
"""Module 5 lab: JWT validation.

Builds real RS256 tokens with an RSA key generated for this run, then sends the
same tokens past two verifiers. Part A trusts what the token says about itself.
Part B enforces a profile the application declared in advance. Every attack in
part A succeeds. The same attacks fail in part B.

This lab needs one package, because Python has no asymmetric cryptography:
    python3 -m pip install cryptography==50.0.1

Keys, tokens and signatures stay in memory. Nothing is printed but the check
labels and their outcomes.

Exit codes: 0 all checks matched, 1 a check did not match, 2 the package is
missing so nothing ran.

Run from the project root:
    python3 labs/jwt_lab.py
"""
import base64
import hashlib
import hmac
import json
import sys

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
except ImportError:
    print("This lab needs the cryptography package, because Python has no")
    print("asymmetric cryptography in its standard library.")
    print()
    print("    python3 -m pip install cryptography==50.0.1")
    print()
    print("Modules 1, 2 and 4 still need nothing beyond Python 3.")
    sys.exit(2)

# A fixed reference time, so every run prints the same thing.
NOW = 1790000000
HOUR = 3600

ISSUER = "https://auth.hotel.example"
AUDIENCE = "https://api.hotel.example"
OTHER_AUDIENCE = "https://ledger.hotel.example"
CLIENT = "app-exampleair"


def b64(raw):
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def unb64(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def signing_input(header, payload):
    part = lambda obj: b64(json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    return (part(header) + "." + part(payload)).encode("ascii")


def make_rs256(header, payload, private_key):
    body = signing_input(header, payload)
    signature = private_key.sign(body, padding.PKCS1v15(), hashes.SHA256())
    return body.decode("ascii") + "." + b64(signature)


def make_hs256(header, payload, secret):
    body = signing_input(header, payload)
    signature = hmac.new(secret, body, hashlib.sha256).digest()
    return body.decode("ascii") + "." + b64(signature)


def make_unsigned(header, payload):
    # RFC 7518 section 3.6: an Unsecured JWS MUST use the empty octet sequence.
    return signing_input(header, payload).decode("ascii") + "."


def split(token):
    head, _, rest = token.partition(".")
    body, _, signature = rest.partition(".")
    return head, body, signature


def claims_of(token):
    return json.loads(unb64(split(token)[1]))


def header_of(token):
    return json.loads(unb64(split(token)[0]))


def rs256_ok(token, public_key):
    head, body, signature = split(token)
    try:
        public_key.verify(unb64(signature), (head + "." + body).encode("ascii"),
                          padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False


def hs256_ok(token, secret):
    head, body, signature = split(token)
    expected = hmac.new(secret, (head + "." + body).encode("ascii"), hashlib.sha256).digest()
    try:
        return hmac.compare_digest(unb64(signature), expected)
    except Exception:
        return False


class TrustingVerifier:
    """Reads the algorithm out of the token and does what it is told.

    This is the shape of a real defect, not a strawman: the verifier holds one
    key, and picks the operation from the token's own header.
    """

    def __init__(self, public_key):
        self.public_key = public_key
        self.public_pem = public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo)

    def verify(self, token):
        algorithm = header_of(token).get("alg")
        if algorithm == "none":
            return "accept"
        if algorithm == "HS256":
            # The public key is public. Using it as an HMAC secret is the bug.
            return "accept" if hs256_ok(token, self.public_pem) else "reject: signature check failed"
        if algorithm == "RS256":
            return "accept" if rs256_ok(token, self.public_key) else "reject: signature check failed"
        return "reject: unknown algorithm"


class ProfileVerifier:
    """Enforces a profile the application declared before seeing any token.

    Algorithms, token type, issuer, audience and required claims are all fixed
    here, never read from the token.
    """

    allowed_algorithms = ("RS256",)
    token_type = "at+jwt"
    # RFC 9068 section 2.2 required claims for an OAuth JWT access token.
    required_claims = ("iss", "exp", "aud", "sub", "client_id", "iat", "jti")
    leeway = 60

    def __init__(self, public_key, issuer, audience):
        self.public_key = public_key
        self.issuer = issuer
        self.audience = audience

    def verify(self, token, now=NOW):
        header = header_of(token)
        if header.get("alg") not in self.allowed_algorithms:
            return "reject: algorithm not allowed"
        if header.get("typ") != self.token_type:
            return "reject: wrong token type"
        if not rs256_ok(token, self.public_key):
            return "reject: signature check failed"
        claims = claims_of(token)
        for name in self.required_claims:
            if name not in claims:
                return "reject: missing claim " + name
        if claims["iss"] != self.issuer:
            return "reject: issuer mismatch"
        audience = claims["aud"]
        audience = audience if isinstance(audience, list) else [audience]
        if self.audience not in audience:
            return "reject: audience mismatch"
        if now > claims["exp"] + self.leeway:
            return "reject: expired"
        if "nbf" in claims and now + self.leeway < claims["nbf"]:
            return "reject: not yet valid"
        if now + self.leeway < claims["iat"]:
            return "reject: issued in the future"
        return "accept"


def access_claims(**overrides):
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": CLIENT,
        "client_id": CLIENT,
        "iat": NOW - 30,
        "exp": NOW + HOUR,
        "jti": "b7f1c0d2-0001",
        "scope": "balance:read",
    }
    claims.update(overrides)
    for key, value in list(claims.items()):
        if value is None:
            del claims[key]
    return claims


RESULTS = []


def check(label, expected, actual):
    RESULTS.append((label, expected, actual))
    print("%2d. %-42s %s" % (len(RESULTS), label, actual))


def main():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    header = {"alg": "RS256", "typ": "at+jwt", "kid": "hotel-2026-09"}
    genuine = make_rs256(header, access_claims(), private_key)

    trusting = TrustingVerifier(public_key)
    unsigned = make_unsigned({"alg": "none", "typ": "at+jwt"}, access_claims(sub="admin"))
    confused = make_hs256({"alg": "HS256", "typ": "at+jwt"}, access_claims(sub="admin"),
                          trusting.public_pem)
    wrong_audience = make_rs256(header, access_claims(aud=OTHER_AUDIENCE), private_key)
    expired = make_rs256(header, access_claims(exp=NOW - HOUR, iat=NOW - 2 * HOUR), private_key)

    print("key source: RSA generated for this run; keys and tokens never printed")
    print()
    print("Part A: a verifier that reads the algorithm out of the token.")
    check("genuine RS256 access token", "accept", trusting.verify(genuine))
    check("alg none, signature removed", "accept", trusting.verify(unsigned))
    check("alg HS256 signed with the public key", "accept", trusting.verify(confused))
    check("token issued for another audience", "accept", trusting.verify(wrong_audience))
    check("token that expired an hour ago", "accept", trusting.verify(expired))

    print()
    print("Part B: a verifier that enforces a declared profile.")
    strict = ProfileVerifier(public_key, ISSUER, AUDIENCE)
    check("genuine RS256 access token", "accept", strict.verify(genuine))
    check("alg none, signature removed", "reject: algorithm not allowed", strict.verify(unsigned))
    check("alg HS256 signed with the public key", "reject: algorithm not allowed", strict.verify(confused))
    check("token issued for another audience", "reject: audience mismatch", strict.verify(wrong_audience))
    check("token that expired an hour ago", "reject: expired", strict.verify(expired))

    other_issuer = make_rs256(header, access_claims(iss="https://auth.attacker.example"), private_key)
    check("token from a different issuer", "reject: issuer mismatch", strict.verify(other_issuer))

    id_token = make_rs256({"alg": "RS256", "typ": "JWT", "kid": "hotel-2026-09"},
                          access_claims(client_id=None, jti=None), private_key)
    check("an ID token where an access token is due", "reject: wrong token type", strict.verify(id_token))

    no_jti = make_rs256(header, access_claims(jti=None), private_key)
    check("required claim jti removed", "reject: missing claim jti", strict.verify(no_jti))

    head, body, signature = split(genuine)
    raw = bytearray(unb64(signature))
    raw[0] ^= 0x01
    tampered = head + "." + body + "." + b64(bytes(raw))
    check("one bit flipped in the signature", "reject: signature check failed", strict.verify(tampered))

    foreign = make_rs256(header, access_claims(), other_key)
    check("signed by a different RSA key", "reject: signature check failed", strict.verify(foreign))

    future = make_rs256(header, access_claims(nbf=NOW + 300), private_key)
    check("nbf five minutes in the future", "reject: not yet valid", strict.verify(future))

    just_expired = make_rs256(header, access_claims(exp=NOW - 30), private_key)
    check("expired 30s ago, inside 60s leeway", "accept", strict.verify(just_expired))

    # Exact comparison: a prefix match can let a check pass for the wrong reason.
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
