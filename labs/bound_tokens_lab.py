#!/usr/bin/env python3
"""Module 7 lab: sender-constrained tokens, mTLS and DPoP.

Three modules have ended with the same unblocked row: a stolen, current,
genuine token still works. This is that row.

Part A is the bearer baseline. Part B binds the token to a key the client
holds, at the application layer, with DPoP. Part C binds it to a client
certificate, at the transport layer, with mutual TLS. Part D is the honest
limit: neither one helps once the attacker has the key as well, and neither
one notices a withdrawn grant.

The TLS layer is simulated. A real resource server takes the client
certificate from its TLS implementation, as RFC 8705 section 3.4 requires;
here the certificate is passed to the handler directly. Everything else,
including the certificate, its DER encoding, the thumbprints and every
signature, is real.

This lab needs one package:
    python3 -m pip install cryptography==50.0.1
Inside an activated virtual environment the command is python, not py -3.

Exit codes: 0 all checks matched, 1 a check did not match, 2 the package is
missing so nothing ran.
"""
import base64
import datetime
import hashlib
import json
import sys

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    from cryptography.x509.oid import NameOID
except ImportError:
    print("This lab needs the cryptography package, because Python has no")
    print("asymmetric cryptography in its standard library.")
    print()
    print("    python3 -m pip install cryptography==50.0.1")
    print()
    print("Modules 1, 2 and 4 still need nothing beyond Python 3.")
    sys.exit(2)

NOW = 1790000000
ISSUER = "https://auth.hotel.example"
AUDIENCE = "https://api.hotel.example"
TARGET = "https://api.hotel.example/balance"


def b64(raw):
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def unb64(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def encode(header, payload, sign):
    part = lambda o: b64(json.dumps(o, separators=(",", ":"), sort_keys=True).encode())
    body = (part(header) + "." + part(payload)).encode("ascii")
    return body.decode("ascii") + "." + b64(sign(body))


def header_of(token):
    return json.loads(unb64(token.split(".")[0]))


def claims_of(token):
    return json.loads(unb64(token.split(".")[1]))


def ec_jwk(public_key):
    numbers = public_key.public_numbers()
    return {"crv": "P-256", "kty": "EC",
            "x": b64(numbers.x.to_bytes(32, "big")),
            "y": b64(numbers.y.to_bytes(32, "big"))}


def jkt(jwk):
    """RFC 9449 section 6.1: base64url of the RFC 7638 JWK SHA-256 thumbprint."""
    canonical = json.dumps({k: jwk[k] for k in sorted(("crv", "kty", "x", "y"))},
                           separators=(",", ":"), sort_keys=True)
    return b64(hashlib.sha256(canonical.encode("ascii")).digest())


def ath(token):
    """RFC 9449 section 4.2: base64url of the SHA-256 of the ASCII access token."""
    return b64(hashlib.sha256(token.encode("ascii")).digest())


def x5t_s256(certificate):
    """RFC 8705 section 3.1: base64url SHA-256 of the DER encoding, unpadded."""
    der = certificate.public_bytes(serialization.Encoding.DER)
    return b64(hashlib.sha256(der).digest())


def self_signed(common_name):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    start = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    certificate = (x509.CertificateBuilder()
                   .subject_name(name).issuer_name(name)
                   .public_key(key.public_key())
                   .serial_number(x509.random_serial_number())
                   .not_valid_before(start)
                   .not_valid_after(start + datetime.timedelta(days=365))
                   .sign(key, hashes.SHA256()))
    return key, certificate


def issue(signing_key, confirmation=None):
    claims = {"iss": ISSUER, "aud": AUDIENCE, "sub": "app-exampleair",
              "client_id": "app-exampleair", "iat": NOW - 30, "exp": NOW + 3600,
              "jti": "tok-0001"}
    if confirmation:
        claims["cnf"] = confirmation
    return encode({"alg": "RS256", "typ": "at+jwt", "kid": "hotel-a"}, claims,
                  lambda body: signing_key.sign(body, padding.PKCS1v15(), hashes.SHA256()))


def make_proof(key, method, url, token=None, jti="p-1", iat=NOW, typ="dpop+jwt", bind_ath=True):
    header = {"alg": "ES256", "typ": typ, "jwk": ec_jwk(key.public_key())}
    payload = {"jti": jti, "htm": method, "htu": url, "iat": iat}
    if token is not None and bind_ath:
        payload["ath"] = ath(token)
    return encode(header, payload, lambda body: key.sign(body, ec.ECDSA(hashes.SHA256())))


class ResourceServer:
    """Validates the token, then whatever binding the token declares."""

    proof_window = 60

    def __init__(self, issuer_public_key):
        self.issuer_public_key = issuer_public_key
        self.seen_proofs = set()
        self.revoked = set()

    def _token_ok(self, token):
        head, body, signature = token.split(".")
        try:
            self.issuer_public_key.verify(unb64(signature), (head + "." + body).encode("ascii"),
                                          padding.PKCS1v15(), hashes.SHA256())
        except Exception:
            return "reject: signature check failed"
        claims = claims_of(token)
        if claims["aud"] != AUDIENCE or claims["iss"] != ISSUER:
            return "reject: issuer or audience mismatch"
        if NOW > claims["exp"]:
            return "reject: expired"
        return None

    def call(self, token, method="GET", url=TARGET, proof=None, certificate=None,
             consult_revocation=False):
        failure = self._token_ok(token)
        if failure:
            return failure
        claims = claims_of(token)
        confirmation = claims.get("cnf", {})

        if "jkt" in confirmation:
            return self._check_dpop(token, confirmation, method, url, proof)
        if "x5t#S256" in confirmation:
            return self._check_mtls(confirmation, certificate)
        if consult_revocation and claims["jti"] in self.revoked:
            return "reject: token not active"
        return "accept"

    def _check_dpop(self, token, confirmation, method, url, proof):
        # RFC 9449 section 7.1: a proof must be present, valid, and its key must
        # match the key the access token is bound to.
        if proof is None:
            return "reject: DPoP proof required"
        header = header_of(proof)
        if header.get("typ") != "dpop+jwt":
            return "reject: proof typ not dpop+jwt"
        jwk = header.get("jwk") or {}
        head, body, signature = proof.split(".")
        try:
            numbers = ec.EllipticCurvePublicNumbers(
                int.from_bytes(unb64(jwk["x"]), "big"),
                int.from_bytes(unb64(jwk["y"]), "big"), ec.SECP256R1())
            numbers.public_key().verify(unb64(signature), (head + "." + body).encode("ascii"),
                                        ec.ECDSA(hashes.SHA256()))
        except Exception:
            return "reject: proof signature check failed"
        if jkt(jwk) != confirmation["jkt"]:
            return "reject: proof key not bound to token"
        claims = claims_of(proof)
        if claims.get("htm") != method:
            return "reject: htm mismatch"
        if claims.get("htu") != url:
            return "reject: htu mismatch"
        if abs(NOW - claims.get("iat", 0)) > self.proof_window:
            return "reject: proof outside the window"
        if claims.get("ath") != ath(token):
            return "reject: ath mismatch"
        if claims.get("jti") in self.seen_proofs:
            return "reject: proof jti already used"
        self.seen_proofs.add(claims.get("jti"))
        return "accept"

    def _check_mtls(self, confirmation, certificate):
        # RFC 8705 section 3.4: take the certificate from the TLS layer and
        # verify it matches the one the token is bound to.
        if certificate is None:
            return "reject: no client certificate"
        if x5t_s256(certificate) != confirmation["x5t#S256"]:
            return "reject: certificate does not match"
        return "accept"


RESULTS = []


def check(label, expected, actual):
    RESULTS.append((label, expected, actual))
    print("%2d. %-40s %s" % (len(RESULTS), label, actual))


def main():
    issuer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server = ResourceServer(issuer_key.public_key())

    client_key = ec.generate_private_key(ec.SECP256R1())
    attacker_key = ec.generate_private_key(ec.SECP256R1())
    client_tls_key, client_cert = self_signed("app-exampleair")
    attacker_tls_key, attacker_cert = self_signed("attacker")

    print("key source: generated for this run; keys, tokens and proofs never printed")
    print()
    print("Part A: a bearer token, as in modules 4 to 6.")

    bearer = issue(issuer_key)
    check("the real client uses its token", "accept", server.call(bearer))
    check("an attacker replays the stolen token", "accept", server.call(bearer))

    print()
    print("Part B: DPoP, bound to a key at the application layer.")

    dpop_token = issue(issuer_key, {"jkt": jkt(ec_jwk(client_key.public_key()))})
    good_proof = make_proof(client_key, "GET", TARGET, dpop_token, jti="p-1")
    check("the real client, with a fresh proof", "accept",
          server.call(dpop_token, proof=good_proof))
    check("stolen token, no proof at all", "reject: DPoP proof required",
          server.call(dpop_token))
    check("stolen token, the attacker's own key", "reject: proof key not bound to token",
          server.call(dpop_token, proof=make_proof(attacker_key, "GET", TARGET, dpop_token, jti="p-2")))
    check("stolen token and the captured proof", "reject: proof jti already used",
          server.call(dpop_token, proof=good_proof))
    check("proof made for a different method", "reject: htm mismatch",
          server.call(dpop_token, proof=make_proof(client_key, "POST", TARGET, dpop_token, jti="p-3")))
    check("proof made for a different URL", "reject: htu mismatch",
          server.call(dpop_token, proof=make_proof(client_key, "GET", "https://api.hotel.example/transfer", dpop_token, jti="p-4")))
    check("proof created outside the window", "reject: proof outside the window",
          server.call(dpop_token, proof=make_proof(client_key, "GET", TARGET, dpop_token, jti="p-5", iat=NOW - 600)))
    check("proof not bound to this access token", "reject: ath mismatch",
          server.call(dpop_token, proof=make_proof(client_key, "GET", TARGET, dpop_token, jti="p-6", bind_ath=False)))
    check("the real client's next request", "accept",
          server.call(dpop_token, proof=make_proof(client_key, "GET", TARGET, dpop_token, jti="p-7")))

    print()
    print("Part C: mutual TLS, bound to a certificate at the transport layer.")

    mtls_token = issue(issuer_key, {"x5t#S256": x5t_s256(client_cert)})
    check("the real client, with its certificate", "accept",
          server.call(mtls_token, certificate=client_cert))
    check("stolen token, no client certificate", "reject: no client certificate",
          server.call(mtls_token))
    check("stolen token, the attacker's certificate", "reject: certificate does not match",
          server.call(mtls_token, certificate=attacker_cert))

    print()
    print("Part D: what binding does not fix.")

    check("the attacker stole the private key too", "accept",
          server.call(dpop_token, proof=make_proof(client_key, "GET", TARGET, dpop_token, jti="p-8")))
    server.revoked.add("tok-0001")
    check("bound token after the grant is withdrawn", "accept",
          server.call(mtls_token, certificate=client_cert))

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
