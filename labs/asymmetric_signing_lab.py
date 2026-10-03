#!/usr/bin/env python3
"""Module 3 lab: asymmetric request signing with RFC 9421.

Module 2 ended with a row that never turned green: take the key from the
receiver and sign new requests as the caller. An HMAC gives both sides the
same power, so a breached receiver can always forge. This lab starts there.

Part A reproduces that limit inside RFC 9421, using its hmac-sha256
algorithm, so that Part A and Part B differ only in the key. Part B swaps in
an Ed25519 keypair and the row closes: the receiver's store holds a public
key, which can verify and cannot sign. Part C is the coverage trap that makes
real deployments insecure anyway, a digest header that is present but not
covered, or covered but never recomputed. Part D is the parameter and key
policy RFC 9421 section 1.4 requires every application to write down. Part E
is what signing does not fix.

Every signature base, signature and digest here is real. The Signature-Input
and Signature header fields are serialized and parsed as text, with a parser
that covers the subset this lab produces rather than the whole Structured
Fields grammar.

This lab needs one package:
    python3 -m pip install cryptography==50.0.1
Inside an activated virtual environment the command is python, not py -3.

Exit codes: 0 all checks matched, 1 a check did not match, 2 the package is
missing so nothing ran.
"""
import base64
import hashlib
import hmac
import secrets
import sys

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.asymmetric.utils import (
        decode_dss_signature, encode_dss_signature)
except ImportError:
    print("This lab needs the cryptography package, because Python has no")
    print("asymmetric cryptography in its standard library.")
    print()
    print("    python3 -m pip install cryptography==50.0.1")
    print()
    print("Modules 1, 2 and 4 still need nothing beyond Python 3.")
    sys.exit(2)

NOW = 1716307200          # the same clock module 2 used
WINDOW_SECONDS = 300      # project baseline: how old a created value may be
AUTHORITY = "api.hotel.example"


# ---------------------------------------------------------------- signature base

def component_value(name, message):
    """RFC 9421 section 2: derived components, then header fields."""
    if name == "@method":
        return message["method"]
    if name == "@authority":
        return message["authority"]
    if name == "@path":
        return message["path"]
    if name == "@target-uri":
        return "https://%s%s" % (message["authority"], message["path"])
    value = message["headers"].get(name)
    if value is None:
        raise LookupError(name)
    return value.strip()


def serialize_params(components, params):
    """The @signature-params value: an Inner List, then its parameters."""
    out = "(%s)" % " ".join('"%s"' % c for c in components)
    for key, value in params:
        if isinstance(value, int):
            out += ";%s=%d" % (key, value)
        else:
            out += ';%s="%s"' % (key, value)
    return out


def signature_base(components, params, message):
    """RFC 9421 section 2.5. The parameters line is always last."""
    lines = ['"%s": %s' % (name, component_value(name, message))
             for name in components]
    lines.append('"@signature-params": ' + serialize_params(components, params))
    return "\n".join(lines).encode("ascii")


def parse_signature_input(text):
    """Read back sig1=("@method" "@path");created=1;keyid="k";alg="a".

    Covers the shape this lab emits, not the full Structured Fields grammar.
    """
    label, rest = text.split("=", 1)
    inner, _, tail = rest.partition(")")
    components = [item.strip('"') for item in inner.lstrip("(").split()] if inner.lstrip("(") else []
    params = []
    for piece in tail.split(";"):
        if not piece:
            continue
        key, _, raw = piece.partition("=")
        params.append((key, raw.strip('"') if raw.startswith('"') else int(raw)))
    return label.strip(), components, params


def b64(raw):
    return base64.b64encode(raw).decode("ascii")


def content_digest(body):
    """RFC 9530 section 2: sha-256=:<base64>: as a Structured Field."""
    return "sha-256=:%s:" % b64(hashlib.sha256(body).digest())


# ---------------------------------------------------------------------- signing

def sign_message(message, keyid, alg, components, params, signer):
    """Attach Signature-Input and Signature to a copy of the message."""
    full = [("created", NOW)] + list(params) + [("keyid", keyid), ("alg", alg)]
    base = signature_base(components, full, message)
    signed = dict(message)
    signed["headers"] = dict(message["headers"])
    signed["headers"]["signature-input"] = "sig1=" + serialize_params(components, full)
    signed["headers"]["signature"] = "sig1=:%s:" % b64(signer(base))
    return signed


def ed25519_signer(private_key):
    return private_key.sign


def hmac_signer(secret):
    return lambda base: hmac.new(secret, base, hashlib.sha256).digest()


def ecdsa_p256_signer(private_key):
    """RFC 9421 section 3.3.4: the signature is R and S concatenated, not DER."""
    def sign(base):
        r, s = decode_dss_signature(private_key.sign(base, ec.ECDSA(hashes.SHA256())))
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return sign


# -------------------------------------------------------------------- verifying

class Verifier:
    """One verifier, three policies, so each omission has its own check.

    require_covered   component names the application insists are covered
    recompute_digest  hash the received body and compare with Content-Digest
    allowed_algs      the algorithm allowlist RFC 9421 section 1.4 requires
    """

    def __init__(self, keys, require_covered=(), recompute_digest=False,
                 allowed_algs=("ed25519", "hmac-sha256", "ecdsa-p256-sha256")):
        self.keys = keys
        self.require_covered = tuple(require_covered)
        self.recompute_digest = recompute_digest
        self.allowed_algs = tuple(allowed_algs)
        self.seen_nonces = set()

    def verify(self, message, now=NOW):
        headers = message["headers"]
        if "signature-input" not in headers or "signature" not in headers:
            return "reject: no signature"
        try:
            label, components, params = parse_signature_input(headers["signature-input"])
            fields = dict(params)
            signature = base64.b64decode(headers["signature"].split("=:", 1)[1].rstrip(":"))
        except (ValueError, IndexError):
            return "reject: malformed signature fields"

        keyid = fields.get("keyid")
        if keyid not in self.keys:
            return "reject: unknown keyid"
        entry = self.keys[keyid]
        alg = fields.get("alg")
        if alg not in self.allowed_algs:
            return "reject: alg not allowed"
        if alg != entry["alg"]:
            return "reject: alg not valid for this key"

        for name in self.require_covered:
            if name not in components:
                return "reject: required component not covered"

        try:
            base = signature_base(components, params, message)
        except LookupError:
            return "reject: covered component missing"
        if not self._signature_ok(entry, alg, signature, base):
            return "reject: signature check failed"

        # Only now is anything in the message trustworthy.
        if self.recompute_digest:
            claimed = message["headers"].get("content-digest")
            if claimed != content_digest(message["body"]):
                return "reject: content-digest does not match the body"
        created = fields.get("created")
        if created is None or abs(now - created) > WINDOW_SECONDS:
            return "reject: created outside the window"
        if "expires" in fields and now > fields["expires"]:
            return "reject: signature expired"
        nonce = fields.get("nonce")
        if nonce is None:
            return "reject: nonce missing"
        # Recorded after the signature verifies, so forged requests
        # cannot fill the store. Module 2 taught this order.
        if nonce in self.seen_nonces:
            return "reject: nonce already used"
        self.seen_nonces.add(nonce)
        return "accept"

    def _signature_ok(self, entry, alg, signature, base):
        material = entry["material"]
        try:
            if alg == "hmac-sha256":
                return hmac.compare_digest(
                    signature, hmac.new(material, base, hashlib.sha256).digest())
            if alg == "ed25519":
                material.verify(signature, base)
                return True
            if alg == "ecdsa-p256-sha256":
                der = encode_dss_signature(int.from_bytes(signature[:32], "big"),
                                           int.from_bytes(signature[32:], "big"))
                material.verify(der, base, ec.ECDSA(hashes.SHA256()))
                return True
        except Exception:
            return False
        return False


def forge_from_store(keys, keyid, message, components, params):
    """Can whoever holds the receiver's key store sign a new request?

    For a shared secret the stored material signs. For a public key it does
    not: Ed25519PublicKey has no sign method, which is the whole point.
    """
    material = keys[keyid]["material"]
    if isinstance(material, bytes):
        return sign_message(message, keyid, "hmac-sha256", components, params,
                            hmac_signer(material))
    if hasattr(material, "sign"):
        return sign_message(message, keyid, keys[keyid]["alg"], components, params,
                            material.sign)
    return None


# ------------------------------------------------------------------------ checks

RESULTS = []


def check(label, expected, actual):
    RESULTS.append((label, expected, actual))
    print("%2d. %-47s %s" % (len(RESULTS), label, actual))


def request(path="/v2/transfer", body=None, digest=True):
    body = body if body is not None else \
        b'{"linkId":"lnk_7Q2x9","partnerTxnId":"EXA-000042","miles":10000}'
    headers = {"content-type": "application/json"}
    if digest:
        headers["content-digest"] = content_digest(body)
    return {"method": "POST", "authority": AUTHORITY, "path": path,
            "headers": headers, "body": body}


def swap_body(message, body):
    """What an intermediary can do: change the body, leave the headers."""
    changed = dict(message)
    changed["body"] = body
    return changed


BIGGER = b'{"linkId":"lnk_7Q2x9","partnerTxnId":"EXA-000042","miles":900000}'
COVERED = ["@method", "@authority", "@path", "content-type", "content-digest"]
UNCOVERED = ["@method", "@authority", "@path", "content-type"]


def main():
    shared_secret = secrets.token_bytes(32)
    client_key = Ed25519PrivateKey.generate()
    attacker_key = Ed25519PrivateKey.generate()
    ec_key = ec.generate_private_key(ec.SECP256R1())

    print("key source: generated for this run; no key material is printed")
    print()
    print("Part A: a shared secret, as in module 2.")

    shared_store = {"exampleair-hmac": {"alg": "hmac-sha256", "material": shared_secret}}
    receiver = Verifier(shared_store, require_covered=("content-digest",),
                        recompute_digest=True, allowed_algs=("hmac-sha256",))
    signed = sign_message(request(), "exampleair-hmac", "hmac-sha256", COVERED,
                          [("nonce", "n-000")], hmac_signer(shared_secret))
    check("the real client signs a transfer", "accept", receiver.verify(signed))
    check("one covered field changed in flight", "reject: signature check failed",
          receiver.verify(dict(signed, path="/v2/transfer-fast")))
    forged = forge_from_store(shared_store, "exampleair-hmac",
                              request(body=BIGGER), COVERED, [("nonce", "forge-a")])
    check("the receiver forges a request as the client", "accept",
          receiver.verify(forged))

    print()
    print("Part B: an Ed25519 keypair. Only the client can sign.")

    store = {"exampleair-2026-a": {"alg": "ed25519", "material": client_key.public_key()}}
    server = Verifier(store, require_covered=("content-digest",), recompute_digest=True,
                      allowed_algs=("ed25519",))
    signed = sign_message(request(), "exampleair-2026-a", "ed25519", COVERED,
                          [("nonce", "n-001")], ed25519_signer(client_key))
    check("the real client signs a transfer", "accept", server.verify(signed))
    attempt = forge_from_store(store, "exampleair-2026-a", request(body=BIGGER),
                               COVERED, [("nonce", "forge-b")])
    check("the receiver tries to forge as the client",
          "reject: the store holds no signing key",
          "reject: the store holds no signing key" if attempt is None
          else server.verify(attempt))
    check("one covered field changed in flight", "reject: signature check failed",
          server.verify(dict(signed, path="/v2/transfer-fast")))
    own_key = sign_message(request(body=BIGGER), "exampleair-2026-a", "ed25519", COVERED,
                           [("nonce", "n-0a")], ed25519_signer(attacker_key))
    check("an attacker signs with its own key", "reject: signature check failed",
          server.verify(own_key))
    stripped = dict(signed)
    stripped["headers"] = {k: v for k, v in signed["headers"].items() if k != "content-type"}
    check("a covered component removed in flight", "reject: covered component missing",
          server.verify(stripped))
    auditor = Verifier(dict(store), require_covered=("content-digest",),
                       recompute_digest=True, allowed_algs=("ed25519",))
    check("a third party verifies, public key only", "accept", auditor.verify(signed))

    print()
    print("Part C: the coverage traps. The signature verifies either way.")

    loose = Verifier(store, allowed_algs=("ed25519",))
    uncovered = sign_message(request(), "exampleair-2026-a", "ed25519", UNCOVERED,
                             [("nonce", "n-002")], ed25519_signer(client_key))
    check("digest present, not covered, body swapped", "accept",
          loose.verify(swap_body(uncovered, BIGGER)))
    strict = Verifier(store, require_covered=("content-digest",), allowed_algs=("ed25519",))
    check("the same request, coverage required",
          "reject: required component not covered",
          strict.verify(swap_body(uncovered, BIGGER)))
    covered = sign_message(request(), "exampleair-2026-a", "ed25519", COVERED,
                           [("nonce", "n-003")], ed25519_signer(client_key))
    check("digest covered, never recomputed, body swapped", "accept",
          strict.verify(swap_body(covered, BIGGER)))
    check("the same request, digest recomputed",
          "reject: content-digest does not match the body",
          server.verify(swap_body(covered, BIGGER)))

    print()
    print("Part D: parameters and key selection.")

    stale = sign_message(request(), "exampleair-2026-a", "ed25519", COVERED,
                         [("nonce", "n-004")], ed25519_signer(client_key))
    check("created before the window", "reject: created outside the window",
          server.verify(stale, now=NOW + WINDOW_SECONDS + 60))
    short = sign_message(request(), "exampleair-2026-a", "ed25519", COVERED,
                         [("expires", NOW + 30), ("nonce", "n-005")],
                         ed25519_signer(client_key))
    check("expires already passed", "reject: signature expired",
          server.verify(short, now=NOW + 120))
    replay = sign_message(request(), "exampleair-2026-a", "ed25519", COVERED,
                          [("nonce", "n-006")], ed25519_signer(client_key))
    server.verify(replay)
    check("the nonce is reused", "reject: nonce already used", server.verify(replay))
    unknown = sign_message(request(), "exampleair-2029-z", "ed25519", COVERED,
                           [("nonce", "n-007")], ed25519_signer(client_key))
    check("an unknown keyid", "reject: unknown keyid", server.verify(unknown))
    both = dict(store)
    both["exampleair-2026-ec"] = {"alg": "ecdsa-p256-sha256",
                                  "material": ec_key.public_key()}
    permissive = Verifier(both, require_covered=("content-digest",), recompute_digest=True)
    confused = sign_message(request(), "exampleair-2026-a", "hmac-sha256", COVERED,
                            [("nonce", "n-008")], hmac_signer(shared_secret))
    check("alg says hmac-sha256 for an Ed25519 key",
          "reject: alg not valid for this key", permissive.verify(confused))
    ec_signed = sign_message(request(), "exampleair-2026-ec", "ecdsa-p256-sha256",
                             COVERED, [("nonce", "n-009")], ecdsa_p256_signer(ec_key))
    check("a valid ecdsa-p256-sha256 signature", "accept", permissive.verify(ec_signed))
    ed25519_only = Verifier(both, require_covered=("content-digest",),
                            recompute_digest=True, allowed_algs=("ed25519",))
    check("the same request against an allowlist of one",
          "reject: alg not allowed", ed25519_only.verify(ec_signed))

    print()
    print("Part E: what signing does not fix.")

    stolen = sign_message(request(body=BIGGER), "exampleair-2026-a", "ed25519", COVERED,
                          [("nonce", "n-010")], ed25519_signer(client_key))
    check("the attacker stole the client's private key", "accept",
          server.verify(stolen))
    unauthorized = sign_message(request(path="/v2/close-account"), "exampleair-2026-a",
                                "ed25519", COVERED, [("nonce", "n-011")],
                                ed25519_signer(client_key))
    check("a signed request the caller may not make", "accept",
          server.verify(unauthorized))

    print()
    print("The signature base that check 4 signed, exactly as signed:")
    for line in signature_base(COVERED,
                               [("created", NOW), ("nonce", "n-001"),
                                ("keyid", "exampleair-2026-a"), ("alg", "ed25519")],
                               request()).decode("ascii").split("\n"):
        print("  " + line)

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
