#!/usr/bin/env python3
"""Module 0 lab: hashes, HMACs and the line between them.

This is the primer's lab. It establishes, by running them, the three things
the rest of the course keeps assuming you know: what a hash proves, what an
HMAC adds, and why proving who sent a request tells you nothing about whether
they may make it.

Part A is hashing. Part B is HMAC. Part C prints the capability table the
whole course turns on: who can produce a value, and who can check it. Part D
is the distinction that no mechanism in Part 1 will fix for you.

The asymmetric row of the table in Part C is stated rather than demonstrated,
because Python has no asymmetric primitives in its standard library. Module 3
demonstrates it with real Ed25519 keys.

Needs nothing beyond Python 3.

Exit codes: 0 all checks matched, 1 a check did not match.
"""
import hashlib
import hmac
import sys

MESSAGE = b'{"partnerTxnId":"EXA-000042","miles":10000}'
ALTERED = b'{"partnerTxnId":"EXA-000042","miles":10001}'

# Two keys, fixed so the run is reproducible. Real keys are random and are
# never written in a file; module 2 covers where they come from instead.
KEY_A = bytes(range(32))
KEY_B = bytes(range(32, 64))

RESULTS = []


def check(label, expected, actual):
    RESULTS.append((label, expected, actual))
    print("%2d. %-48s %s" % (len(RESULTS), label, actual))


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def tag(key, data):
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def verify(key, data, signature):
    """Constant-time comparison, as module 2 requires."""
    return hmac.compare_digest(signature, tag(key, data))


def differing_bits(a, b):
    x = int(a, 16) ^ int(b, 16)
    return bin(x).count("1")


def main():
    print("message: %s" % MESSAGE.decode())
    print("altered: %s   (one digit)" % ALTERED.decode())
    print()
    print("Part A: a hash.")

    first, second = sha256(MESSAGE), sha256(MESSAGE)
    check("the same input twice", "identical",
          "identical" if first == second else "different")
    check("one digit changed", "different",
          "different" if sha256(ALTERED) != first else "identical")
    moved = differing_bits(first, sha256(ALTERED))
    check("bits that changed, out of 256", "roughly half",
          "roughly half" if 96 <= moved <= 160 else "%d, not roughly half" % moved)
    print("      (%d bits actually changed)" % moved)
    # No key was involved, so an attacker who changes the message can change
    # the hash beside it and the pair stays consistent.
    stolen_message, stolen_hash = ALTERED, sha256(ALTERED)
    check("an attacker alters the message and the hash", "still consistent",
          "still consistent" if sha256(stolen_message) == stolen_hash else "detected")

    print()
    print("Part B: an HMAC.")

    tag_a = tag(KEY_A, MESSAGE)
    check("the same key and message twice", "identical",
          "identical" if tag(KEY_A, MESSAGE) == tag_a else "different")
    check("the same message, a different key", "different",
          "different" if tag(KEY_B, MESSAGE) != tag_a else "identical")
    check("one digit changed, same key", "different",
          "different" if tag(KEY_A, ALTERED) != tag_a else "identical")
    check("the right key and message", "accepted",
          "accepted" if verify(KEY_A, MESSAGE, tag_a) else "rejected")
    check("the wrong key", "rejected",
          "rejected" if not verify(KEY_B, MESSAGE, tag_a) else "accepted")
    check("the altered message, the original tag", "rejected",
          "rejected" if not verify(KEY_A, ALTERED, tag_a) else "accepted")

    print()
    print("Part C: who can produce a value, and who can check it.")
    print()
    print("  %-22s %-26s %s" % ("mechanism", "can produce", "can check"))
    rows = [
        ("hash", "anyone", "anyone"),
        ("HMAC", "anyone holding the key", "anyone holding the key"),
        ("asymmetric signature", "the private key holder", "anyone with the public key"),
    ]
    for name, produce, check_it in rows:
        print("  %-22s %-26s %s" % (name, produce, check_it))
    print()
    print("  Rows 1 and 2 were produced above. Row 3 is stated here and")
    print("  demonstrated in module 3, because Python's standard library has")
    print("  no asymmetric primitives.")
    print()

    check("a tag proves which key was used", "yes",
          "yes" if tag(KEY_A, MESSAGE) != tag(KEY_B, MESSAGE) else "no")
    # The receiver holds the same key, so it can produce a tag for a message
    # the caller never sent, and its own verifier accepts it.
    forged_by_receiver = tag(KEY_A, ALTERED)
    check("a message the caller never sent, from the receiver", "accepted",
          "accepted" if verify(KEY_A, ALTERED, forged_by_receiver) else "rejected")

    print()
    print("Part D: authentication is not authorization.")

    accounts = {"app-exampleair": {"own": "acct-77"}}

    def handle(caller, request, signature, authorize):
        """Authenticate, then decide whether to also authorize."""
        if not verify(KEY_A, request, signature):
            return "reject: bad signature"
        target = request.decode().split("account=")[1]
        if authorize and target != accounts[caller]["own"]:
            return "reject: not your account"
        return "accept"

    own = b"GET /balance?account=acct-77"
    other = b"GET /balance?account=acct-91"

    check("the caller reads its own balance", "accept",
          handle("app-exampleair", own, tag(KEY_A, own), authorize=False))
    check("the same caller reads another account", "accept",
          handle("app-exampleair", other, tag(KEY_A, other), authorize=False))
    check("a forged request for another account", "reject: bad signature",
          handle("app-exampleair", other, tag(KEY_B, other), authorize=False))
    check("with an ownership check, its own account", "accept",
          handle("app-exampleair", own, tag(KEY_A, own), authorize=True))
    check("with an ownership check, another account", "reject: not your account",
          handle("app-exampleair", other, tag(KEY_A, other), authorize=True))

    print()
    print("  Check 14 is the whole point of this module. The signature was")
    print("  genuine, the caller was who it claimed, and the request should")
    print("  still have been refused. Nothing in Part 1 of this course adds")
    print("  the check that refuses it. Part 2 does.")

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
