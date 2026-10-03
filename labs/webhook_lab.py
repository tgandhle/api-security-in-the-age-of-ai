#!/usr/bin/env python3
"""Module 16 lab: receiving webhooks.

A webhook endpoint is a publicly reachable URL that changes your data when
somebody posts to it. Nothing about being on the internet authenticates the
caller, so the signature is the whole of the authentication, and the details
of what that signature covers decide what it is worth.

Part A is a receiver with no verification. Part B adds a signature over the
body and the timestamp. Part C is the four details that decide whether the
signature helps: what it covers, how old an event may be, whether the
identifier is recorded, and when it is recorded. Part D is what signing does
not fix, including the fact that a duplicate is usually not an attack.

Every signature here is a real HMAC. The transport is a stub, so the lab
opens no sockets.

Needs nothing beyond Python 3.

Exit codes: 0 all checks matched, 1 a check did not match.
"""
import hashlib
import hmac
import json
import secrets
import sys

NOW = 1790000000
WINDOW = 300          # project baseline: an event may be up to 5 minutes old

RESULTS = []


def check(label, expected, actual):
    RESULTS.append((label, expected, actual))
    print("%2d. %-52s %s" % (len(RESULTS), label, actual))


def body_of(event_id, kind, amount):
    """ExampleHotels tells ExampleAir a payment settled. Names are fictional."""
    return json.dumps({"jti": event_id, "type": kind, "amount": amount},
                      separators=(",", ":"), sort_keys=True).encode()


def sign(secret, body, timestamp=None):
    """Sign the body, and the timestamp too when one is given."""
    signed = body if timestamp is None else (b"%d." % timestamp) + body
    return hmac.new(secret, signed, hashlib.sha256).hexdigest()


class Receiver:
    """One receiver, five switches, so each omission has its own check."""

    def __init__(self, secret, verify=True, cover_timestamp=True,
                 check_window=True, record_ids=True, record_before=True):
        self.secret = secret
        self.verify = verify
        self.cover_timestamp = cover_timestamp
        self.check_window = check_window
        self.record_ids = record_ids
        self.record_before = record_before
        self.seen = set()
        self.applied = []

    def reserve(self, body, signature=None, timestamp=NOW, now=NOW):
        """Verify, then claim the identifier. Returns a response, or None."""
        if self.verify:
            if signature is None:
                return "400 no signature"
            expected = sign(self.secret, body,
                            timestamp if self.cover_timestamp else None)
            # Constant-time, for the reason module 2 gave.
            if not hmac.compare_digest(signature, expected):
                return "400 signature check failed"
            # abs(): a timestamp too far in the future is refused too, with
            # the same message.
            if self.check_window and abs(now - timestamp) > WINDOW:
                return "400 event too old"
        if self.record_ids:
            event_id = json.loads(body)["jti"]
            if event_id in self.seen:
                # RFC 8935 section 2: respond as if it had not been seen.
                return "202 accepted"
            if self.record_before:
                self.seen.add(event_id)
        return None

    def apply(self, body):
        """Do the work, and record the identifier if it was not claimed."""
        event = json.loads(body)
        self.applied.append(event)
        if self.record_ids and not self.record_before:
            self.seen.add(event["jti"])
        return "202 accepted"

    def post(self, body, signature=None, timestamp=NOW, now=NOW):
        early = self.reserve(body, signature, timestamp, now)
        return early if early is not None else self.apply(body)


def main():
    secret = secrets.token_bytes(32)
    other = secrets.token_bytes(32)
    body = body_of("evt-1001", "payment.settled", 42000)
    print("key source: random, this run only; no secret is printed")
    print()
    print("Part A: a receiver that verifies nothing.")

    open_ = Receiver(secret, verify=False, record_ids=False)
    check("the real sender posts an event", "202 accepted", open_.post(body))
    check("anyone who knows the URL posts one", "202 accepted",
          open_.post(body_of("evt-9001", "payment.settled", 9900000)))
    check("events applied", "2", str(len(open_.applied)))

    print()
    print("Part B: a signature over the body and the timestamp.")

    guarded = Receiver(secret)
    good = sign(secret, body, NOW)
    check("the real sender, correctly signed", "202 accepted",
          guarded.post(body, good))
    check("an unsigned post", "400 no signature",
          guarded.post(body_of("evt-9002", "payment.settled", 9900000)))
    check("signed with the wrong key", "400 signature check failed",
          guarded.post(body_of("evt-9003", "payment.settled", 9900000),
                       sign(other, body_of("evt-9003", "payment.settled", 9900000), NOW)))
    check("the body altered after signing", "400 signature check failed",
          guarded.post(body_of("evt-1001", "payment.settled", 9900000), good))
    check("events applied", "1", str(len(guarded.applied)))

    print()
    print("Part C: the four details.")

    # 1. What the signature covers.
    body_only = Receiver(secret, cover_timestamp=False, record_ids=False)
    stale_sig = sign(secret, body)
    # The signature does not cover the timestamp, so the attacker supplies a
    # fresh one and the window check has nothing to object to.
    check("signature over the body alone, replayed a year later",
          "202 accepted", body_only.post(body, stale_sig,
                                         timestamp=NOW + 31536000,
                                         now=NOW + 31536000))
    covered = Receiver(secret)
    check("the same replay, timestamp covered and checked", "400 event too old",
          covered.post(body, sign(secret, body, NOW), now=NOW + 31536000))

    # 2. Whether the window is checked at all.
    no_window = Receiver(secret, check_window=False)
    check("timestamp covered but never compared to the clock", "202 accepted",
          no_window.post(body, sign(secret, body, NOW), now=NOW + 31536000))

    # 3. Whether the identifier is recorded.
    no_ids = Receiver(secret, record_ids=False)
    no_ids.post(body, good)
    no_ids.post(body, good)
    check("the same event twice, ids not recorded", "2 applied",
          "%d applied" % len(no_ids.applied))
    recording = Receiver(secret)
    recording.post(body, good)
    check("the same event twice, ids recorded", "202 accepted",
          recording.post(body, good))
    check("  and applied only once", "1 applied",
          "%d applied" % len(recording.applied))

    # 4. When it is recorded. Two copies of one event, interleaved explicitly:
    #    both arrive and verify before either finishes processing.
    late = Receiver(secret, record_before=False)
    late.reserve(body, good)
    late.reserve(body, good)
    late.apply(body)
    late.apply(body)
    check("id recorded after processing, two copies interleaved", "2 applied",
          "%d applied" % len(late.applied))
    early = Receiver(secret, record_before=True)
    early.reserve(body, good)
    second = early.reserve(body, good)
    early.apply(body)
    check("  the same interleaving, id claimed first", "202 accepted",
          second if second is not None else early.apply(body))
    check("  events applied", "1 applied", "%d applied" % len(early.applied))

    print()
    print("Part D: what the signature does not settle.")

    # At-least-once delivery means a duplicate is usually the sender retrying.
    honest = Receiver(secret)
    first_response = honest.post(body, good)
    retry_response = honest.post(body, good)
    check("a legitimate retry from the sender", "202 accepted", retry_response)
    check("  the response differs from the first", "False",
          str(first_response != retry_response))
    check("  and it was applied once", "1 applied",
          "%d applied" % len(honest.applied))
    # Order is not guaranteed, and the signature says nothing about it.
    ordered = Receiver(secret)
    later = body_of("evt-1002", "payment.refunded", 42000)
    ordered.post(later, sign(secret, later, NOW))
    ordered.post(body, good)
    check("a refund applied before the payment it refunds",
          "['payment.refunded', 'payment.settled']",
          str([e["type"] for e in ordered.applied]))
    # And the response is information.
    prober = Receiver(secret)
    prober.post(body, good)
    check("a prober posts a known id with no signature", "400 no signature",
          prober.post(body))

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
