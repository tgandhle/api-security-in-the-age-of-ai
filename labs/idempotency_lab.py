#!/usr/bin/env python3
"""Module 11 lab: business flows and idempotency.

Modules 9 and 10 settled which objects and which properties and functions a
caller may reach. This module is about the request being correct, permitted,
and arriving twice.

Part A is a credit applied twice because the network dropped after the server
committed and the client retried. Part B adds an idempotency key. Part C is
the four details that decide whether the key works: when it is recorded, what
happens on reuse with a different payload, whose key it is, and how long it is
kept. Part D is the different problem underneath, where every request is
distinct, every one is idempotent, and the business still loses.

Concurrency is explicit rather than threaded, so the interleaving is stated in
the code and the output is the same on every run.

Needs nothing beyond Python 3.

Exit codes: 0 all checks matched, 1 a check did not match.
"""
import hashlib
import json
import sys

NOW = 1790000000
KEY_TTL = 86400          # project baseline: keep an idempotency key 24 hours


def fingerprint(payload):
    """What "the same request" means, decided explicitly rather than by luck."""
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()[:12]


class Ledger:
    """ExampleAir's loyalty ledger. Company names are fictional."""

    def __init__(self):
        self.balances = {"acct-77": 4200}
        self.credits = []
        self.keys = {}

    # -------------------------------------------------------------- Part A
    def credit(self, account, miles):
        """No idempotency at all. Every call applies."""
        self.balances[account] += miles
        self.credits.append((account, miles))
        return "200 credited %d" % miles

    # ---------------------------------------------------- Parts B and C
    #
    # Split into two phases so Part C can interleave two requests explicitly.
    # begin() is the lookup and the reservation. commit() does the work.

    def slot(self, account, key, scope_by_caller):
        return (account, key) if scope_by_caller else key

    def begin(self, account, miles, key, now=NOW, scope_by_caller=True,
              record_before=True):
        """Returns a response to send now, or None meaning carry on."""
        payload = {"miles": miles}          # what the client sent, not the caller
        slot = self.slot(account, key, scope_by_caller)
        entry = self.keys.get(slot)

        if entry is not None and now > entry["expires"]:
            # Expired: the record is gone, so this is a new request again.
            del self.keys[slot]
            entry = None

        if entry is not None:
            if entry["fingerprint"] != fingerprint(payload):
                # The key is a promise about one request, not a session token.
                return "422 key reused with a different payload"
            if entry["state"] == "in_flight":
                return "409 a request with this key is still in progress"
            return "200 replayed: %s" % entry["response"]

        if record_before:
            # Reserved before the work, so a concurrent retry sees it.
            self.keys[slot] = {"state": "in_flight", "fingerprint": fingerprint(payload),
                               "response": None, "expires": now + KEY_TTL}
        return None

    def commit(self, account, miles, key, now=NOW, scope_by_caller=True):
        self.balances[account] += miles
        self.credits.append((account, miles))
        response = "credited %d" % miles
        self.keys[self.slot(account, key, scope_by_caller)] = {
            "state": "done", "fingerprint": fingerprint({"miles": miles}),
            "response": response, "expires": now + KEY_TTL}
        return "200 %s" % response

    def credit_idempotent(self, account, miles, key, now=NOW,
                          scope_by_caller=True, record_before=True):
        """The ordinary path: one request, start to finish."""
        early = self.begin(account, miles, key, now, scope_by_caller, record_before)
        if early is not None:
            return early
        return self.commit(account, miles, key, now, scope_by_caller)


RESULTS = []


def check(label, expected, actual):
    RESULTS.append((label, expected, actual))
    print("%2d. %-52s %s" % (len(RESULTS), label, actual))


def main():
    print("account acct-77 opens with 4200 miles in every part below")
    print()
    print("Part A: a retry with no idempotency key.")

    ledger = Ledger()
    check("the first request, response lost in transit", "200 credited 10000",
          ledger.credit("acct-77", 10000))
    check("the client retries the same request", "200 credited 10000",
          ledger.credit("acct-77", 10000))
    check("credits applied", "2", str(len(ledger.credits)))
    check("balance", "24200", str(ledger.balances["acct-77"]))

    print()
    print("Part B: the same two requests with an idempotency key.")

    ledger = Ledger()
    check("the first request, response lost in transit", "200 credited 10000",
          ledger.credit_idempotent("acct-77", 10000, "key-a"))
    check("the client retries with the same key", "200 replayed: credited 10000",
          ledger.credit_idempotent("acct-77", 10000, "key-a"))
    check("credits applied", "1", str(len(ledger.credits)))
    check("balance", "14200", str(ledger.balances["acct-77"]))

    print()
    print("Part C: the four details that decide whether the key works.")

    # 1. When the key is recorded. Two requests, interleaved explicitly:
    #    A begins, B begins before A commits, then each one told to carry on commits.
    ledger = Ledger()
    a_early = ledger.begin("acct-77", 10000, "key-b")
    b_early = ledger.begin("acct-77", 10000, "key-b")
    check("request A begins, key reserved first", "carry on",
          "carry on" if a_early is None else a_early)
    check("request B begins before A commits",
          "409 a request with this key is still in progress",
          b_early if b_early is not None else ledger.commit("acct-77", 10000, "key-b"))
    ledger.commit("acct-77", 10000, "key-b")
    check("credits applied by both", "1", str(len(ledger.credits)))

    # The same interleaving, with the key recorded only on completion.
    ledger = Ledger()
    a_early = ledger.begin("acct-77", 10000, "key-b", record_before=False)
    b_early = ledger.begin("acct-77", 10000, "key-b", record_before=False)
    check("B begins, key recorded only after the work", "carry on",
          "carry on" if b_early is None else b_early)
    ledger.commit("acct-77", 10000, "key-b")
    ledger.commit("acct-77", 10000, "key-b")
    check("credits applied by both", "2", str(len(ledger.credits)))

    # 2. The same key with a different payload.
    ledger = Ledger()
    ledger.credit_idempotent("acct-77", 10000, "key-c")
    check("the same key, a different amount",
          "422 key reused with a different payload",
          ledger.credit_idempotent("acct-77", 90000, "key-c"))
    check("balance after that attempt", "14200", str(ledger.balances["acct-77"]))

    # 3. Whose key is it.
    ledger = Ledger()
    ledger.balances["acct-91"] = 500
    ledger.credit_idempotent("acct-77", 10000, "key-d", scope_by_caller=False)
    check("another caller sends the same key, keys scoped globally",
          "200 replayed: credited 10000",
          ledger.credit_idempotent("acct-91", 10000, "key-d", scope_by_caller=False))
    check("acct-91's balance after that", "500", str(ledger.balances["acct-91"]))
    check("the same request, keys scoped per caller", "200 credited 10000",
          ledger.credit_idempotent("acct-91", 10000, "key-d"))
    check("acct-91's balance after that", "10500", str(ledger.balances["acct-91"]))
    globals_only = Ledger()
    globals_only.balances["acct-91"] = 500
    globals_only.credit_idempotent("acct-77", 10000, "key-d", scope_by_caller=False)
    globals_only.credit_idempotent("acct-91", 10000, "key-d", scope_by_caller=False)
    check("acct-91's credits under global scoping alone", "0",
          str(len([c for c in globals_only.credits if c[0] == "acct-91"])))

    # 4. How long the key is kept.
    ledger = Ledger()
    ledger.credit_idempotent("acct-77", 10000, "key-e")
    check("the same key one hour later", "200 replayed: credited 10000",
          ledger.credit_idempotent("acct-77", 10000, "key-e", now=NOW + 3600))
    check("the same key after the retention window",
          "200 credited 10000",
          ledger.credit_idempotent("acct-77", 10000, "key-e", now=NOW + KEY_TTL + 1))
    check("credits applied in total", "2", str(len(ledger.credits)))

    print()
    print("Part D: the problem idempotency does not address.")

    ledger = Ledger()
    for n in range(500):
        ledger.credit_idempotent("acct-77", 10000, "key-%04d" % n)
    check("500 distinct requests, each one idempotent", "500 credits",
          "%d credits" % len(ledger.credits))
    check("balance", "5004200", str(ledger.balances["acct-77"]))
    # Credits applied, less the keys that hold a credit. Anything left over
    # is a key whose operation ran more than once.
    credited_keys = [e for e in ledger.keys.values()
                     if str(e["response"]).startswith("credited")]
    check("how many of those were duplicate executions", "0",
          str(len(ledger.credits) - len(credited_keys)))

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
