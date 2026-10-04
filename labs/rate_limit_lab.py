#!/usr/bin/env python3
"""Module 15 lab: rate limiting and cost controls.

Module 11 asked how many times a business flow may run. This module is the
mechanism underneath that, and the four ways a limit that looks correct
bounds something other than what you meant.

Part A is the fixed window and its boundary. Part B is the sliding window.
Part C is the token bucket, where the burst is a decision rather than an
accident. Part D is what a request-rate limit does not bound at all: cost,
duration, the number of identities, and the number of instances counting.

Part E is one more case of the first of those. The endpoint is backed by a
language model and billed per model token, so a few very large requests cost
many times what many small ones do. The model is a stub in this file. Nothing
here calls a real model or the network, and the prices are the lab's own.

"Token" means two things in this file. In TokenBucket a token is a unit of
allowance in a rate limiter. A model token is the unit a language model reads
and writes text in, and the unit its bill is counted in. Part E says "model
token" every time.

The clock is a number this file increments, so every run produces the same
output and nothing sleeps.

Needs nothing beyond Python 3.

Exit codes: 0 all checks matched, 1 a check did not match.
"""
import sys
from collections import deque

LIMIT = 100          # requests
WINDOW = 60          # seconds

RESULTS = []


def check(label, expected, actual):
    RESULTS.append((label, expected, actual))
    print("%2d. %-50s %s" % (len(RESULTS), label, actual))


class FixedWindow:
    """Count per calendar window. The cheapest limiter, and the leakiest."""

    def __init__(self, limit=LIMIT, window=WINDOW):
        self.limit, self.window, self.counts = limit, window, {}

    def allow(self, now, cost=1):
        bucket = now // self.window
        used = self.counts.get(bucket, 0)
        if used + cost > self.limit:
            return False
        self.counts[bucket] = used + cost
        return True


class SlidingWindow:
    """Count the last `window` seconds, whenever the request arrives."""

    def __init__(self, limit=LIMIT, window=WINDOW):
        self.limit, self.window, self.seen = limit, window, deque()

    def allow(self, now, cost=1):
        while self.seen and self.seen[0] <= now - self.window:
            self.seen.popleft()
        if len(self.seen) + cost > self.limit:
            return False
        for _ in range(cost):
            self.seen.append(now)
        return True


class TokenBucket:
    """Capacity is the burst you are willing to serve. Rate is the average."""

    def __init__(self, capacity=LIMIT, per_second=LIMIT / WINDOW):
        self.capacity, self.per_second = capacity, per_second
        self.tokens, self.updated = float(capacity), 0

    def allow(self, now, cost=1):
        self.tokens = min(self.capacity,
                          self.tokens + (now - self.updated) * self.per_second)
        self.updated = now
        if self.tokens < cost:
            return False
        self.tokens -= cost
        return True


def send(limiter, times, cost=1):
    """Return how many of these requests were allowed."""
    return sum(1 for t in times for _ in [0] if limiter.allow(t, cost))


# Part E. This lab's own price table, in cost units per model token.
PRICE = {"input": 1, "output": 5}


def cost_of(tokens_in, tokens_out):
    """Cost of one model call, in units, from the price table."""
    return tokens_in * PRICE["input"] + tokens_out * PRICE["output"]


class StubModel:
    """Stands in for a language model, and records every call it receives.

    It always writes the whole output it was allowed. That is the worst case,
    and it is what an estimate made before the call has to assume.
    """

    def __init__(self):
        self.calls = 0

    def generate(self, tokens_in, max_out):
        self.calls += 1
        return max_out          # model tokens written


class ModelEndpoint:
    """An API endpoint that passes each request to the stub model.

    Every request is counted against the stated limit of 100 requests per 60
    seconds. Every other control is off unless it is given a number. All
    state is per caller, and every decision is made before the model is
    called. tokens_in and max_out are counts of model tokens: what the
    caller sends, and the most it lets the model write.
    """

    def __init__(self, max_input=None, max_output=None, max_cost=None,
                 per_minute=None, per_day=None, ceiling=None, halt=True):
        self.model = StubModel()
        self.max_input, self.max_output = max_input, max_output
        self.max_cost = max_cost
        self.per_minute, self.per_day = per_minute, per_day
        self.ceiling, self.halt = ceiling, halt
        self.requests, self.minute, self.day = {}, {}, {}
        self.spend, self.alerts = {}, 0

    @staticmethod
    def limiter(table, caller, limit, window):
        if caller not in table:
            table[caller] = SlidingWindow(limit, window)
        return table[caller]

    def call(self, caller, now, tokens_in, max_out):
        """Return "ok" after calling the model, or the reason for refusing."""
        if not self.limiter(self.requests, caller, LIMIT, WINDOW).allow(now):
            return "refused: request rate"
        if self.max_input is not None and tokens_in > self.max_input:
            return "refused: input cap"
        if self.max_output is not None and max_out > self.max_output:
            return "refused: output cap"
        estimate = cost_of(tokens_in, max_out)
        if self.max_cost is not None and estimate > self.max_cost:
            return "refused: cost per request"
        spent = self.spend.get(caller, 0)
        if self.ceiling is not None and spent + estimate > self.ceiling:
            self.alerts += 1
            if self.halt:
                return "refused: budget ceiling"
        # The minute is tested before the day. A request the day refuses has
        # then used some of the minute, which errs towards refusing.
        size = tokens_in + max_out          # model tokens, in and out
        if self.per_minute is not None and not self.limiter(
                self.minute, caller, self.per_minute, 60).allow(now, size):
            return "refused: model tokens per minute"
        if self.per_day is not None and not self.limiter(
                self.day, caller, self.per_day, 86400).allow(now, size):
            return "refused: model tokens per day"
        written = self.model.generate(tokens_in, max_out)
        self.spend[caller] = spent + cost_of(tokens_in, written)
        return "ok"


def drive(endpoint, caller, times, tokens_in, max_out):
    """Send one request at each time. Return the results in order.

    Each result is compared with the stub model's own count of calls. "ok"
    stands only if that request made exactly one model call, and a refusal
    stands only if it made none. Anything else is reported in the result.
    """
    results = []
    for t in times:
        before = endpoint.model.calls
        result = endpoint.call(caller, t, tokens_in, max_out)
        made = endpoint.model.calls - before
        if made != (1 if result == "ok" else 0):
            result = "%s, with %d model call(s)" % (result, made)
        results.append(result)
    return results


def bill(endpoint, caller, results):
    """Requests served, and what the caller has spent so far.

    If drive() marked any result, the number of marked results is added.
    """
    text = "%d calls, %d units" % (results.count("ok"),
                                   endpoint.spend.get(caller, 0))
    marked = sum(1 for r in results if "model call(s)" in r)
    return text + (", %d marked" % marked if marked else "")


def main():
    print("the stated limit is %d requests per %d seconds" % (LIMIT, WINDOW))
    print()
    print("Part A: a fixed window, counted per calendar minute.")

    fixed = FixedWindow()
    before = send(fixed, [59] * 100)
    after = send(fixed, [60] * 100)
    check("100 requests at t=59", "100 allowed", "%d allowed" % before)
    check("100 more at t=60", "100 allowed", "%d allowed" % after)
    check("allowed in those two seconds", "200", str(before + after))
    check("the same traffic expressed as a rate", "6000 per minute",
          "%d per minute" % ((before + after) * 60 // 2))
    check("the 101st request inside one window", "refused",
          "refused" if send(FixedWindow(), [0] * 101) == 100 else "allowed")

    print()
    print("Part B: a sliding window over the last 60 seconds.")

    sliding = SlidingWindow()
    first = send(sliding, [59] * 100)
    second = send(sliding, [60] * 100)
    check("100 requests at t=59", "100 allowed", "%d allowed" % first)
    check("100 more at t=60", "0 allowed", "%d allowed" % second)
    check("allowed in those two seconds", "100", str(first + second))
    check("a request at t=119, once the first batch ages out", "allowed",
          "allowed" if sliding.allow(119) else "refused")

    print()
    print("Part C: a token bucket, capacity 100, refilling 100 per minute.")

    bucket = TokenBucket()
    check("100 requests at t=0, from a full bucket", "100 allowed",
          "%d allowed" % send(bucket, [0] * 100))
    check("one more at t=0", "refused", "refused" if not bucket.allow(0) else "allowed")
    check("one at t=1, after 1.67 tokens refill", "allowed",
          "allowed" if bucket.allow(1) else "refused")
    steady = TokenBucket()
    check("a caller sending 1 per second for 600 seconds", "600 allowed",
          "%d allowed" % send(steady, list(range(600))))
    drained = TokenBucket()
    send(drained, [0] * 100)
    wait = next(t for t in range(1, 120) if drained.allow(t))
    check("seconds to wait after draining it", "1", str(wait))

    print()
    print("Part D: what a request-rate limit does not bound.")

    # 1. Requests are not equal.
    cheap = SlidingWindow()
    expensive = SlidingWindow()
    check("100 cheap requests, 1 unit each", "100 units",
          "%d units" % (send(cheap, list(range(100))) * 1))
    check("100 expensive requests, 50 units each", "5000 units",
          "%d units" % (send(expensive, list(range(100))) * 50))
    weighted = SlidingWindow(limit=100)
    check("the same expensive traffic, cost-weighted at 50", "4 allowed",
          "%d allowed" % send(weighted, list(range(100)), cost=50))

    # 2. A rate limit says nothing about duration.
    slow = SlidingWindow()
    day = send(slow, list(range(86400)))
    check("1 request per second for a day", "86400 allowed", "%d allowed" % day)
    check("any of them refused", "0", str(86400 - day))

    # 3. Per caller means per caller.
    per_caller = [SlidingWindow() for _ in range(50)]
    total = sum(send(lim, [0] * 100) for lim in per_caller)
    check("50 identities, each inside its own limit", "5000 allowed",
          "%d allowed" % total)

    # 4. And the counter has to be shared.
    instances = [SlidingWindow() for _ in range(4)]
    spread = sum(send(inst, [0] * 100) for inst in instances)
    check("one caller across 4 instances with local counters", "400 allowed",
          "%d allowed" % spread)
    shared = SlidingWindow()
    check("the same traffic against one shared counter", "100 allowed",
          "%d allowed" % sum(send(shared, [0] * 100) for _ in range(4)))

    print()
    print("Part E: an endpoint backed by a model, billed per model token.")
    print("    prices: %d unit per input model token, %d per output model token"
          % (PRICE["input"], PRICE["output"]))

    # 1. The attack. Only the request-rate limit is on.
    normal_times = list(range(0, 60, 3))
    heavy_times = list(range(5))
    bare = ModelEndpoint()
    normal = drive(bare, "normal", normal_times, 500, 100)
    heavy = drive(bare, "heavy", heavy_times, 100000, 20000)
    check("normal caller, 20 requests of 500 in, 100 out",
          "20 calls, 20000 units", bill(bare, "normal", normal))
    check("heavy caller, 5 requests of 100000 in, 20000 out",
          "5 calls, 1000000 units", bill(bare, "heavy", heavy))
    check("requests the 100 a minute limit refused", "0",
          str(len(normal + heavy) - (normal + heavy).count("ok")))
    check("the heavy caller's cost against the normal one's", "50 times",
          "%d times" % (bare.spend["heavy"] // bare.spend["normal"]))

    # 2. Caps on size, tested before the model is called.
    capped = ModelEndpoint(max_input=4000, max_output=1000)
    check("100000 in against an input cap of 4000", "refused: input cap",
          capped.call("heavy", 0, 100000, 100))
    check("20000 max out against an output cap of 1000", "refused: output cap",
          capped.call("heavy", 1, 500, 20000))
    check("model calls made for those two requests", "0",
          str(capped.model.calls))

    # 3. An estimated cost for each request, tested before the call.
    priced = ModelEndpoint(max_cost=6000)
    check("3000 in, 1000 out against a 6000 unit limit",
          "estimate 8000, refused: cost per request",
          "estimate %d, %s" % (cost_of(3000, 1000),
                               priced.call("a", 0, 3000, 1000)))
    check("4000 in, 400 out, which is more model tokens",
          "estimate 6000, ok",
          "estimate %d, %s" % (cost_of(4000, 400),
                               priced.call("a", 1, 4000, 400)))
    check("model calls made for the two priced requests", "1",
          str(priced.model.calls))

    # 4. Model tokens per minute, and per day, for each caller.
    metered = ModelEndpoint(per_minute=20000, per_day=100000)
    burst = drive(metered, "a", [0] * 5, 4000, 1000)
    check("5 requests of 5000 model tokens at t=0", "4 allowed",
          "%d allowed" % burst.count("ok"))
    check("the fifth", "refused: model tokens per minute", burst[4])
    check("one more at t=60, once the minute has aged out", "ok",
          metered.call("a", 60, 4000, 1000))
    minutes = list(range(0, 86400, 60))
    steady = drive(metered, "b", minutes, 4000, 1000)
    check("one 5000 model token request a minute for a day", "20 allowed",
          "%d allowed" % steady.count("ok"))
    first = next((i for i, r in enumerate(steady) if r != "ok"), None)
    check("the first refusal", "t=1200, refused: model tokens per day",
          "none" if first is None
          else "t=%d, %s" % (minutes[first], steady[first]))
    check("the same request at t=86400", "ok",
          metered.call("b", 86400, 4000, 1000))

    # 5. A budget ceiling for each caller: one that halts, one that alerts.
    seconds = list(range(100))
    halting = ModelEndpoint(ceiling=30000)
    halted = drive(halting, "a", seconds, 2000, 400)
    check("ceiling 30000, halting: 100 requests of 4000 units",
          "7 calls, 28000 units", bill(halting, "a", halted))
    check("the eighth request", "refused: budget ceiling", halted[7])
    check("spend went over the ceiling", "no",
          "yes" if halting.spend["a"] > halting.ceiling else "no")
    alerting = ModelEndpoint(ceiling=30000, halt=False)
    check("the same ceiling as an alert only", "100 calls, 400000 units",
          bill(alerting, "a", drive(alerting, "a", seconds, 2000, 400)))
    check("alerts raised while it ran on", "93", str(alerting.alerts))

    # 6. Every control at once.
    guarded = ModelEndpoint(max_input=4000, max_output=1000, max_cost=6000,
                            per_minute=20000, per_day=100000, ceiling=30000)
    check("normal caller under every control above", "20 calls, 20000 units",
          bill(guarded, "normal",
               drive(guarded, "normal", normal_times, 500, 100)))
    check("heavy caller under every control above", "0 calls, 0 units",
          bill(guarded, "heavy",
               drive(guarded, "heavy", heavy_times, 100000, 20000)))

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
