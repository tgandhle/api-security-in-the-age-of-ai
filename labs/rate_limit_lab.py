#!/usr/bin/env python3
"""Module 15 lab: rate limiting and cost controls.

Module 11 asked how many times a business flow may run. This module is the
mechanism underneath that, and the four ways a limit that looks correct
bounds something other than what you meant.

Part A is the fixed window and its boundary. Part B is the sliding window.
Part C is the token bucket, where the burst is a decision rather than an
accident. Part D is what a request-rate limit does not bound at all: cost,
duration, the number of identities, and the number of instances counting.

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
