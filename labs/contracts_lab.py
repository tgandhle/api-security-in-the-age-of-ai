#!/usr/bin/env python3
"""Module 13 lab: request and response contracts.

Every check in this course so far ran on a parsed request. This module is
about the step before that: turning bytes into the object those checks
inspect. Two parsers can read the same bytes differently, a parser can accept
values your contract never described, and parsing itself can be the thing that
costs you.

Part A is one body and two answers. Part B is values a JSON parser accepts
that the contract did not anticipate. Part C is shapes that cost you before
any validator runs. Part D is why a schema cannot fix Part C, or Part A.

Every parser result here is real behaviour of Python's own json module,
observed on the machine you run it on, not a simulation. The first-wins parser
and the two limits are the lab's own code. Where behaviour could differ between
Python versions, the checks compare categories rather than messages.

Needs nothing beyond Python 3.

Exit codes: 0 all checks matched, 1 a check did not match.
"""
import json
import sys
import zlib

RESULTS = []


def check(label, expected, actual):
    RESULTS.append((label, expected, actual))
    print("%2d. %-50s %s" % (len(RESULTS), label, actual))


def outcome(fn, *args, **kwargs):
    """Run it and report what kind of thing happened, never the message.

    Messages vary between Python versions; the kind of failure does not.
    """
    try:
        return "ok: %s" % (fn(*args, **kwargs),)
    except RecursionError:
        return "crash: RecursionError"
    except json.JSONDecodeError:
        return "reject: JSONDecodeError"
    except ValueError:
        return "crash: ValueError"


def first_wins(pairs):
    """How some parsers and some languages resolve a repeated name."""
    out = {}
    for key, value in pairs:
        out.setdefault(key, value)
    return out


def depth_of(text):
    """Measure nesting from the bytes, without parsing them."""
    depth = worst = 0
    in_string = escaped = False
    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch in "[{":
            depth += 1
            worst = max(worst, depth)
        elif ch in "]}":
            depth -= 1
    return worst


def accepts_schema(body):
    """A contract of the kind teams actually write: types and required fields."""
    if not isinstance(body, dict):
        return False
    if not {"partnerTxnId", "miles"} <= set(body):
        return False
    return isinstance(body.get("partnerTxnId"), str) and \
        isinstance(body.get("miles"), (int, float)) and \
        not isinstance(body["miles"], bool) and body["miles"] > 0


def main():
    print("every parser result below is Python's json module on this machine")
    print()
    print("Part A: one body, two answers.")

    body = b'{"partnerTxnId": "EXA-42", "miles": 10, "miles": 90000}'
    handler = json.loads(body)
    validator = json.loads(body, object_pairs_hook=first_wins)
    check("the handler's parser reads miles as", "90000", str(handler["miles"]))
    check("a first-wins parser reads miles as", "10", str(validator["miles"]))
    check("the two agree", "False", str(handler == validator))
    check("both parsers accepted the body", "True",
          str(isinstance(handler, dict) and isinstance(validator, dict)))

    print()
    print("Part B: values the contract never described.")

    check("NaN, which is not valid JSON", "ok: nan", outcome(json.loads, "NaN"))
    check("Infinity, which is not valid JSON", "ok: inf",
          outcome(json.loads, "Infinity"))
    check("1e400, a number with no JSON limit", "ok: inf",
          outcome(json.loads, "1e400"))

    def strict_constants(_):
        raise ValueError("constant not allowed")

    check("NaN with parse_constant refusing", "crash: ValueError",
          outcome(json.loads, "NaN", parse_constant=strict_constants))
    huge = '{"partnerTxnId": "EXA-42", "miles": %s}' % ("1" * 10000)
    check("a 10000-digit integer literal", "crash: ValueError",
          outcome(json.loads, huge))
    check("inf passes a schema that wants a positive number", "True",
          str(accepts_schema({"partnerTxnId": "EXA-42", "miles": float("inf")})))

    print()
    print("Part C: shapes that cost you before any check runs.")

    nested = "[" * 100000 + "]" * 100000
    check("100000 levels of nesting, parsed", "crash: RecursionError",
          outcome(json.loads, nested))
    check("its depth, measured without parsing", "100000", str(depth_of(nested)))
    check("a depth limit of 64, applied first", "reject: too deeply nested",
          "reject: too deeply nested" if depth_of(nested) > 64 else outcome(json.loads, nested))

    payload = json.dumps({"partnerTxnId": "EXA-42", "miles": 10,
                          "notes": "A" * 2_000_000}).encode()
    compressed = zlib.compress(payload, 9)
    check("a compressed body under 64 KiB", "True", str(len(compressed) < 65536))
    check("its decoded size over 1 MiB", "True", str(len(payload) > 1_048_576))
    check("expansion ratio over 100 to 1", "True",
          str(len(payload) // len(compressed) > 100))
    decoded = zlib.decompressobj().decompress(compressed, 1_048_576 + 1)
    check("a decoded-size limit of 1 MiB, applied while decoding",
          "reject: body too large",
          "reject: body too large" if len(decoded) > 1_048_576 else "ok")

    print()
    print("Part D: why the schema cannot do Part C's job.")

    check("the nested body reaches the schema at all", "no, it crashed in the parser",
          "no, it crashed in the parser"
          if outcome(json.loads, nested).startswith("crash") else "yes")
    check("the oversized body satisfies the schema", "True",
          str(accepts_schema(json.loads(payload))))
    check("the duplicate-key body satisfies the schema", "True",
          str(accepts_schema(handler)))

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
