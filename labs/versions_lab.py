#!/usr/bin/env python3
"""Module 18 lab: versioning and deprecation.

Every module in Part 3 has assumed there is one version of the service to
secure. There is rarely one. This module is about the ones still answering
after their replacement shipped, and about the two HTTP header fields that
exist to say so.

Part A is what an announcement is made of, and what a version actually emits.
Part B is the ordering constraint RFC 9745 places on the two dates. Part C
computes each version's state at several points on the calendar. Part D
reconciles the documented inventory against what is reachable and what is
receiving traffic. Part E is what a header never does.

Dates are real date arithmetic. Reachability and traffic are inventory data,
so the lab opens no sockets.

Needs nothing beyond Python 3.

Exit codes: 0 all checks matched, 1 a check did not match.
"""
import datetime
import sys

TODAY = datetime.date(2026, 9, 30)


def d(year, month, day):
    return datetime.date(year, month, day)


# ExampleAir's booking API. Company names are fictional. "emits" records the
# headers the deployment actually returns, which is not always what the
# announcement said it would.
VERSIONS = {
    "v3": dict(role="current", deprecated=None, sunset=None, reachable=True,
               requests_30d=4_120_000, callers_known=True,
               emits=[]),
    "v2": dict(role="superseded", deprecated=d(2026, 3, 1), sunset=d(2026, 12, 31),
               reachable=True, requests_30d=180_000, callers_known=True,
               emits=["Deprecation", "Sunset", "Link"]),
    "v1": dict(role="superseded", deprecated=d(2025, 6, 1), sunset=d(2026, 6, 30),
               reachable=True, requests_30d=9_400, callers_known=False,
               emits=[]),
    "v0-beta": dict(role="superseded", deprecated=None, sunset=None,
                    reachable=True, requests_30d=140, callers_known=False,
                    emits=[]),
    "v1-internal": dict(role="retired in the documentation", deprecated=d(2024, 1, 1),
                        sunset=d(2024, 6, 30), reachable=True, requests_30d=2_300,
                        callers_known=False, emits=[]),
}

DOCUMENTED = {"v3", "v2", "v1"}      # what the API documentation lists

RANK = {"Critical": 0, "High": 1, "Medium": 2}


def findings(name, version, today=TODAY):
    out = []
    if version["role"] == "current":
        return out
    if not version["reachable"]:
        return out
    if version["role"].startswith("retired"):
        out.append(("Critical", "retired in the documentation and still answering"))
    if version["sunset"] and today > version["sunset"]:
        out.append(("Critical", "past its sunset date and still answering"))
    if version["deprecated"] is None:
        out.append(("Critical", "no deprecation date has ever been announced"))
    elif "Deprecation" not in version["emits"]:
        out.append(("High", "deprecated, but emits no Deprecation header"))
    if version["deprecated"] and version["sunset"] \
            and version["sunset"] < version["deprecated"]:
        # RFC 9745 section 4: Sunset MUST NOT be earlier than Deprecation.
        out.append(("High", "sunset date is earlier than the deprecation date"))
    if version["sunset"] is None and version["deprecated"] is not None:
        out.append(("Medium", "deprecated with no sunset date"))
    if version["requests_30d"] > 0 and not version["callers_known"]:
        out.append(("High", "still receiving traffic from callers nobody can name"))
    return sorted(out, key=lambda f: RANK[f[0]])


def worst(name, version, today=TODAY):
    found = findings(name, version, today)
    return "clean" if not found else "%s: %s" % found[0]


def state(version, today):
    """What RFC 9745 and RFC 8594 let a client work out from the two dates."""
    if version["deprecated"] is None:
        return "no signal"
    if today < version["deprecated"]:
        return "announced, not yet deprecated"
    if version["sunset"] is None:
        return "deprecated, no end date"
    if today == version["sunset"]:
        return "sunsets today"
    if today < version["sunset"]:
        left = (version["sunset"] - today).days
        return "deprecated, %d day%s left" % (left, "" if left == 1 else "s")
    over = (today - version["sunset"]).days
    return "past sunset by %d day%s" % (over, "" if over == 1 else "s")


RESULTS = []


def check(label, expected, actual):
    RESULTS.append((label, expected, actual))
    print("%2d. %-50s %s" % (len(RESULTS), label, actual))


def main():
    print("today is %s; five deployments answer on the booking API" % TODAY)
    print()
    print("Part A: what each version announces, and what it emits.")

    for name in ("v3", "v2", "v1", "v1-internal"):
        v = VERSIONS[name]
        print("  %-12s %-26s deprecated %-12s sunset %-12s emits %s"
              % (name, v["role"],
                 v["deprecated"] or "never", v["sunset"] or "never",
                 ",".join(v["emits"]) or "nothing"))
    print()
    check("v2, deprecated and saying so", "clean", worst("v2", VERSIONS["v2"]))
    check("v1, its worst finding", "Critical: past its sunset date and still answering",
          worst("v1", VERSIONS["v1"]))
    check("v1, its header finding as well",
          "deprecated, but emits no Deprecation header",
          [text for _, text in findings("v1", VERSIONS["v1"])
           if "Deprecation header" in text][0])

    print()
    print("Part B: the ordering constraint on the two dates.")

    # Both dates in the future, so the ordering problem is the only finding.
    backwards = dict(VERSIONS["v2"], deprecated=d(2027, 3, 1), sunset=d(2027, 1, 1))
    check("a sunset date before the deprecation date",
          "High: sunset date is earlier than the deprecation date",
          worst("v2", backwards))
    check("the same version with the dates in order", "clean",
          worst("v2", VERSIONS["v2"]))

    print()
    print("Part C: what a client can work out from the dates alone.")

    for label, when in [("before the announcement", d(2026, 1, 1)),
                        ("the day it was deprecated", d(2026, 3, 1)),
                        ("today", TODAY),
                        ("the day it sunsets", d(2026, 12, 31)),
                        ("a month later", d(2027, 1, 31))]:
        check("v2 %s" % label, {
            "before the announcement": "announced, not yet deprecated",
            "the day it was deprecated": "deprecated, 305 days left",
            "today": "deprecated, 92 days left",
            "the day it sunsets": "sunsets today",
            "a month later": "past sunset by 31 days",
        }[label], state(VERSIONS["v2"], when))
    check("v0-beta, which announced nothing", "no signal",
          state(VERSIONS["v0-beta"], TODAY))

    print()
    print("Part D: the documentation against what is reachable.")

    reachable = {n for n, v in VERSIONS.items() if v["reachable"]}
    check("versions in the documentation", "3", str(len(DOCUMENTED)))
    check("versions actually answering", "5", str(len(reachable)))
    check("answering but undocumented", "['v0-beta', 'v1-internal']",
          str(sorted(reachable - DOCUMENTED)))
    undocumented_traffic = sum(VERSIONS[n]["requests_30d"]
                               for n in reachable - DOCUMENTED)
    check("requests to them in 30 days", "2440", str(undocumented_traffic))
    for name in sorted(reachable - DOCUMENTED):
        check("  %s" % name, {
            "v0-beta": "Critical: no deprecation date has ever been announced",
            "v1-internal": "Critical: retired in the documentation and still answering",
        }[name], worst(name, VERSIONS[name]))
    check("v1, past its sunset date", "Critical: past its sunset date and still answering",
          worst("v1", VERSIONS["v1"]))

    print()
    print("Part E: what the headers do not do.")

    # Withdrawing a version is the only thing that ends the exposure.
    withdrawn = {n: dict(v) for n, v in VERSIONS.items()}
    for name in ("v1", "v0-beta", "v1-internal"):
        withdrawn[name]["reachable"] = False
    check("findings after withdrawing the three", "0",
          str(sum(len(findings(n, v)) for n, v in withdrawn.items())))
    # Announcing perfectly changes nothing about who is still calling.
    announced = {n: dict(v) for n, v in VERSIONS.items()}
    announced["v1"].update(emits=["Deprecation", "Sunset", "Link"],
                           sunset=d(2027, 6, 30))
    check("v1 with a perfect announcement and a new sunset date",
          "High: still receiving traffic from callers nobody can name",
          worst("v1", announced["v1"]))
    check("  requests it still received in 30 days", "9400",
          str(announced["v1"]["requests_30d"]))

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
