#!/usr/bin/env python3
"""Module 12 lab: which paths actually reach the service.

Parts 1 and 2 put checks in handlers. This module asks a question about the
network those handlers sit on: is the gateway a control, or a habit. A gateway
enforces something only if every path to the service crosses it, and the
number of paths is almost never the number on the diagram.

Part A runs the rules over the architecture as documented, where everything
goes through the gateway and nothing is wrong. Part B reconciles that document
against the connections actually observed. Part C runs the same rules over the
real path set. Part D applies the remediation and reruns. Part E is what a
gateway was never going to fix.

Needs nothing beyond Python 3.

Exit codes: 0 all checks matched, 1 a check did not match.
"""
import sys

# ExampleAir's services. Company names are fictional. "own_authn" means the
# service authenticates the caller itself rather than believing the gateway
# already did.
SERVICES = {
    "svc-booking": dict(env="production", version="v2", own_authn=False,
                        own_authz=True, trusts_caller_header=False,
                        production_data=True, current=True, retirement=None),
    "svc-loyalty": dict(env="production", version="v3", own_authn=True,
                        own_authz=True, trusts_caller_header=False,
                        production_data=True, current=True, retirement=None),
    "svc-reporting": dict(env="production", version="v1", own_authn=False,
                          own_authz=False, trusts_caller_header=True,
                          production_data=True, current=True, retirement=None),
    "svc-booking-v1": dict(env="production", version="v1", own_authn=False,
                           own_authz=True, trusts_caller_header=False,
                           production_data=True, current=False, retirement=None),
    "svc-booking-staging": dict(env="staging", version="v2", own_authn=False,
                                own_authz=True, trusts_caller_header=False,
                                production_data=True, current=True, retirement=None),
}

# A path is one way traffic reaches a service. "can_set_headers" means whatever
# sits at the source can put any header it likes on the request.
def path(source, service, via_gateway, can_set_headers, reachable_from):
    return dict(source=source, service=service, via_gateway=via_gateway,
                can_set_headers=can_set_headers, reachable_from=reachable_from)


DOCUMENTED = [
    path("internet", "svc-booking", True, True, "public"),
    path("internet", "svc-loyalty", True, True, "public"),
    path("internet", "svc-reporting", True, True, "public"),
]

# What the connection logs show, which is the only source that knows.
OBSERVED = DOCUMENTED + [
    path("svc-loyalty", "svc-booking", False, True, "internal"),
    path("batch-nightly", "svc-reporting", False, True, "internal"),
    path("partner-vpn", "svc-booking-v1", False, True, "partner"),
    path("internet", "svc-booking-staging", False, True, "public"),
]

RANK = {"Critical": 0, "High": 1, "Medium": 2}


def findings(p, services=None):
    """Each rule is a question about what the gateway was carrying for you."""
    service = (services if services is not None else SERVICES)[p["service"]]
    out = []
    if p["via_gateway"]:
        return out
    if not service["own_authn"]:
        out.append(("Critical", "reachable without authentication"))
    if service["trusts_caller_header"] and p["can_set_headers"]:
        out.append(("Critical", "caller identity is a header this path can set"))
    if service["env"] != "production" and service["production_data"] \
            and p["reachable_from"] == "public":
        out.append(("Critical", "non-production deployment, production data, publicly reachable"))
    if not service["current"] and service["retirement"] is None \
            and p["reachable_from"] != "internal":
        out.append(("High", "older version reachable with no retirement date"))
    if not service["own_authz"]:
        out.append(("High", "no authorization of its own"))
    out.append(("Medium", "gateway-only controls absent: schema, size limits, request logging"))
    return sorted(out, key=lambda f: RANK[f[0]])


def worst(p, services=None):
    found = findings(p, services)
    if not found:
        return "clean"
    return "%s: %s" % found[0]


def label(p):
    return "%s -> %s" % (p["source"], p["service"])


def report(paths, services=None):
    for p in paths:
        found = findings(p, services)
        print("  %-34s %-9s %s" % (label(p),
                                   "gateway" if p["via_gateway"] else "direct",
                                   "clean" if not found else
                                   "%d finding%s" % (len(found), "" if len(found) == 1 else "s")))
        for severity, text in found:
            print("  %-34s   %-8s %s" % ("", severity, text))


RESULTS = []


def check(label_text, expected, actual):
    RESULTS.append((label_text, expected, actual))
    print("%2d. %-50s %s" % (len(RESULTS), label_text, actual))


def main():
    print("the gateway performs authentication, rate limiting, schema validation")
    print("and request logging for every service behind it")
    print()
    print("Part A: the architecture as documented.")
    report(DOCUMENTED)
    print()
    check("paths in the document", "3", str(len(DOCUMENTED)))
    check("findings across all of them", "0",
          str(sum(len(findings(p)) for p in DOCUMENTED)))

    print()
    print("Part B: reconcile the document against observed connections.")
    documented = {(p["source"], p["service"]) for p in DOCUMENTED}
    undocumented = [p for p in OBSERVED if (p["source"], p["service"]) not in documented]
    check("paths actually observed", "7", str(len(OBSERVED)))
    check("paths absent from the document", "4", str(len(undocumented)))
    check("services absent from the document", "2",
          str(len({p["service"] for p in undocumented} - {p["service"] for p in DOCUMENTED})))

    print()
    print("Part C: the same rules over the paths that exist.")
    report(undocumented)
    print()
    for p in undocumented:
        check(label(p), {
            "svc-loyalty -> svc-booking": "Critical: reachable without authentication",
            "batch-nightly -> svc-reporting": "Critical: reachable without authentication",
            "partner-vpn -> svc-booking-v1": "Critical: reachable without authentication",
            "internet -> svc-booking-staging": "Critical: reachable without authentication",
        }[label(p)], worst(p))
    staging = [p for p in undocumented if p["service"] == "svc-booking-staging"][0]
    check("staging's second critical finding",
          "non-production deployment, production data, publicly reachable",
          [text for sev, text in findings(staging) if sev == "Critical"][1])

    print()
    print("Part D: after the remediation.")
    fixed = {k: dict(v) for k, v in SERVICES.items()}
    for name in fixed:
        fixed[name]["own_authn"] = True          # each service authenticates
        fixed[name]["own_authz"] = True          # and authorizes, for itself
    fixed["svc-reporting"]["trusts_caller_header"] = False
    fixed["svc-booking-staging"]["production_data"] = False
    fixed["svc-booking-v1"]["retirement"] = "2026-12-31"

    for p in undocumented:
        check("%s after remediation" % label(p),
              "Medium: gateway-only controls absent: schema, size limits, request logging",
              worst(p, fixed))
    check("critical findings remaining", "0",
          str(sum(1 for p in OBSERVED for sev, _ in findings(p, fixed) if sev == "Critical")))

    print()
    print("Part E: what the remediation does not reach.")
    check("paths still missing the gateway's own controls", "4",
          str(sum(1 for p in OBSERVED if not p["via_gateway"])))
    # A connection made after the reconciliation ran. The Part C review was
    # correct on the day it happened and says nothing about this one.
    later = OBSERVED + [path("ops-console", "svc-loyalty", False, True, "internal")]
    reviewed = {(q["source"], q["service"]) for q in OBSERVED}
    unreviewed = [q for q in later if (q["source"], q["service"]) not in reviewed]
    check("connections made since the reconciliation", "1", str(len(unreviewed)))
    check("Part C checks that covered them", "0",
          str(len([q for q in undocumented
                   if (q["source"], q["service"]) ==
                   ("ops-console", "svc-loyalty")])))
    check("findings they produce once reviewed", "1",
          str(sum(len(findings(q, fixed)) for q in unreviewed)))

    failures = [r for r in RESULTS if r[2] != r[1]]
    print()
    if failures:
        print("%d check(s) did not match the expected outcome:" % len(failures))
        for lbl, expected, actual in failures:
            print("  %s: expected %s, got %s" % (lbl, expected, actual))
        return 1
    print("all lab checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
