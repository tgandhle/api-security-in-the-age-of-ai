#!/usr/bin/env python3
"""Module 26 lab: design review.

The other twenty-six labs each demonstrated one thing going wrong. This one
is the job: take a described system, run the course's checklist against it,
and produce something a team can act on.

The useful part is not the findings. It is Part C. A design document answers
some of the questions a reviewer asks and is silent on the rest, and the
silence is where reviews go wrong, because an unanswered question looks
exactly like a passed one in a summary. This harness keeps them apart and
counts them separately.

Part A is the design as a set of answered and unanswered facts. Part B is
the findings, ordered. Part C is what the design does not say. Part D
applies the remediation a team would realistically do first and measures
what is left. Part E is the review's own coverage, which is the paragraph
that belongs at the top of the report.

The rule table below is the lab. Point it at a dict describing your own
system and it will do the same thing.

Needs nothing beyond Python 3.

Exit codes: 0 all checks matched, 1 a check did not match.
"""
import sys

UNKNOWN = None

# The system under review. Each key is a question a reviewer asks; the value
# is what the design document says. UNKNOWN means the document is silent.
DESIGN = {
    "name": "ExampleAir assistant platform",
    # Part 1, proving who is calling
    "key_storage": "hashed",
    "token_audience_checked": False,
    "credential_inventory": UNKNOWN,
    # Part 2, deciding what they may do
    "object_check": "after-load",
    "response_fields": "declared-list",
    "idempotency": "none",
    # Part 3, edges and boundaries
    "services_authenticate_themselves": UNKNOWN,
    "limits_before_parser": UNKNOWN,
    "egress_allowlist": False,
    "rate_limit_store": "per-instance",
    "webhook_verification": "signature+timestamp",
    "versions_reachable": 3,
    "versions_documented": 2,
    # Part 4, AI and agents
    "agent_calls_downstream": "passthrough",
    "mcp_audience_validation": False,
    "a2a_card_trust": "fetched-key",
    "tool_dispatch": "deny-by-default",
    "model_holds_credential": True,
    "approval_binds": "proposal-id",
    "system_prompt_has_credential": True,
    "prompt_context": "whole-record",
    "retrieval_filter": "post",
    "memory_provenance": False,
    "retrieval_logging": UNKNOWN,
}

# check id, severity, module, the fact it depends on, test, finding.
# Every id, severity and module number below matches the module page that
# defines it. Module numbers are the site's: the primer is 0, this lab is 26.
RULES = [
    ("api-keys-04", "High", 1, "key_storage",
     lambda d: d["key_storage"] != "hashed",
     "API keys are not stored in a form that survives disclosure"),
    ("jwt-02", "Critical", 5, "token_audience_checked",
     lambda d: not d["token_audience_checked"],
     "The audience is not validated against this service's own identifier"),
    ("life-01", "Critical", 8, "credential_inventory",
     lambda d: not d["credential_inventory"],
     "The credential register has not been reconciled against the systems"),
    ("bola-01", "Critical", 9, "object_check",
     lambda d: d["object_check"] != "after-load",
     "Handlers do not compare the caller with the owner on the loaded object"),
    ("prop-04", "High", 10, "response_fields",
     lambda d: d["response_fields"] != "declared-list",
     "Responses are not built from a declared field list"),
    ("flow-01", "Critical", 11, "idempotency",
     lambda d: d["idempotency"] == "none",
     "Non-idempotent operations accept no idempotency key"),
    ("gw-01", "Critical", 12, "services_authenticate_themselves",
     lambda d: not d["services_authenticate_themselves"],
     "Services do not authenticate for themselves on every path"),
    ("ctr-02", "Critical", 13, "limits_before_parser",
     lambda d: not d["limits_before_parser"],
     "Request limits do not run before the parser"),
    ("out-06", "High", 14, "egress_allowlist",
     lambda d: not d["egress_allowlist"],
     "Outbound schemes and hosts are not allowlisted by exact match"),
    ("rate-01", "Critical", 15, "rate_limit_store",
     lambda d: d["rate_limit_store"] != "shared",
     "Rate limit counters are not held in a store every instance shares"),
    ("hook-01", "Critical", 16, "webhook_verification",
     lambda d: "timestamp" not in str(d["webhook_verification"]),
     "The webhook signature does not cover the timestamp"),
    ("ver-01", "Critical", 18, "versions_reachable",
     lambda d: d["versions_reachable"] > d["versions_documented"],
     "More versions answer than the documentation lists, so the list did not "
     "come from the network"),
    ("dlg-01", "Critical", 19, "agent_calls_downstream",
     lambda d: d["agent_calls_downstream"] == "passthrough",
     "A service forwards a user's token outside the audience it was issued for"),
    ("mcp-01", "Critical", 20, "mcp_audience_validation",
     lambda d: not d["mcp_audience_validation"],
     "The MCP server does not validate that each token's audience is itself"),
    ("a2a-01", "Critical", 21, "a2a_card_trust",
     lambda d: d["a2a_card_trust"] != "pinned-key",
     "Agent cards are not verified against an out-of-band key per counterparty"),
    ("inj-01", "Critical", 22, "tool_dispatch",
     lambda d: d["tool_dispatch"] != "deny-by-default",
     "Tools are not dispatched from a deny-by-default table"),
    ("inj-02", "Critical", 22, "model_holds_credential",
     lambda d: d["model_holds_credential"],
     "Tool credentials are held by the model, not the application"),
    ("apv-01", "Critical", 23, "approval_binds",
     lambda d: d["approval_binds"] != "parameters",
     "Approvals bind a proposal identifier rather than the parameters"),
    ("ctx-01", "Critical", 24, "system_prompt_has_credential",
     lambda d: d["system_prompt_has_credential"],
     "A credential appears in a system prompt"),
    ("ctx-02", "Critical", 24, "prompt_context",
     lambda d: d["prompt_context"] != "allowlist",
     "Prompt context is not built from a per-task field allowlist"),
    ("ret-01", "Critical", 25, "retrieval_filter",
     lambda d: d["retrieval_filter"] != "pre",
     "The permission filter is applied to the result, not the corpus"),
    ("ret-05", "High", 25, "memory_provenance",
     lambda d: not d["memory_provenance"],
     "Memory writes do not record their source document and origin"),
    ("ret-08", "Medium", 25, "retrieval_logging",
     lambda d: not d["retrieval_logging"],
     "Retrieval activity is not logged with a stated retention"),
]

RANK = {"Critical": 0, "High": 1, "Medium": 2}


def review(design):
    """Return findings, and separately the questions the design never answers."""
    findings, unanswered = [], []
    for check_id, severity, module, fact, test, text in RULES:
        if design.get(fact, UNKNOWN) is UNKNOWN:
            unanswered.append((check_id, severity, module, fact, text))
            continue
        if test(design):
            findings.append((check_id, severity, module, text))
    findings.sort(key=lambda f: (RANK[f[1]], f[0]))
    unanswered.sort(key=lambda u: (RANK[u[1]], u[0]))
    return findings, unanswered


def by_severity(findings):
    out = {}
    for _, severity, _, _ in findings:
        out[severity] = out.get(severity, 0) + 1
    return out


def coverage(design):
    """Which modules this review reached a conclusion about, and which not."""
    assessed, blocked = set(), set()
    for check_id, severity, module, fact, test, text in RULES:
        if design.get(fact, UNKNOWN) is UNKNOWN:
            blocked.add(module)
        else:
            assessed.add(module)
    return sorted(assessed), sorted(blocked - assessed)


RESULTS = []


def check(label, expected, actual):
    RESULTS.append((label, expected, actual))
    print("%2d. %-56s %s" % (len(RESULTS), label, actual))


def main():
    print("system under review: %s" % DESIGN["name"])
    print("rules in the checklist harness: %d" % len(RULES))
    print()

    findings, unanswered = review(DESIGN)

    print("Part A: what the design document says, and does not.")
    facts = [k for k in DESIGN if k != "name"]
    check("facts the harness asks about", "24", str(len(facts)))
    check("  answered in the design", "20",
          str(len([k for k in facts if DESIGN[k] is not UNKNOWN])))
    check("  left unanswered", "4",
          str(len([k for k in facts if DESIGN[k] is UNKNOWN])))
    check("rules that could be evaluated", "19", str(len(RULES)
                                                    - len(unanswered)))
    check("rules blocked on a missing answer", "4", str(len(unanswered)))

    print()
    print("Part B: findings, worst first.")
    check("findings raised", "14", str(len(findings)))
    counts = by_severity(findings)
    check("  critical", "12", str(counts.get("Critical", 0)))
    check("  high", "2", str(counts.get("High", 0)))
    check("  medium", "0", str(counts.get("Medium", 0)))
    check("the first finding", "a2a-01",
          findings[0][0] if findings else "none raised")
    order = [RANK[f[1]] for f in findings]
    check("  findings are ordered worst first", "yes",
          "yes" if order == sorted(order) else "no")
    check("  the last finding's severity", "High",
          findings[-1][1] if findings else "none raised")
    check("  what the first finding says",
          "Agent cards are not verified against an out-of-band key per "
          "counterparty", findings[0][3] if findings else "none raised")
    criticals = [f[0] for f in findings if f[1] == "Critical"]
    check("critical check ids, in order",
          "['a2a-01', 'apv-01', 'ctx-01', 'ctx-02', 'dlg-01', 'flow-01', "
          "'inj-02', 'jwt-02', 'mcp-01', 'rate-01', 'ret-01', 'ver-01']",
          str(criticals))
    check("  of which come from Part 4", "8",
          str(len([f for f in findings
                   if f[1] == "Critical" and f[2] >= 19])))
    check("  and from Parts 1 to 3", "4",
          str(len([f for f in findings
                   if f[1] == "Critical" and f[2] < 19])))

    print()
    print("Part C: the questions the design does not answer.")
    check("unanswered questions", "4", str(len(unanswered)))
    check("  their check ids", "['ctr-02', 'gw-01', 'life-01', 'ret-08']",
          str([u[0] for u in unanswered]))
    check("  the facts they needed",
          "['limits_before_parser', 'services_authenticate_themselves', "
          "'credential_inventory', 'retrieval_logging']",
          str([u[3] for u in unanswered]))
    check("  severity of the worst one", "Critical",
          unanswered[0][1] if unanswered else "none recorded")
    check("if they were counted as passes, findings would read", "14",
          str(len(findings)))
    check("  and the review would be silent about", "4", str(len(unanswered)))
    check("the honest total of open items", "18",
          str(len(findings) + len(unanswered)))

    print()
    print("Part D: the remediation a team does first, and what is left.")
    # Six changes, each one a configuration or a small code change.
    fixed = dict(DESIGN,
                 token_audience_checked=True,
                 mcp_audience_validation=True,
                 system_prompt_has_credential=False,
                 model_holds_credential=False,
                 prompt_context="allowlist",
                 retrieval_filter="pre")
    after, still_unanswered = review(fixed)
    check("findings after six changes", "8", str(len(after)))
    check("  critical remaining", "6",
          str(by_severity(after).get("Critical", 0)))
    check("  removed by those changes", "6",
          str(len(findings) - len(after)))
    check("critical ids remaining",
          "['a2a-01', 'apv-01', 'dlg-01', 'flow-01', 'rate-01', 'ver-01']",
          str([f[0] for f in after if f[1] == "Critical"]))
    check("  unanswered questions, unchanged", "4", str(len(still_unanswered)))
    # Every change above was a setting or a few lines. Each remaining
    # critical needs a design decision: key distribution for agent cards,
    # what an approval binds, a token exchange, an idempotency key, a shared
    # rate limit store, and a version retirement. That is the difference
    # worth reporting.
    before_crit = len([f for f in findings if f[1] == "Critical"])
    after_crit = len([f for f in after if f[1] == "Critical"])
    check("criticals the six changes removed", "6",
          str(before_crit - after_crit))
    check("  criticals left, each needing a design change", "6",
          str(after_crit))
    check("  is ret-01 among them", "no",
          "yes" if "ret-01" in [f[0] for f in after] else "no")

    print()
    print("Part E: what this review did and did not cover.")
    assessed, blocked = coverage(DESIGN)
    check("modules the review reached a conclusion about", "16",
          str(len(assessed)))
    check("modules blocked on a missing answer", "3", str(len(blocked)))
    check("  which ones", "[8, 12, 13]", str(blocked))
    modules_with_findings = sorted({f[2] for f in findings})
    check("modules with at least one finding", "12",
          str(len(modules_with_findings)))
    clean = sorted(set(assessed) - set(modules_with_findings))
    check("modules assessed and clean", "[1, 9, 10, 16]", str(clean))
    check("  so the report's first line is", "18 open items, 4 unanswerable",
          "%d open items, %d unanswerable"
          % (len(findings) + len(unanswered), len(unanswered)))

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
