#!/usr/bin/env python3
"""Module 23 lab: agent authority and approvals.

An approval is a control only if the thing executed is the thing approved.
That sentence sounds obvious and almost every implementation of it is wrong
in one of a few ways, which this lab reproduces part by part.

Part A is the gap between approving and executing, where the proposal is
read twice and can change in between. Part B is coverage: an approval binds
the fields you chose and nothing else, which is RFC 9421 section 7.2.1's
lesson in a new setting. Part C is the difference between what the approver
read and what the executor used. Part D is single use and expiry. Part E is
the blanket approval, measured rather than argued about.

OWASP LLM06:2025 names the root cause this module is about as excessive
autonomy: systems that lack independent verification and approval for
high-impact actions. The approval in Parts A to D is that verification. The
point of the lab is that having one is not the same as it working.

Approvals are real HMAC over a canonical document. Keys are generated for
this run and never printed. Nothing opens a socket.

Needs nothing beyond Python 3.

Exit codes: 0 all checks matched, 1 a check did not match.
"""
import hashlib
import hmac
import json
import secrets
import sys

NOW = 1790000000
TTL = 300


class Refused(Exception):
    pass


def canonical(doc):
    return json.dumps(doc, separators=(",", ":"), sort_keys=True).encode()


# --------------------------------------------------------------- approvals

def approve(params, key, cover=None, now=NOW, ttl=TTL, nonce=None):
    """Issue an approval over the covered fields.

    cover is the list of parameter names the approval is computed over.
    Anything outside it is not approved, it is merely present.
    """
    cover = sorted(params) if cover is None else sorted(cover)
    covered = {k: params[k] for k in cover if k in params}
    body = {"covered": covered, "cover": cover, "exp": now + ttl,
            "nonce": nonce or secrets.token_hex(8)}
    mac = hmac.new(key, canonical(body), hashlib.sha256).hexdigest()
    out = dict(body)
    out["mac"] = mac
    return out


def check_approval(approval, params, key, now=NOW, spent=None):
    """Verify an approval against the parameters about to execute."""
    body = {k: v for k, v in approval.items() if k != "mac"}
    expected = hmac.new(key, canonical(body), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(approval.get("mac", ""), expected):
        raise Refused("approval does not verify")
    if now >= approval["exp"]:
        raise Refused("approval has expired")
    if spent is not None:
        if approval["nonce"] in spent:
            raise Refused("approval has already been used")
    actual = {k: params[k] for k in approval["cover"] if k in params}
    if actual != approval["covered"]:
        changed = sorted(k for k in approval["cover"]
                         if params.get(k) != approval["covered"].get(k))
        raise Refused("changed after approval: %s" % ",".join(changed))
    if spent is not None:
        spent.add(approval["nonce"])
    return "executed"


def outcome(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except Refused as exc:
        return "refused: %s" % exc


# ------------------------------------------- Part A: the gap between the two

class Queue:
    """Proposals live in a store the agent can still write to."""

    def __init__(self, bind=True, key=None):
        self.items = {}
        self.approved = set()
        self.bind = bind
        self.key = key
        self.approvals = {}
        self.spent = set()

    def propose(self, pid, params):
        self.items[pid] = dict(params)

    def approve(self, pid, cover=None):
        self.approved.add(pid)
        if self.bind:
            self.approvals[pid] = approve(self.items[pid], self.key, cover)

    def execute(self, pid, now=NOW):
        if pid not in self.approved:
            return "refused: not approved"
        params = self.items[pid]          # read a second time, from the store
        if not self.bind:
            return "executed %s to %s for %s" % (
                params["amount"], params["account_id"], params["tool"])
        try:
            check_approval(self.approvals[pid], params, self.key,
                           now=now, spent=self.spent)
        except Refused as exc:
            return "refused: %s" % exc
        return "executed %s to %s for %s" % (
            params["amount"], params["account_id"], params["tool"])


# ------------------------------------ Part C: what the approver actually read

def render(params):
    """The one line a human sees in the approval prompt."""
    return "Refund %s to %s" % (params["amount"], params["account_name"])


RESULTS = []


def check(label, expected, actual):
    RESULTS.append((label, expected, actual))
    print("%2d. %-58s %s" % (len(RESULTS), label, actual))


def main():
    key = secrets.token_bytes(32)
    print("approval keys: random, this run only; nothing is printed")
    print()

    original = {"tool": "refund", "amount": 40, "account_id": "ACC-771",
                "account_name": "T. Okafor", "booking_id": "B-5512"}
    tampered = dict(original, amount=4000, account_id="ACC-999")

    print("Part A: the proposal is read twice, and can change in between.")
    loose = Queue(bind=False)
    loose.propose("p1", original)
    loose.approve("p1")
    check("the approved proposal, executed unchanged",
          "executed 40 to ACC-771 for refund", loose.execute("p1"))
    loose.propose("p2", original)
    loose.approve("p2")
    loose.items["p2"] = dict(tampered)       # the agent writes again
    check("the same approval after the proposal was rewritten",
          "executed 4000 to ACC-999 for refund", loose.execute("p2"))
    check("  what the human approved", "Refund 40 to T. Okafor",
          render(original))
    check("  what ran", "4000", str(loose.items["p2"]["amount"]))

    bound = Queue(bind=True, key=key)
    bound.propose("p3", original)
    bound.approve("p3")
    bound.items["p3"] = dict(tampered)
    check("the same rewrite against a bound approval",
          "refused: changed after approval: account_id,amount",
          bound.execute("p3"))
    bound.propose("p4", original)
    bound.approve("p4")
    check("an unchanged proposal against a bound approval",
          "executed 40 to ACC-771 for refund", bound.execute("p4"))

    print()
    print("Part B: an approval covers the fields you chose, and no others.")
    narrow = approve(original, key, cover=("tool", "amount"))
    wide = approve(original, key)
    check("fields the narrow approval covers", "['amount', 'tool']",
          str(narrow["cover"]))
    check("fields the wide approval covers",
          "['account_id', 'account_name', 'amount', 'booking_id', 'tool']",
          str(wide["cover"]))
    for field, value in [("amount", 4000), ("tool", "send_payment"),
                         ("account_id", "ACC-999"),
                         ("account_name", "Someone Else"),
                         ("booking_id", "B-0001")]:
        changed = dict(original)
        changed[field] = value
        got = outcome(check_approval, narrow, changed, key)
        check("  changing %s, under the narrow approval" % field,
              "refused: changed after approval: %s" % field
              if field in narrow["cover"] else "executed", got)
    caught_narrow = sum(
        1 for f, v in [("amount", 4000), ("tool", "send_payment"),
                       ("account_id", "ACC-999"),
                       ("account_name", "Someone Else"),
                       ("booking_id", "B-0001")]
        if outcome(check_approval, narrow, dict(original, **{f: v}),
                   key).startswith("refused"))
    caught_wide = sum(
        1 for f, v in [("amount", 4000), ("tool", "send_payment"),
                       ("account_id", "ACC-999"),
                       ("account_name", "Someone Else"),
                       ("booking_id", "B-0001")]
        if outcome(check_approval, wide, dict(original, **{f: v}),
                   key).startswith("refused"))
    check("changes the narrow approval catches, of five", "2",
          str(caught_narrow))
    check("changes the wide approval catches, of five", "5", str(caught_wide))
    check("  the destination account is covered by which", "wide only",
          "wide only" if "account_id" in wide["cover"]
          and "account_id" not in narrow["cover"] else "both")

    print()
    print("Part C: what the approver read, against what the executor used.")
    relabelled = dict(original, account_id="ACC-999")
    check("the summary the approver sees", "Refund 40 to T. Okafor",
          render(original))
    check("the summary after the account id is swapped",
          "Refund 40 to T. Okafor", render(relabelled))
    check("  the two summaries agree", "yes",
          "yes" if render(original) == render(relabelled) else "no")
    check("  the accounts agree", "no",
          "yes" if original["account_id"] == relabelled["account_id"]
          else "no")
    summary_only = approve({"summary": render(original)}, key)
    check("an approval bound to the summary, against the swap", "executed",
          outcome(check_approval, summary_only,
                  {"summary": render(relabelled)}, key))
    check("an approval bound to the parameters, against the swap",
          "refused: changed after approval: account_id",
          outcome(check_approval, wide, relabelled, key))
    check("  the summary shows the account id", "no",
          "yes" if original["account_id"] in render(original) else "no")

    print()
    print("Part D: single use, and expiry.")
    spent = set()
    once = approve(original, key, nonce="n-1")
    check("the first execution", "executed",
          outcome(check_approval, once, original, key, spent=spent))
    check("the second, with the same approval",
          "refused: approval has already been used",
          outcome(check_approval, once, original, key, spent=spent))
    unguarded = sum(1 for _ in range(2)
                    if outcome(check_approval, once, original,
                               key).startswith("executed"))
    check("  the same two attempts with no single-use record", "2",
          str(unguarded))
    fresh = approve(original, key, nonce="n-2")
    check("a fresh approval a minute later", "executed",
          outcome(check_approval, fresh, original, key, now=NOW + 60))
    check("and after its lifetime", "refused: approval has expired",
          outcome(check_approval, fresh, original, key, now=NOW + TTL))
    check("  seconds it was valid for", "300", str(TTL))
    forged = dict(wide, covered=dict(wide["covered"], amount=4000))
    check("an approval edited to raise the amount",
          "refused: approval does not verify",
          outcome(check_approval, forged, dict(original, amount=4000), key))

    print()
    print("Part E: the blanket approval, measured.")
    session_ops = [dict(original, booking_id="B-%04d" % n, amount=40 + n)
                   for n in range(12)]
    per_action = [approve(p, key, nonce="per-%d" % i)
                  for i, p in enumerate(session_ops)]
    check("operations in the session", "12", str(len(session_ops)))
    check("approvals a per-action policy issues", "12", str(len(per_action)))
    blanket = approve({"session": "s-1"}, key, nonce="blanket-1")
    check("approvals a blanket policy issues, for the same twelve", "1",
          str(len([blanket])))
    # The executor presents the operation with the session handle. The
    # blanket approval covers only the handle, so nothing else in the
    # operation is compared.
    authorised = sum(1 for p in session_ops
                     if outcome(check_approval, blanket,
                                dict(p, session="s-1"),
                                key).startswith("executed"))
    check("  operations it authorises", "12", str(authorised))
    check("  fields of an operation it constrains", "0",
          str(len([k for k in blanket["cover"] if k in session_ops[0]])))
    check("  fields a per-action approval constrains", "5",
          str(len([k for k in per_action[0]["cover"]
                   if k in session_ops[0]])))
    escalated = dict(session_ops[0], tool="send_payment", amount=40000)
    check("a payment slipped into that session, under the blanket",
          "executed",
          outcome(check_approval, blanket,
                  dict(escalated, session="s-1"), key))
    check("  the same payment under a per-action approval",
          "refused: changed after approval: amount,tool",
          outcome(check_approval, per_action[0], escalated, key))
    check("  what the blanket approval actually bound", "['session']",
          str(blanket["cover"]))

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
