#!/usr/bin/env python3
"""Check data/checklist-applicability.json against the checklist and its own model.

Usage:
  python3 tools/check_applicability.py

Standard library only. Exits 1 with every problem listed, 0 with one line of
counts.

The file is authored, not generated. It says, for each checklist item, which
facts about a system the item needs in order to apply: either "always", or
{"all_of": [...]} whose members are fact ids or {"any_of": [fact ids]} groups.
A fact may imply another ("implies"): child Yes makes parent Yes, and parent
No makes child No. Nothing reads the file yet except this tool.

What fails:
  - model_version is not the one this tool was written for;
  - a fact has no id, group or question, appears twice, or implies a fact
    that is not declared, or the implications contain a cycle;
  - a checklist id on the topic pages has no entry, or has two;
  - an entry names an id that is not on the checklist;
  - a condition breaks the grammar or names a fact that is not declared;
  - a condition contains a redundant fact: one that could be deleted without
    changing the result under any valid assignment of Yes, No and Unknown,
    whether that comes from a direct or a chained implication and whether the
    fact sits in the all_of list or inside an any_of group;
  - a reason is missing or empty.

Evaluation is three-valued. A fact is true on Yes, false on No and unknown
otherwise. any_of is true if any member is true and false only if all are
false. all_of is false if any member is false and true only if all are true.
"""
import itertools
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
DATA = ROOT / "data" / "checklist-applicability.json"
PAGES = sorted(ROOT.glob("topics/*/index.html")) + sorted(ROOT.glob("protocols/*/index.html"))
MODEL_VERSION = "1"


def pairs_keeping_duplicates(pairs):
    """json.loads keeps the last of two equal keys. Record them instead."""
    seen, out = set(), {}
    for key, value in pairs:
        if key in seen:
            out.setdefault("\0duplicates", []).append(key)
        seen.add(key)
        out[key] = value
    return out


def checklist_ids():
    ids = []
    for page in PAGES:
        ids += re.findall(r'<li data-check="([^"]+)"', page.read_text(encoding="utf-8"))
    return ids


def grammar_problem(cond, facts):
    """None if the condition is well formed, otherwise what is wrong with it."""
    if cond == "always":
        return None
    if not (isinstance(cond, dict) and list(cond) == ["all_of"]
            and isinstance(cond["all_of"], list) and cond["all_of"]):
        return 'must be "always" or {"all_of": [at least one member]}'
    for member in cond["all_of"]:
        if isinstance(member, str):
            names = [member]
        elif (isinstance(member, dict) and list(member) == ["any_of"]
              and isinstance(member["any_of"], list) and len(member["any_of"]) >= 2
              and all(isinstance(x, str) for x in member["any_of"])):
            names = member["any_of"]
        else:
            return "each member must be a fact id or {\"any_of\": [two or more fact ids]}"
        for name in names:
            if name not in facts:
                return f"names the undeclared fact {name}"
    return None


def facts_in(cond):
    if cond == "always":
        return []
    out = []
    for member in cond["all_of"]:
        out += member["any_of"] if isinstance(member, dict) else [member]
    return out


def evaluate(cond, answers):
    """True, False or None (unknown) under resolved answers."""
    if cond == "always":
        return True

    def fact(name):
        return {"Y": True, "N": False}.get(answers[name])

    results = []
    for member in cond["all_of"]:
        if isinstance(member, dict):
            values = [fact(x) for x in member["any_of"]]
            results.append(True if True in values else False if all(v is False for v in values) else None)
        else:
            results.append(fact(member))
    return False if False in results else True if all(r is True for r in results) else None


def truth_table(cond, universe, implications):
    """The condition's result for every valid assignment over the universe."""
    table = {}
    for combo in itertools.product("YNU", repeat=len(universe)):
        answers = dict(zip(universe, combo))
        changed = True
        while changed:
            changed = False
            for child, parent in implications:
                if child in answers and parent in answers:
                    if answers[child] == "Y" and answers[parent] == "U":
                        answers[parent], changed = "Y", True
                    if answers[parent] == "N" and answers[child] == "U":
                        answers[child], changed = "N", True
        if any(child in answers and parent in answers
               and answers[child] == "Y" and answers[parent] == "N"
               for child, parent in implications):
            continue
        table[combo] = evaluate(cond, answers)
    return table


def redundant_facts(cond, related, implications):
    """Facts that could be deleted without changing the condition's result."""
    if cond == "always":
        return []
    universe = sorted({g for f in facts_in(cond) for g in related[f]})
    base = truth_table(cond, universe, implications)
    members, out = cond["all_of"], []
    for i, member in enumerate(members):
        if isinstance(member, dict):
            for name in member["any_of"]:
                rest = [x for x in member["any_of"] if x != name]
                smaller = rest[0] if len(rest) == 1 else {"any_of": rest}
                trial = {"all_of": members[:i] + [smaller] + members[i + 1:]}
                if truth_table(trial, universe, implications) == base:
                    out.append(name)
        else:
            rest = members[:i] + members[i + 1:]
            trial = {"all_of": rest} if rest else "always"
            if truth_table(trial, universe, implications) == base:
                out.append(member)
    return out


def main():
    problems = []
    data = json.loads(DATA.read_text(encoding="utf-8"),
                      object_pairs_hook=pairs_keeping_duplicates)
    name = DATA.relative_to(ROOT).as_posix()

    if data.get("model_version") != MODEL_VERSION:
        problems.append(f'model_version is {data.get("model_version")!r}, expected "{MODEL_VERSION}"')

    # Facts and implications.
    facts, implications = {}, []
    for entry in data.get("facts", []):
        fid = entry.get("id")
        if not fid or not str(entry.get("group", "")).strip() or not str(entry.get("question", "")).strip():
            problems.append(f"fact {fid!r} needs an id, a group and a question")
            continue
        if fid in facts:
            problems.append(f"fact {fid} is declared twice")
        facts[fid] = entry
    for fid, entry in facts.items():
        for parent in entry.get("implies", []):
            if parent not in facts:
                problems.append(f"fact {fid} implies the undeclared fact {parent}")
            else:
                implications.append((fid, parent))

    parents = {f: {p for c, p in implications if c == f} for f in facts}
    ancestors, cyclic = {}, set()
    for fid in facts:
        seen, stack = set(), list(parents[fid])
        while stack:
            p = stack.pop()
            if p == fid:
                cyclic.add(fid)
            elif p not in seen:
                seen.add(p)
                stack += parents[p]
        ancestors[fid] = seen
    if cyclic:
        problems.append("the implications contain a cycle through " + ", ".join(sorted(cyclic)))
    # A fact, everything it implies and everything that implies it.
    related = {f: {f} | ancestors[f] | {g for g in facts if f in ancestors[g]} for f in facts}

    # Items against the checklist.
    items = data.get("items", {})
    for dup in items.get("\0duplicates", []):
        problems.append(f"{dup} has two entries")
    items = {k: v for k, v in items.items() if k != "\0duplicates"}
    on_pages = checklist_ids()
    for missing in sorted(set(on_pages) - set(items)):
        problems.append(f"{missing} is on the checklist and has no entry")
    for stale in sorted(set(items) - set(on_pages)):
        problems.append(f"{stale} has an entry and is not on the checklist")

    # Each entry.
    for item, entry in items.items():
        if not isinstance(entry, dict) or "condition" not in entry:
            problems.append(f"{item} has no condition")
            continue
        if not str(entry.get("reason", "")).strip():
            problems.append(f"{item} has no reason")
        bad = grammar_problem(entry["condition"], facts)
        if bad:
            problems.append(f"{item}: condition {bad}")
        elif not cyclic:
            for fact in redundant_facts(entry["condition"], related, implications):
                problems.append(f"{item}: {fact} is redundant in its condition")

    if problems:
        print(f"{name}: {len(problems)} problem(s)")
        for p in problems:
            print("  " + p)
        return 1
    always = sum(1 for e in items.values() if e["condition"] == "always")
    print(f"{len(items)} items: {always} always, {len(items) - always} conditional; "
          f"{len(facts)} facts; {len(implications)} implications")
    return 0


if __name__ == "__main__":
    sys.exit(main())
