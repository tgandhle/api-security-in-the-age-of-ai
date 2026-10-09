// The checklist applicability model, version 1. The rules are under
// "Checklist applicability" in CONVENTIONS.md; the facts, implications and
// conditions are in data/checklist-applicability.json. This file only
// evaluates them. It has no React and no DOM, so it can be tested with
// node --test (src/applicability.test.js).
//
// Answers are "yes", "no" or "unknown". A fact with no answer is unknown.

export const YES = "yes";
export const NO = "no";
export const UNKNOWN = "unknown";

// [child, parent] for every declared implication.
export function implications(facts) {
  const out = [];
  for (const fact of facts) {
    for (const parent of fact.implies || []) out.push([fact.id, parent]);
  }
  return out;
}

// Child Yes makes parent Yes. Parent No makes child No. Nothing else follows.
// Returns the resolved answers and, for each fact the rules settled, the fact
// whose answer settled it. Answers the reader gave are never changed.
export function resolve(answers, facts) {
  const resolved = {};
  const because = {};
  for (const fact of facts) resolved[fact.id] = answers[fact.id] || UNKNOWN;
  const pairs = implications(facts);
  let changed = true;
  while (changed) {
    changed = false;
    for (const [child, parent] of pairs) {
      if (resolved[child] === YES && resolved[parent] === UNKNOWN) {
        resolved[parent] = YES;
        because[parent] = because[child] || child;
        changed = true;
      }
      if (resolved[parent] === NO && resolved[child] === UNKNOWN) {
        resolved[child] = NO;
        because[child] = because[parent] || parent;
        changed = true;
      }
    }
  }
  return { resolved, because };
}

// Every declared implication the answers break: child Yes and parent No,
// after resolution, so a chain is caught as well as a direct pair. Each entry
// names the two answers the reader gave that conflict.
export function contradictions(answers, facts) {
  const { resolved, because } = resolve(answers, facts);
  const found = [];
  for (const [child, parent] of implications(facts)) {
    if (resolved[child] === YES && resolved[parent] === NO) {
      found.push({ yes: because[child] || child, no: because[parent] || parent });
    }
  }
  const seen = new Set();
  return found.filter((c) => {
    const key = c.yes + " " + c.no;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function factValue(id, resolved) {
  const a = resolved[id] || UNKNOWN;
  return a === YES ? true : a === NO ? false : null;
}

// true, false, or null for unknown.
export function evaluate(condition, resolved) {
  if (condition === "always") return true;
  const results = condition.all_of.map((member) => {
    if (typeof member === "string") return factValue(member, resolved);
    const values = member.any_of.map((id) => factValue(id, resolved));
    if (values.includes(true)) return true;
    if (values.every((v) => v === false)) return false;
    return null;
  });
  if (results.includes(false)) return false;
  if (results.every((r) => r === true)) return true;
  return null;
}

// Only false hides an item.
export function hidden(condition, resolved) {
  return evaluate(condition, resolved) === false;
}

// The facts answered No that make a hidden item's condition false: the first
// false member of its all_of, which is one fact, or every fact of an any_of.
// Empty if the item is not hidden.
export function excludedBy(condition, resolved) {
  if (!hidden(condition, resolved)) return [];
  for (const member of condition.all_of) {
    if (typeof member === "string") {
      if (factValue(member, resolved) === false) return [member];
    } else if (member.any_of.every((id) => factValue(id, resolved) === false)) {
      return [...member.any_of];
    }
  }
  return [];
}
