// Tests for applicability.js. Run with `npm test` in app/, which is
// node --test with no other dependency.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  YES, NO, UNKNOWN, resolve, contradictions, evaluate, hidden, excludedBy
} from "./applicability.js";

const data = JSON.parse(readFileSync(
  new URL("../../data/checklist-applicability.json", import.meta.url), "utf8"));
const facts = data.facts;
const items = Object.entries(data.items);

// A small model of the same shape: a implies b, b implies c.
const chain = [
  { id: "a", implies: ["b"] }, { id: "b", implies: ["c"] }, { id: "c", implies: [] },
  { id: "d", implies: [] }
];
const all = (...m) => ({ all_of: m });
const any = (...ids) => ({ any_of: ids });

test("every fact starts unknown", () => {
  const { resolved } = resolve({}, chain);
  assert.deepEqual(resolved, { a: UNKNOWN, b: UNKNOWN, c: UNKNOWN, d: UNKNOWN });
});

test("child yes makes parent yes, through a chain", () => {
  const { resolved, because } = resolve({ a: YES }, chain);
  assert.equal(resolved.b, YES);
  assert.equal(resolved.c, YES);
  assert.equal(because.c, "a");
});

test("parent no makes child no, through a chain", () => {
  const { resolved, because } = resolve({ c: NO }, chain);
  assert.equal(resolved.b, NO);
  assert.equal(resolved.a, NO);
  assert.equal(because.a, "c");
});

test("nothing follows from child no or parent yes", () => {
  assert.equal(resolve({ a: NO }, chain).resolved.b, UNKNOWN);
  assert.equal(resolve({ c: YES }, chain).resolved.b, UNKNOWN);
});

test("an answer the reader gave is never changed", () => {
  const { resolved } = resolve({ a: YES, b: NO }, chain);
  assert.equal(resolved.a, YES);
  assert.equal(resolved.b, NO);
});

test("child yes with parent no is a contradiction, naming both answers", () => {
  assert.deepEqual(contradictions({ a: YES, b: NO }, chain), [{ yes: "a", no: "b" }]);
  assert.deepEqual(contradictions({ a: YES, c: NO }, chain), [{ yes: "a", no: "c" }]);
  assert.deepEqual(contradictions({ a: YES, c: YES }, chain), []);
  assert.deepEqual(contradictions({ a: NO, c: YES }, chain), []);
});

test("three-valued evaluation", () => {
  const r = (x) => resolve(x, chain).resolved;
  assert.equal(evaluate("always", r({ a: NO, b: NO, c: NO, d: NO })), true);
  assert.equal(evaluate(all("d"), r({})), null);
  assert.equal(evaluate(all("d"), r({ d: YES })), true);
  assert.equal(evaluate(all("d"), r({ d: NO })), false);
  assert.equal(evaluate(all(any("a", "d")), r({ d: NO })), null);
  assert.equal(evaluate(all(any("a", "d")), r({ a: NO, d: NO })), false);
  assert.equal(evaluate(all(any("a", "d")), r({ a: YES, d: NO })), true);
  assert.equal(evaluate(all("a", "d"), r({ a: YES })), null);
  assert.equal(evaluate(all("a", "d"), r({ d: NO })), false);
});

test("only false hides, and an implied no hides", () => {
  const r = (x) => resolve(x, chain).resolved;
  assert.equal(hidden(all("a"), r({})), false);
  assert.equal(hidden(all("a"), r({ a: YES })), false);
  assert.equal(hidden(all("a"), r({ c: NO })), true);
  assert.deepEqual(excludedBy(all("a"), r({ c: NO })), ["a"]);
  assert.deepEqual(excludedBy(all(any("a", "d")), r({ c: NO, d: NO })), ["a", "d"]);
  assert.deepEqual(excludedBy(all("d"), r({ d: YES })), []);
});

test("with no answers, none of the 325 items is hidden", () => {
  const { resolved } = resolve({}, facts);
  assert.equal(items.length, 325);
  for (const [id, item] of items) assert.equal(hidden(item.condition, resolved), false, id);
});

test("with every fact yes, none of the 325 items is hidden", () => {
  const answers = Object.fromEntries(facts.map((f) => [f.id, YES]));
  const { resolved } = resolve(answers, facts);
  for (const [id, item] of items) assert.equal(hidden(item.condition, resolved), false, id);
});

test("with every fact no, exactly the conditional items are hidden, each with a reason", () => {
  const answers = Object.fromEntries(facts.map((f) => [f.id, NO]));
  const { resolved } = resolve(answers, facts);
  let n = 0;
  for (const [id, item] of items) {
    const h = hidden(item.condition, resolved);
    assert.equal(h, item.condition !== "always", id);
    if (h) {
      n++;
      assert.ok(excludedBy(item.condition, resolved).length > 0, id);
    }
  }
  assert.equal(n, 208);
});

test("one fact answered no hides only items that need it, and names it", () => {
  for (const fact of facts) {
    const { resolved } = resolve({ [fact.id]: NO }, facts);
    for (const [id, item] of items) {
      if (!hidden(item.condition, resolved)) continue;
      for (const f of excludedBy(item.condition, resolved)) {
        assert.equal(resolved[f], NO, id + " " + f);
      }
    }
  }
});

test("the real model: a2a-04 needs both a2a and webhook_receiver", () => {
  const c = data.items["a2a-04"].condition;
  assert.equal(hidden(c, resolve({ a2a: YES }, facts).resolved), false);
  assert.equal(hidden(c, resolve({ webhook_receiver: NO }, facts).resolved), true);
  assert.equal(hidden(c, resolve({ a2a: NO }, facts).resolved), true);
});

test("the real model: browser_client no hides cookie items through the implication", () => {
  const { resolved } = resolve({ browser_client: NO }, facts);
  assert.equal(resolved.cookie_session, NO);
  assert.equal(hidden(data.items["csrf-01"].condition, resolved), true);
  assert.deepEqual(contradictions({ browser_client: NO, cookie_session: YES }, facts),
                   [{ yes: "cookie_session", no: "browser_client" }]);
});
