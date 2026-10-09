import { Fragment, useEffect, useMemo, useState } from "react";
import data from "../../data/checklist-applicability.json";
import {
  YES, NO, UNKNOWN, resolve, contradictions, hidden, excludedBy
} from "./applicability.js";

// The applicability filter on the hosted checklist. Client only: it is
// created, not hydrated, so with JavaScript off the page shows every item and
// no controls that would not work. It never removes an item from the page. It
// sets `hidden` on the items its answers rule out, and lists each of those
// below with the answers that ruled it out.
//
// Rules: "Checklist applicability" in CONVENTIONS.md. Evaluation:
// applicability.js. Answers are held in memory only and are not saved.

const facts = data.facts;
const question = Object.fromEntries(facts.map((f) => [f.id, f.question]));
const groups = [];
for (const fact of facts) {
  let g = groups.find((x) => x.name === fact.group);
  if (!g) groups.push(g = { name: fact.group, facts: [] });
  g.facts.push(fact);
}
const CHOICES = [[YES, "Yes"], [NO, "No"], [UNKNOWN, "Not known"]];

// The checklist items already on the page, read once. The title and severity
// are read from the prerendered markup so they are not shipped twice.
function readItems() {
  return [...document.querySelectorAll("li[data-check]")].map((li) => ({
    id: li.dataset.check,
    li,
    title: li.querySelector("strong")?.textContent || li.dataset.check,
    severity: li.querySelector(".sev")?.textContent || ""
  }));
}

function quote(id) {
  return "“" + question[id] + "”";
}

export default function ApplicabilityFilter() {
  const [answers, setAnswers] = useState({});
  const [refused, setRefused] = useState(null);
  const [items, setItems] = useState([]);

  useEffect(() => setItems(readItems()), []);

  const { resolved, because } = useMemo(() => resolve(answers, facts), [answers]);
  const setAside = useMemo(() => items.filter((it) => {
    const entry = data.items[it.id];
    // An item with no entry is never hidden. tools/check_applicability.py
    // fails the build before that can be published.
    return entry && hidden(entry.condition, resolved);
  }), [items, resolved]);

  useEffect(() => {
    const out = new Set(setAside.map((it) => it.id));
    for (const it of items) it.li.hidden = out.has(it.id);
  }, [items, setAside]);

  function choose(id, value) {
    const next = { ...answers, [id]: value };
    if (value === UNKNOWN) delete next[id];
    const conflict = contradictions(next, facts)[0];
    if (conflict) {
      setRefused(`Not applied. Answering Yes to ${quote(conflict.yes)} means ` +
        `Yes to ${quote(conflict.no)}, which is answered No. Change one of ` +
        "those two answers first.");
      return;
    }
    setRefused(null);
    setAnswers(next);
  }

  function reset() {
    setRefused(null);
    setAnswers({});
  }

  const answered = Object.keys(answers).length;
  const shown = items.length - setAside.length;

  return (
    <section className="applicability" aria-labelledby="applicability-heading">
      <h2 id="applicability-heading">Filter for one system</h2>
      <p className="prose meta">
        Answer what you know about the system under review. A question left
        as &ldquo;Not known&rdquo; hides nothing. An item is set aside only
        when your answers show it cannot apply, and every item set aside is
        listed below with the answer that ruled it out. Answers are not saved.
      </p>
      {groups.map((g) => (
        <details key={g.name}>
          <summary>{g.name} ({g.facts.length} questions)</summary>
          <div className="applicability-questions">
            {g.facts.map((f) => {
              const derived = !answers[f.id] && resolved[f.id] !== UNKNOWN;
              return (
                <fieldset key={f.id}>
                  <legend>{f.question}</legend>
                  {CHOICES.map(([value, label]) => (
                    <label key={value}>
                      <input type="radio" name={"fact-" + f.id} value={value}
                             checked={(answers[f.id] || UNKNOWN) === value}
                             onChange={() => choose(f.id, value)} />
                      {label}
                    </label>
                  ))}
                  {derived && (
                    <p className="meta">
                      Treated as {resolved[f.id] === YES ? "Yes" : "No"}, from
                      your answer to {quote(because[f.id])}
                    </p>
                  )}
                </fieldset>
              );
            })}
          </div>
        </details>
      ))}
      <p className="applicability-refused" role="alert">{refused}</p>
      <div className="applicability-status">
        <p aria-live="polite">
          Showing {shown} of {items.length} items. {setAside.length} set aside.
        </p>
        <button type="button" className="button secondary" onClick={reset}
                disabled={answered === 0}>
          Clear answers
        </button>
      </div>
      {setAside.length > 0 && (
        <details>
          <summary>Items set aside ({setAside.length})</summary>
          <ul className="applicability-aside">
            {setAside.map((it) => {
              const entry = data.items[it.id];
              const by = excludedBy(entry.condition, resolved);
              return (
                <li key={it.id}>
                  <strong>{it.title}</strong>
                  {it.severity && <span className={"sev " + it.severity}>{it.severity}</span>}
                  <span className="meta"> {it.id}</span>
                  <br />
                  <span className="meta">
                    Set aside because the answer is No to{" "}
                    {by.map((id, n) => (
                      <Fragment key={id}>
                        {n > 0 && (n === by.length - 1 ? " and " : ", ")}
                        {quote(id)}
                        {!answers[id] && because[id] &&
                          <> (from your answer to {quote(because[id])})</>}
                      </Fragment>
                    ))}
                  </span>
                  <br />
                  <span className="meta">Why: {entry.reason}</span>
                </li>
              );
            })}
          </ul>
        </details>
      )}
    </section>
  );
}
