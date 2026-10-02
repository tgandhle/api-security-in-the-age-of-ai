import { useEffect, useRef, useState } from "react";
import { search, href, label } from "./search.js";

// The index is 25.6 KB gzipped and is injected on the first keystroke, never
// on page load, so a reader who does not search pays nothing for it.
let indexPromise = null;
function loadIndex(up) {
  if (indexPromise) return indexPromise;
  indexPromise = new Promise((resolve, reject) => {
    if (window.__searchIndex) return resolve(window.__searchIndex);
    const script = document.createElement("script");
    script.src = up + "assets/search-index.js";
    script.onload = () => resolve(window.__searchIndex || []);
    script.onerror = () => reject(new Error("the search index did not load"));
    document.head.appendChild(script);
  });
  return indexPromise;
}

export default function Search({ up }) {
  const [query, setQuery] = useState("");
  const [index, setIndex] = useState(null);
  const [failed, setFailed] = useState(false);
  const [active, setActive] = useState(-1);
  const box = useRef(null);

  useEffect(() => {
    if (query.length < 2 || index || failed) return;
    loadIndex(up).then(setIndex).catch(() => setFailed(true));
  }, [query, index, failed, up]);

  const results = index ? search(index, query, 20) : [];
  useEffect(() => { setActive(-1); }, [query]);

  function onKeyDown(event) {
    if (event.key === "Escape") { setQuery(""); return; }
    if (!results.length) return;
    if (event.key === "ArrowDown") {
      event.preventDefault();
      setActive((a) => (a + 1) % results.length);
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      setActive((a) => (a <= 0 ? results.length - 1 : a - 1));
    } else if (event.key === "Enter" && active >= 0) {
      event.preventDefault();
      window.location.href = href(results[active], up);
    }
  }

  const open = query.trim().length >= 2;
  let status = "";
  if (open && failed) status = "The search index did not load.";
  else if (open && !index) status = "Loading the search index.";
  else if (open) status = results.length === 1 ? "1 result"
    : results.length + " results";

  return (
    <div className="site-search" ref={box}>
      <label className="visually-hidden" htmlFor="site-search-input">
        Search the course
      </label>
      <input
        id="site-search-input"
        type="search"
        placeholder="Search lessons, glossary, checklist"
        autoComplete="off"
        value={query}
        onChange={(event) => setQuery(event.target.value)}
        onKeyDown={onKeyDown}
      />
      {/* A list of links, not an ARIA combobox. The first version put
          role="listbox" on this div with role="option" on the anchors inside a
          <ul>, which axe-core reported as 11 violations across three rules:
          the options were not direct children of the listbox
          (aria-required-parent, 9 nodes), the listbox had no valid required
          children (aria-required-children, 1), and aria-expanded is not
          allowed on the implicit searchbox role of <input type="search">
          (aria-allowed-attr, 1). Links in a list need no roles at all, so the
          count goes to a live region and the arrow-key position to
          aria-current. */}
      <p className="visually-hidden" role="status">{status}</p>
      {open ? (
        <div className="search-results" id="site-search-results">
          {failed ? (
            <p className="meta">The search index did not load. Every page is
              still reachable from the module list.</p>
          ) : !index ? (
            <p className="meta">Loading the index, once per visit.</p>
          ) : results.length === 0 ? (
            <p className="meta">Nothing matches {JSON.stringify(query)}.</p>
          ) : (
            <ul>
              {results.map((doc, i) => (
                <li key={doc.k + ":" + doc.s + ":" + (doc.i || doc.t)}>
                  <a href={href(doc, up)}
                     aria-current={i === active ? "true" : undefined}
                     className={i === active ? "active" : undefined}>
                    <span className="hit-title">{doc.t}</span>
                    <span className="hit-where">{label(doc)}</span>
                  </a>
                </li>
              ))}
            </ul>
          )}
        </div>
      ) : null}
    </div>
  );
}
