// Ranking, kept simple on purpose. People search for a header name, a term,
// or a check id, so an exact id match wins, then a title that starts with the
// query, then a title that contains it, then the detail text.
const WEIGHT = { code: 0, check: 1, term: 2, control: 3, lesson: 4, section: 5 };

export function score(doc, query) {
  const q = query.toLowerCase();
  const title = doc.t.toLowerCase();
  const detail = (doc.x || "").toLowerCase();
  if (doc.i && doc.i.toLowerCase() === q) return 1000;
  if (title === q) return 900;
  if (doc.i && doc.i.toLowerCase().indexOf(q) === 0) return 800;
  if (title.indexOf(q) === 0) return 700;
  if (title.indexOf(q) !== -1) return 500 - title.length / 100;
  if (detail.indexOf(q) !== -1) return 200 - detail.length / 1000;
  // Every word of the query somewhere in the record.
  const words = q.split(/\s+/).filter(Boolean);
  if (words.length > 1 && words.every((w) =>
      title.indexOf(w) !== -1 || detail.indexOf(w) !== -1)) return 150;
  return 0;
}

export function search(index, query, limit) {
  const trimmed = query.trim();
  if (trimmed.length < 2) return [];
  const hits = [];
  for (const doc of index) {
    const s = score(doc, trimmed);
    if (s > 0) hits.push({ doc, s });
  }
  hits.sort((a, b) =>
    b.s - a.s || WEIGHT[a.doc.k] - WEIGHT[b.doc.k] ||
    a.doc.t.localeCompare(b.doc.t));
  return hits.slice(0, limit || 25).map((h) => h.doc);
}

export function href(doc, up) {
  if (doc.k === "term") return up + "glossary/index.html#" + doc.s;
  if (doc.k === "check" || doc.k === "control") {
    return up + "topics/" + doc.s + "/index.html#reference";
  }
  return up + "topics/" + doc.s + "/index.html";
}

export function label(doc) {
  if (doc.k === "term") return "Glossary";
  if (doc.k === "check") return doc.i + " · " + doc.v;
  if (doc.k === "section") return "Module " + doc.m + " · " + doc.x;
  return "Module " + doc.m;
}
