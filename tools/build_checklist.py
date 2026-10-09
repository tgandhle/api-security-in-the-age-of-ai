"""Regenerate the checklist from the checklist items on topic pages.

Usage:
  python3 tools/build_checklist.py          rewrite the three files below
  python3 tools/build_checklist.py --check  exit 1 if any of them is out of date

Writes checklist/index.html, and checklist/checklist.json and
checklist/checklist.csv for other tools. The two data files carry each item's
applicability condition from data/checklist-applicability.json, a schema
version, and a data version that is a hash of their content, so it changes
exactly when the data does. They are licensed CC BY 4.0 (CHECKLIST-LICENSE.md).

Retired ids: data/retired-checklist-ids.json lists ids that were published and
withdrawn. Both modes exit 1 if a retired id is on a topic page, or if an id
the committed checklist.json publishes is no longer on any page and is not in
that list. The committed checklist.json is what remembers which ids were
published.

Standard library only. Items are <li data-check="id" data-severity="...">
elements containing a <strong> title and a <span> detail.

The two paragraphs that explain what a severity means are not written here.
They come from data/severity-rubric-summary.json, which app/src/Checklist.jsx
reads as well, so the static page and the hosted page cannot say different
things. That file names the rubric version it summarises, and this tool
refuses to run if CONVENTIONS.md states a different one.
"""
import csv, hashlib, html, io, json, pathlib, re, sys
from html.parser import HTMLParser

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "checklist" / "index.html"
PAGES = sorted(ROOT.glob("topics/*/index.html")) + sorted(ROOT.glob("protocols/*/index.html"))
ORDER = {"Critical": 0, "High": 1, "Medium": 2}
SUMMARY = ROOT / "data" / "severity-rubric-summary.json"
CONVENTIONS = ROOT / "CONVENTIONS.md"
APPLICABILITY = ROOT / "data" / "checklist-applicability.json"
RETIRED = ROOT / "data" / "retired-checklist-ids.json"
OUT_JSON = ROOT / "checklist" / "checklist.json"
OUT_CSV = ROOT / "checklist" / "checklist.csv"
SCHEMA_VERSION = "1"
REPOSITORY = "https://github.com/tgandhle/api-security-in-the-age-of-ai"
SITE = "https://tgandhle.github.io/api-security-in-the-age-of-ai/"
LICENSE = {
    "id": "CC-BY-4.0",
    "url": "https://creativecommons.org/licenses/by/4.0/",
    "notice": "The review checklist data in this file is licensed under the Creative "
              "Commons Attribution 4.0 International licence. See CHECKLIST-LICENSE.md "
              "in the repository. The lessons, glossary and other course material are "
              "not covered by this licence.",
    "attribution": "Review checklist from API Security in the Age of AI, "
                   "copyright (c) 2026 tgandhle, " + REPOSITORY + ", licensed CC BY 4.0.",
}


def load_summary():
    """The learner-facing summary, checked against the full rubric's version."""
    summary = json.loads(SUMMARY.read_text(encoding="utf-8"))
    names = [level["name"] for level in summary["levels"]]
    if names != sorted(ORDER, key=ORDER.get):
        sys.exit(f"{SUMMARY.name} must describe {', '.join(sorted(ORDER, key=ORDER.get))} "
                 f"in that order, found {', '.join(names)}")
    stated = re.search(r"^## Severity rubric\n\nVersion ([0-9.]+)[,.]",
                       CONVENTIONS.read_text(encoding="utf-8"), re.M)
    if not stated:
        sys.exit("CONVENTIONS.md has no 'Version N' line under '## Severity rubric'")
    if stated.group(1) != summary["rubric_version"]:
        sys.exit(f"CONVENTIONS.md has rubric version {stated.group(1)} and "
                 f"{SUMMARY.name} summarises version {summary['rubric_version']}: "
                 "bring the summary up to date and set its rubric_version")
    return summary


def render_summary(summary):
    t = lambda text: html.escape(text, quote=False)
    levels = " ".join(f"<strong>{t(level['name'])}:</strong> {t(level['rule'])}"
                      for level in summary["levels"])
    pointer = summary["full_rubric"]
    return (
        f'<p class="prose meta">{t(summary["question"])} {levels} '
        f'{t(summary["detecting_recovering"])} {t(summary["assuring"])} '
        f'{t(pointer["before"])} <code>{t(pointer["file"])}</code> {t(pointer["after"])}</p>\n'
        f'<p class="prose meta">{t(summary["not_a_finding"])}</p>')


class Items(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.items, self.cur, self.field, self.title = [], None, None, None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "title" and self.title is None:
            # Only the first <title>, which is the one in <head>. Every lesson
            # with a diagram also has a <title> inside its inline <svg>, and
            # taking the last one labelled 26 of 27 source links with the
            # diagram's description instead of the lesson name.
            self.field = "pagetitle"
            self.title = ""
        if tag == "li" and "data-check" in a:
            self.cur = {"id": a["data-check"], "sev": a.get("data-severity", "Medium"), "title": "", "detail": ""}
        elif self.cur and tag == "strong":
            self.field = "title"
        elif self.cur and tag == "span":
            self.field = "detail"

    def handle_endtag(self, tag):
        if tag in ("strong", "span", "title"):
            self.field = None
        if tag == "li" and self.cur:
            self.items.append(self.cur)
            self.cur = None

    def handle_data(self, data):
        if self.field == "pagetitle":
            self.title += data
        elif self.cur and self.field:
            self.cur[self.field] += data


def collect():
    rows, seen = [], set()
    for page in PAGES:
        p = Items()
        p.feed(page.read_text(encoding="utf-8"))
        topic = p.title.split("|")[0].strip()
        rel = page.relative_to(ROOT).as_posix()
        for it in p.items:
            if it["id"] in seen:
                sys.exit(f"duplicate checklist id {it['id']} in {rel}")
            if it["sev"] not in ORDER:
                sys.exit(f"unknown severity {it['sev']} for {it['id']} in {rel}")
            seen.add(it["id"])
            rows.append({**it, "topic": topic, "href": "../" + rel + "#reference"})
    return sorted(rows, key=lambda r: (ORDER[r["sev"]], r["topic"], r["id"]))


def show(condition):
    """A condition as one line of text, for the CSV."""
    if condition == "always":
        return "always"
    parts = [m if isinstance(m, str) else
             ("(" if len(condition["all_of"]) > 1 else "") + " OR ".join(m["any_of"]) +
             (")" if len(condition["all_of"]) > 1 else "")
             for m in condition["all_of"]]
    return " AND ".join(parts)


def export(rows):
    """The machine-readable checklist: a JSON document and a CSV of the items.

    Fails if a retired id is on a page, or if an id that the committed
    checklist.json publishes has gone from the pages without being retired.
    """
    retired = json.loads(RETIRED.read_text(encoding="utf-8"))
    applicability = json.loads(APPLICABILITY.read_text(encoding="utf-8"))
    retired_ids = {r["id"] for r in retired["retired"]}
    ids = {r["id"] for r in rows}
    for reused in sorted(ids & retired_ids):
        sys.exit(f"{reused} is in {RETIRED.relative_to(ROOT)} and is on a topic page: "
                 "a retired id is never used again")
    if OUT_JSON.exists():
        before = {i["id"] for i in json.loads(OUT_JSON.read_text(encoding="utf-8"))["items"]}
        for gone in sorted(before - ids - retired_ids):
            sys.exit(f"{gone} was published and is no longer on any topic page: add it to "
                     f"{RETIRED.relative_to(ROOT)} with the date and the reason")
    items = []
    for r in rows:
        entry = applicability["items"].get(r["id"])
        if entry is None:
            sys.exit(f"{r['id']} has no entry in {APPLICABILITY.relative_to(ROOT)}")
        items.append({
            "id": r["id"],
            "severity": r["sev"],
            "title": " ".join(r["title"].split()),
            "detail": " ".join(r["detail"].split()),
            "lesson": r["topic"],
            "lesson_path": r["href"][len("../"):],
            "applicability": {"condition": entry["condition"], "reason": entry["reason"]},
        })
    body = {
        "items": items,
        "facts": applicability["facts"],
        "retired": retired["retired"],
    }
    digest = hashlib.sha256(json.dumps(body, sort_keys=True, ensure_ascii=False)
                            .encode("utf-8")).hexdigest()[:16]
    doc = {
        "schema_version": SCHEMA_VERSION,
        "data_version": digest,
        "license": LICENSE,
        "source": REPOSITORY,
        "site": SITE,
        "rubric_version": load_summary()["rubric_version"],
        "applicability_model_version": applicability["model_version"],
        "counts": {s: sum(1 for i in items if i["severity"] == s) for s in ORDER},
        **body,
    }
    text = json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
    buf = io.StringIO()
    out = csv.writer(buf, lineterminator="\n")
    out.writerow(["id", "severity", "title", "detail", "lesson", "lesson_path",
                  "applies_when", "applicability_reason", "data_version"])
    for i in items:
        out.writerow([i["id"], i["severity"], i["title"], i["detail"], i["lesson"],
                      i["lesson_path"], show(i["applicability"]["condition"]),
                      i["applicability"]["reason"], digest])
    return text, buf.getvalue()


def render(rows, summary):
    e = html.escape
    items = "\n".join(
        f'<li><label><input type="checkbox"><span><strong>{e(r["title"].strip())}</strong>'
        f'<span class="sev {e(r["sev"])}">{e(r["sev"])}</span><br>'
        f'<span class="meta">{e(r["detail"].strip())} Source: <a href="{e(r["href"])}">{e(r["topic"])}</a>.</span></span></label></li>'
        for r in rows)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Review checklist | API Security in the Age of AI</title>
<link rel="stylesheet" href="../assets/site.css">
</head>
<body>
<nav class="site-nav" aria-label="Site"><div><a class="home" href="../index.html">API Security in the Age of AI</a><a href="../index.html#course">Course</a><a href="../index.html#path">Modules</a><a href="../roadmap/index.html">Roadmap</a><a href="index.html">Checklist</a><a href="../glossary/index.html">Glossary</a></div></nav>
<main>
<h1>Review checklist</h1>
<p class="prose meta">Generated from the reference sections of each topic page by <code>tools/build_checklist.py</code>. Do not edit this file by hand. {len(rows)} items, sorted by severity. Ticks are not saved.</p>
{render_summary(summary)}
<p class="prose meta">For other tools: <a href="checklist.json">checklist.json</a> and <a href="checklist.csv">checklist.csv</a>, with each item's applicability condition. The checklist data is licensed <a href="https://creativecommons.org/licenses/by/4.0/">CC BY 4.0</a>; the lessons are not.</p>
<ul class="checks">
{items}
</ul>
</main>
<footer>Part of API Security in the Age of AI.</footer>
</body>
</html>
"""


if __name__ == "__main__":
    rows = collect()
    new = render(rows, load_summary())
    data_json, data_csv = export(rows)
    outputs = [(OUT, new), (OUT_JSON, data_json), (OUT_CSV, data_csv)]
    if "--check" in sys.argv:
        for path, text in outputs:
            current = path.read_text(encoding="utf-8") if path.exists() else ""
            if current != text:
                sys.exit(f"{path.relative_to(ROOT)} is out of date: run python3 tools/build_checklist.py")
        print("checklist is up to date")
    else:
        for path, text in outputs:
            path.write_text(text, encoding="utf-8", newline="")
        print(f"wrote {OUT.relative_to(ROOT)} with {new.count('<li>')} items, "
              f"and {OUT_JSON.name} and {OUT_CSV.name}, data version "
              f"{json.loads(data_json)['data_version']}")
