"""Regenerate checklist/index.html from the checklist items on topic pages.

Usage:
  python3 tools/build_checklist.py          rewrite checklist/index.html
  python3 tools/build_checklist.py --check  exit 1 if the file is out of date

Standard library only. Items are <li data-check="id" data-severity="...">
elements containing a <strong> title and a <span> detail.

The two paragraphs that explain what a severity means are not written here.
They come from data/severity-rubric-summary.json, which app/src/Checklist.jsx
reads as well, so the static page and the hosted page cannot say different
things. That file names the rubric version it summarises, and this tool
refuses to run if CONVENTIONS.md states a different one.
"""
import html, json, pathlib, re, sys
from html.parser import HTMLParser

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "checklist" / "index.html"
PAGES = sorted(ROOT.glob("topics/*/index.html")) + sorted(ROOT.glob("protocols/*/index.html"))
ORDER = {"Critical": 0, "High": 1, "Medium": 2}
SUMMARY = ROOT / "data" / "severity-rubric-summary.json"
CONVENTIONS = ROOT / "CONVENTIONS.md"


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
<ul class="checks">
{items}
</ul>
</main>
<footer>Part of API Security in the Age of AI.</footer>
</body>
</html>
"""


if __name__ == "__main__":
    new = render(collect(), load_summary())
    if "--check" in sys.argv:
        current = OUT.read_text(encoding="utf-8") if OUT.exists() else ""
        if current != new:
            sys.exit("checklist/index.html is out of date: run python3 tools/build_checklist.py")
        print("checklist is up to date")
    else:
        OUT.write_text(new, encoding="utf-8")
        print(f"wrote {OUT.relative_to(ROOT)} with {new.count('<li>')} items")
