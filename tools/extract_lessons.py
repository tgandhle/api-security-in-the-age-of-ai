#!/usr/bin/env python3
"""Extract published lessons from HTML into structured JSON, losslessly.

Standard library only. Reads the same page set as tools/build_checklist.py:
topics/*/index.html and protocols/*/index.html.

Why this exists: a front end that re-types lesson content loses it. The
react-poc migration of Module 1 dropped 7 of 12 sections, all 8 glossary
links, all 3 sources and 13 of 20 lab transcript lines. This extractor never
re-types anything. It records byte offsets into the source file and slices
the original bytes, so every block it emits is verbatim by construction.

Usage:
    python3 tools/extract_lessons.py            # write content/lessons/*.json
    python3 tools/extract_lessons.py --check    # verify, write nothing, exit 1 on loss

--check re-reads each source page independently of the extractor's own tree
and asserts that every countable artifact on the page is present in the
extracted record, with identical bytes. It is deliberately a second
implementation: a bug shared by both would have to be written twice.
"""

import html.parser
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT_DIR = ROOT / "content" / "lessons"

VERBATIM_TAGS = ("pre", "svg", "table")
VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link",
        "meta", "source", "track", "wbr"}


def pages():
    return sorted(ROOT.glob("topics/*/index.html")) + \
           sorted(ROOT.glob("protocols/*/index.html"))


class Offsets(html.parser.HTMLParser):
    """Builds a flat list of (tag, attrs, start, end) for elements we care about."""

    def __init__(self, text):
        super().__init__(convert_charrefs=False)
        self.text = text
        starts = [0]
        for line in text.splitlines(keepends=True):
            starts.append(starts[-1] + len(line))
        self.line_starts = starts
        self.stack = []
        self.elements = []

    def _abs(self):
        line, col = self.getpos()
        return self.line_starts[line - 1] + col

    def handle_starttag(self, tag, attrs):
        if tag in VOID:
            return
        self.stack.append((tag, dict(attrs), self._abs()))

    def handle_startendtag(self, tag, attrs):
        return

    def handle_endtag(self, tag):
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                name, attrs, start = self.stack.pop(i)
                del self.stack[i:]
                end = self._abs() + len("</%s>" % tag)
                self.elements.append((name, attrs, start, end))
                return

    def outer(self, element):
        return self.text[element[2]:element[3]]

    def inner(self, element):
        name = element[0]
        open_end = self.text.index(">", element[2]) + 1
        return self.text[open_end:element[3] - len("</%s>" % name)]

    def find(self, tag, **attr_match):
        out = []
        for el in self.elements:
            if el[0] != tag:
                continue
            if all(el[1].get(k) == v for k, v in attr_match.items()):
                out.append(el)
        return sorted(out, key=lambda e: e[2])


def text_of(fragment):
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", fragment)).strip()


def extract(path):
    text = path.read_text(encoding="utf-8")
    doc = Offsets(text)
    doc.feed(text)
    doc.close()

    def first(tag, **kw):
        found = doc.find(tag, **kw)
        return found[0] if found else None

    record = {
        "slug": path.parent.name,
        "source": path.relative_to(ROOT).as_posix(),
        "kind": path.relative_to(ROOT).parts[0],
    }

    title_el = first("title")
    record["page_title"] = doc.inner(title_el) if title_el else ""

    body = first("body")
    record["lesson_key"] = body[1].get("data-course-lesson", "") if body else ""

    h1 = first("h1")
    record["title"] = doc.inner(h1) if h1 else ""

    kicker = first("p", **{"class": "kicker"})
    record["kicker"] = doc.inner(kicker) if kicker else ""

    meta = first("p", **{"class": "meta"})
    meta_text = text_of(doc.inner(meta)) if meta else ""
    found = re.search(r"Last reviewed (\d{4}-\d{2}-\d{2})", meta_text)
    record["reviewed"] = found.group(1) if found else ""

    status = first("section", **{"class": "lesson-status"})
    record["lesson_status_html"] = doc.outer(status) if status else ""

    # Sections: every h2, with everything between it and the next h2 or the
    # next layer marker, sliced verbatim from the source.
    headings = doc.find("h2")
    layers = doc.find("span", **{"class": "layer"})
    boundaries = sorted([e[2] for e in headings] + [e[2] for e in layers] +
                        [len(text)])
    sections = []
    for el in headings:
        after = el[3]
        nxt = min((b for b in boundaries if b >= after), default=len(text))
        sections.append({
            "heading": doc.inner(el),
            "heading_text": text_of(doc.inner(el)),
            "html": text[after:nxt].strip(),
        })
    record["sections"] = sections

    record["layers"] = [{"id": e[1].get("id", ""), "label": doc.inner(e)}
                        for e in layers]

    for tag in VERBATIM_TAGS:
        record[tag + "_blocks"] = [doc.outer(e) for e in doc.find(tag)]

    record["glossary_links"] = [
        {"href": e[1].get("href", ""), "text": text_of(doc.inner(e))}
        for e in doc.find("a")
        if "glossary/index.html#" in e[1].get("href", "")
    ]

    checks = []
    for el in doc.elements:
        if el[0] != "li" or "data-check" not in el[1]:
            continue
        inner = doc.inner(el)
        strong = re.search(r"<strong>(.*?)</strong>", inner, re.S)
        span = re.search(r"<span>(.*?)</span>", inner, re.S)
        checks.append({
            "id": el[1]["data-check"],
            "severity": el[1].get("data-severity", "Medium"),
            "title": strong.group(1) if strong else "",
            "detail": span.group(1) if span else "",
        })
    record["checks"] = sorted(checks, key=lambda c: c["id"])

    # Citations. The template puts them under an h2 reading "Sources",
    # followed by a list. Some pages also give individual entries an
    # id="source-..." so the Learn text can link back to them.
    sources = []
    sources_h2 = next((e for e in doc.find("h2")
                       if text_of(doc.inner(e)) == "Sources"), None)
    if sources_h2 is not None:
        lists = [e for e in doc.find("ul") if e[2] > sources_h2[3]]
        if lists:
            first_list = min(lists, key=lambda e: e[2])
            for el in doc.find("li"):
                if first_list[2] < el[2] and el[3] <= first_list[3]:
                    inner = doc.inner(el)
                    link = re.search(r'<a href="([^"]+)"[^>]*>(.*?)</a>', inner, re.S)
                    sources.append({
                        "id": el[1].get("id", ""),
                        "href": link.group(1) if link else "",
                        "title": link.group(2) if link else "",
                        "html": inner,
                    })
    record["sources"] = sources
    record["source_anchors"] = sorted(
        e[1]["id"] for e in doc.elements
        if e[1].get("id", "").startswith("source-"))

    record["quiz"] = [
        {"summary": re.search(r"<summary>(.*?)</summary>", doc.inner(e), re.S).group(1)
         if re.search(r"<summary>(.*?)</summary>", doc.inner(e), re.S) else "",
         "html": doc.inner(e)}
        for e in doc.find("details")
    ]

    return record


# ---------------------------------------------------------------------------
# --check: an independent second reading of the same file.
# ---------------------------------------------------------------------------

def audit(path):
    """Count artifacts straight out of the raw text, without the tree above."""
    t = path.read_text(encoding="utf-8")
    return {
        "h2": re.findall(r"<h2[^>]*>(.*?)</h2>", t, re.S),
        "pre": re.findall(r"<pre>.*?</pre>", t, re.S),
        "svg": re.findall(r"<svg\b.*?</svg>", t, re.S),
        "table": re.findall(r"<table>.*?</table>", t, re.S),
        "glossary": re.findall(r'href="([^"]*glossary/index\.html#[^"]*)"', t),
        "checks": re.findall(r'data-check="([^"]+)"', t),
        "severities": re.findall(r'data-check="[^"]+"\s+data-severity="([^"]+)"', t),
        "anchors": sorted(re.findall(r'id="(source-[^"]+)"', t)),
        "details": re.findall(r"<details>(.*?)</details>", t, re.S),
        "citations": sources_citations(t),
    }


def sources_block(t):
    """The markup from the Sources heading to the end of its list."""
    start = t.find("<h2>Sources</h2>")
    if start == -1:
        return ""
    end = t.find("</ul>", start)
    return t[start:end] if end != -1 else t[start:]


def sources_citations(t):
    """First href inside each <li> of the Sources list. The capstone cites
    the site's own checklist and lab, so an href is not always absolute."""
    out = []
    for item in sources_block(t).split("<li")[1:]:
        link = re.search(r'<a href="([^"]+)"', item)
        if link:
            out.append(link.group(1))
    return out


def check():
    failures = []
    labels = ("h2", "pre", "svg", "table", "glossary", "checks",
              "citations", "anchors", "details")
    totals = {k: 0 for k in labels}
    for path in pages():
        rel = path.relative_to(ROOT).as_posix()
        rec = extract(path)
        a = audit(path)

        def compare(label, expected, actual):
            totals[label] = totals.get(label, 0) + len(expected)
            if len(expected) != len(actual):
                failures.append("%s: %s count %d extracted, %d in source"
                                % (rel, label, len(actual), len(expected)))
                return
            for i, (e, g) in enumerate(zip(expected, actual)):
                if e != g:
                    failures.append("%s: %s[%d] differs from source bytes"
                                    % (rel, label, i))

        compare("h2", a["h2"], [s["heading"] for s in rec["sections"]])
        compare("pre", a["pre"], rec["pre_blocks"])
        compare("svg", a["svg"], rec["svg_blocks"])
        compare("table", a["table"], rec["table_blocks"])
        compare("glossary", a["glossary"], [g["href"] for g in rec["glossary_links"]])
        compare("checks", sorted(a["checks"]), [c["id"] for c in rec["checks"]])
        compare("citations", a["citations"], [s["href"] for s in rec["sources"]])
        compare("anchors", a["anchors"], rec["source_anchors"])
        compare("details", a["details"], [q["html"] for q in rec["quiz"]])

        if len(a["severities"]) == len(a["checks"]):
            by_id = dict(zip(a["checks"], a["severities"]))
            for c in rec["checks"]:
                if by_id.get(c["id"]) != c["severity"]:
                    failures.append("%s: severity for %s is %s, source says %s"
                                    % (rel, c["id"], c["severity"], by_id.get(c["id"])))

        for field in ("title", "kicker", "reviewed", "lesson_key"):
            if not rec[field]:
                failures.append("%s: %s is empty" % (rel, field))

    print("extract_lessons --check")
    print("  pages                 %d" % len(pages()))
    for k in labels:
        print("  %-21s %d" % (k, totals[k]))
    if failures:
        print("\n%d problem(s):" % len(failures))
        for f in failures[:40]:
            print("  " + f)
        return 1
    print("\nall artifacts round-trip with identical bytes")
    return 0


def write():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    written = 0
    for path in pages():
        rec = extract(path)
        target = OUT_DIR / (rec["slug"] + ".json")
        target.write_text(json.dumps(rec, indent=2, ensure_ascii=False) + "\n",
                          encoding="utf-8")
        written += 1
    index = [{"slug": p.stem} for p in sorted(OUT_DIR.glob("*.json"))]
    (OUT_DIR.parent / "index.json").write_text(
        json.dumps(index, indent=2) + "\n", encoding="utf-8")
    print("wrote %d lesson files to %s" % (written, OUT_DIR.relative_to(ROOT)))
    return 0


def main():
    if "--check" in sys.argv[1:]:
        return check()
    return write()


if __name__ == "__main__":
    sys.exit(main())
