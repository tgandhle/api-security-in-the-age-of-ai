#!/usr/bin/env python3
"""Extract published lessons from HTML into structured JSON, losslessly.

Standard library only. Reads the same page set as tools/build_checklist.py:
topics/*/index.html and protocols/*/index.html.

Why this exists: a front end that re-types lesson content loses it. The
react-poc migration of module 1 dropped 7 of 12 sections, all 8 glossary
links, all 3 sources and 13 of 20 lab transcript lines. This extractor never
re-types anything. It records byte offsets into the source file and slices
the original text, so every block it emits is verbatim by construction.

The record partitions the whole page. Every byte of the source file belongs
to exactly one field, so `render()` reassembles the published page from the
JSON alone. That is the property a front end needs: anything the data cannot
reproduce is something a human would have to retype.

Fields:
  prologue, nav, main_open, blocks[], main_close, footer, epilogue
      the partition. Concatenated in that order they are the source file.
  page_title, lesson_key, title, kicker, reviewed, sections, layers,
  pre_blocks, svg_blocks, table_blocks, glossary_links, checks, sources,
  source_anchors, quiz
      views over the same bytes, for a renderer that wants them by name.

Usage:
    python3 tools/extract_lessons.py            # write content/lessons/*.json
    python3 tools/extract_lessons.py --check    # verify, write nothing, exit 1 on loss

--check does two independent things:
  1. rebuilds each page from its record and compares it to the source byte
     for byte, which proves the partition is exhaustive;
  2. re-reads each source page with a separate set of regexes and asserts
     every countable artifact appears in the record with identical bytes,
     which proves the named views agree with the page. A bug shared by both
     readings would have to be written twice.
"""

import html.parser
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT_DIR = ROOT / "content" / "lessons"

VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link",
        "meta", "source", "track", "wbr"}

PARTITION = ("prologue", "nav", "main_open", "blocks", "main_close",
             "footer", "epilogue")


def pages():
    return sorted(ROOT.glob("topics/*/index.html")) + \
           sorted(ROOT.glob("protocols/*/index.html"))


class Element:
    __slots__ = ("tag", "attrs", "start", "end", "parent")

    def __init__(self, tag, attrs, start, parent):
        self.tag, self.attrs, self.start, self.parent = tag, attrs, start, parent
        self.end = None


class Offsets(html.parser.HTMLParser):
    """Records byte offsets for every non-void element, with its parent."""

    def __init__(self, text):
        super().__init__(convert_charrefs=False)
        self.text = text
        starts = [0]
        for line in text.splitlines(keepends=True):
            starts.append(starts[-1] + len(line))
        self.line_starts = starts
        self.open = []
        self.elements = []
        self.unclosed = []

    def _abs(self):
        line, col = self.getpos()
        return self.line_starts[line - 1] + col

    def handle_starttag(self, tag, attrs):
        if tag in VOID:
            return
        parent = self.open[-1].start if self.open else None
        el = Element(tag, dict(attrs), self._abs(), parent)
        self.open.append(el)

    def handle_startendtag(self, tag, attrs):
        return  # self-closing, contributes no container

    def handle_endtag(self, tag):
        for i in range(len(self.open) - 1, -1, -1):
            if self.open[i].tag == tag:
                el = self.open.pop(i)
                # Anything still open inside it was never closed.
                self.unclosed.extend(e.tag for e in self.open[i:])
                del self.open[i:]
                el.end = self._abs() + len("</%s>" % tag)
                self.elements.append(el)
                return

    def done(self):
        self.unclosed.extend(e.tag for e in self.open)
        self.elements.sort(key=lambda e: e.start)

    def outer(self, el):
        return self.text[el.start:el.end]

    def inner(self, el):
        open_end = self.text.index(">", el.start) + 1
        return self.text[open_end:el.end - len("</%s>" % el.tag)]

    def find(self, tag, **attr_match):
        return [e for e in self.elements
                if e.tag == tag
                and all(e.attrs.get(k) == v for k, v in attr_match.items())]

    def first(self, tag, **attr_match):
        found = self.find(tag, **attr_match)
        return found[0] if found else None

    def children_of(self, el):
        return [e for e in self.elements if e.parent == el.start]


def text_of(fragment):
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", fragment)).strip()


def parse(path):
    text = path.read_text(encoding="utf-8")
    doc = Offsets(text)
    doc.feed(text)
    doc.close()
    doc.done()
    if doc.unclosed:
        raise ValueError("%s: unclosed tags, offsets are unreliable: %s"
                         % (path, sorted(set(doc.unclosed))))
    return text, doc


def extract(path):
    text, doc = parse(path)

    body = doc.first("body")
    nav = doc.first("nav")
    main = doc.first("main")
    footer = doc.first("footer")
    for name, el in (("body", body), ("nav", nav), ("main", main),
                     ("footer", footer)):
        if el is None:
            raise ValueError("%s: no <%s>" % (path, name))

    body_open_end = text.index(">", body.start) + 1
    main_open_end = text.index(">", main.start) + 1

    record = {
        "slug": path.parent.name,
        "source": path.relative_to(ROOT).as_posix(),
        "kind": path.relative_to(ROOT).parts[0],
    }

    # --- the partition -----------------------------------------------------
    record["prologue"] = text[:body_open_end]
    record["nav"] = text[body_open_end:nav.end]
    record["main_open"] = text[nav.end:main_open_end]

    blocks = []
    cursor = main_open_end
    for child in sorted(doc.children_of(main), key=lambda e: e.start):
        blocks.append({
            "tag": child.tag,
            "attrs": child.attrs,
            # Includes any whitespace or text since the previous child, so
            # the concatenation is exact.
            "html": text[cursor:child.end],
        })
        cursor = child.end
    record["blocks"] = blocks
    record["main_close"] = text[cursor:main.end]
    record["footer"] = text[main.end:footer.end]
    record["epilogue"] = text[footer.end:]

    # --- named views over the same bytes ----------------------------------
    title_el = doc.first("title")
    record["page_title"] = doc.inner(title_el) if title_el else ""
    record["lesson_key"] = body.attrs.get("data-course-lesson", "")

    h1 = doc.first("h1")
    record["title"] = doc.inner(h1) if h1 else ""

    kicker = doc.first("p", **{"class": "kicker"})
    record["kicker"] = doc.inner(kicker) if kicker else ""

    meta = doc.first("p", **{"class": "meta"})
    found = re.search(r"Last reviewed (\d{4}-\d{2}-\d{2})",
                      text_of(doc.inner(meta)) if meta else "")
    record["reviewed"] = found.group(1) if found else ""

    status = doc.first("section", **{"class": "lesson-status"})
    record["lesson_status_html"] = doc.outer(status) if status else ""
    counted = re.search(r"Published lesson (\d+) of (\d+)",
                        record["lesson_status_html"])
    record["lesson_number"] = int(counted.group(1)) if counted else 0
    record["lesson_total"] = int(counted.group(2)) if counted else 0
    numbered = re.search(r"Module (\d+)", record["kicker"])
    record["module"] = int(numbered.group(1)) if numbered else -1

    # The intro prose: the prose div before the first h2. This is the
    # Objective and Before you start text. The first version of this tool
    # did not capture it.
    headings = doc.find("h2")
    first_h2 = min((e.start for e in headings), default=len(text))
    intro = [doc.outer(e) for e in doc.find("div", **{"class": "prose"})
             if e.end < first_h2]
    record["intro_prose"] = intro

    layers = doc.find("span", **{"class": "layer"})
    boundaries = sorted([e.start for e in headings] + [e.start for e in layers] +
                        [main.end])
    record["sections"] = [{
        "heading": doc.inner(el),
        "heading_text": text_of(doc.inner(el)),
        "html": text[el.end:min((b for b in boundaries if b >= el.end),
                                default=main.end)].strip(),
    } for el in sorted(headings, key=lambda e: e.start)]

    record["layers"] = [{"id": e.attrs.get("id", ""), "label": doc.inner(e)}
                        for e in sorted(layers, key=lambda e: e.start)]

    for tag in ("pre", "svg", "table"):
        record[tag + "_blocks"] = [doc.outer(e) for e in
                                   sorted(doc.find(tag), key=lambda e: e.start)]

    record["glossary_links"] = [
        {"href": e.attrs.get("href", ""), "text": text_of(doc.inner(e))}
        for e in sorted(doc.find("a"), key=lambda e: e.start)
        if "glossary/index.html#" in e.attrs.get("href", "")]

    checks = []
    for el in doc.elements:
        if el.tag != "li" or "data-check" not in el.attrs:
            continue
        inner = doc.inner(el)
        strong = re.search(r"<strong>(.*?)</strong>", inner, re.S)
        span = re.search(r"<span>(.*?)</span>", inner, re.S)
        checks.append({
            "id": el.attrs["data-check"],
            "severity": el.attrs.get("data-severity", "Medium"),
            "title": strong.group(1) if strong else "",
            "detail": span.group(1) if span else "",
        })
    record["checks"] = sorted(checks, key=lambda c: c["id"])

    # Citations sit under an h2 reading "Sources", followed by a list. Some
    # pages also give an entry an id="source-..." so Learn text can link back.
    sources = []
    sources_h2 = next((e for e in headings if text_of(doc.inner(e)) == "Sources"),
                      None)
    if sources_h2 is not None:
        after = [e for e in doc.find("ul") if e.start > sources_h2.end]
        if after:
            lst = min(after, key=lambda e: e.start)
            for el in sorted(doc.find("li"), key=lambda e: e.start):
                if lst.start < el.start and el.end <= lst.end:
                    inner = doc.inner(el)
                    link = re.search(r'<a href="([^"]+)"[^>]*>(.*?)</a>', inner, re.S)
                    sources.append({
                        "id": el.attrs.get("id", ""),
                        "href": link.group(1) if link else "",
                        "title": link.group(2) if link else "",
                        "html": inner,
                    })
    record["sources"] = sources
    record["source_anchors"] = sorted(
        e.attrs["id"] for e in doc.elements
        if e.attrs.get("id", "").startswith("source-"))

    record["quiz"] = []
    for el in sorted(doc.find("details"), key=lambda e: e.start):
        inner = doc.inner(el)
        summary = re.search(r"<summary>(.*?)</summary>", inner, re.S)
        record["quiz"].append({
            "summary": summary.group(1) if summary else "",
            "html": inner,
        })

    return record


def render(record):
    """Rebuild the published page from the record alone."""
    return (record["prologue"] + record["nav"] + record["main_open"]
            + "".join(b["html"] for b in record["blocks"])
            + record["main_close"] + record["footer"] + record["epilogue"])


# ---------------------------------------------------------------------------
# --check
# ---------------------------------------------------------------------------

def sources_block(t):
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


def audit(path):
    """A second reading of the same file, independent of the parser above."""
    t = path.read_text(encoding="utf-8")
    return {
        "h2": re.findall(r"<h2[^>]*>(.*?)</h2>", t, re.S),
        "pre": re.findall(r"<pre>.*?</pre>", t, re.S),
        "svg": re.findall(r"<svg\b.*?</svg>", t, re.S),
        "table": re.findall(r"<table>.*?</table>", t, re.S),
        "glossary": re.findall(r'href="([^"]*glossary/index\.html#[^"]*)"', t),
        "checks": re.findall(r'data-check="([^"]+)"', t),
        "severities": re.findall(
            r'data-check="[^"]+"\s+data-severity="([^"]+)"', t),
        "citations": sources_citations(t),
        "anchors": sorted(re.findall(r'id="(source-[^"]+)"', t)),
        "details": re.findall(r"<details>(.*?)</details>", t, re.S),
    }


LABELS = ("h2", "pre", "svg", "table", "glossary", "checks", "citations",
          "anchors", "details")


def check():
    failures = []
    records = {}
    totals = dict.fromkeys(LABELS, 0)
    rebuilt = 0
    block_count = 0
    for path in pages():
        rel = path.relative_to(ROOT).as_posix()
        source = path.read_text(encoding="utf-8")
        rec = extract(path)
        block_count += len(rec["blocks"])

        if render(rec) == source:
            rebuilt += 1
        else:
            out = render(rec)
            at = next((i for i in range(min(len(out), len(source)))
                       if out[i] != source[i]), min(len(out), len(source)))
            failures.append("%s: rebuild differs from source at byte %d "
                            "(rebuilt %d bytes, source %d)"
                            % (rel, at, len(out), len(source)))

        a = audit(path)

        def compare(label, expected, actual):
            totals[label] += len(expected)
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
        compare("glossary", a["glossary"],
                [g["href"] for g in rec["glossary_links"]])
        compare("checks", sorted(a["checks"]), [c["id"] for c in rec["checks"]])
        compare("citations", a["citations"], [s["href"] for s in rec["sources"]])
        compare("anchors", a["anchors"], rec["source_anchors"])
        compare("details", a["details"], [q["html"] for q in rec["quiz"]])

        if len(a["severities"]) == len(a["checks"]):
            by_id = dict(zip(a["checks"], a["severities"]))
            for c in rec["checks"]:
                if by_id.get(c["id"]) != c["severity"]:
                    failures.append("%s: severity for %s is %s, source says %s"
                                    % (rel, c["id"], c["severity"],
                                       by_id.get(c["id"])))

        for field in ("title", "kicker", "reviewed", "lesson_key"):
            if not rec[field]:
                failures.append("%s: %s is empty" % (rel, field))
        if not rec["intro_prose"]:
            failures.append("%s: no intro prose captured" % rel)
        records[rec["slug"]] = rec

    # The lesson number and denominator on each page must agree with the
    # course order published on index.html. Every module so far has needed
    # the denominator changed on all 26 pages at once, and this is what
    # catches a page that was missed.
    order = course_order()
    if sorted(order) != sorted(records):
        failures.append(
            "index.html lists %d lessons, %d lesson pages exist; only in one: %s"
            % (len(order), len(records),
               sorted(set(order) ^ set(records))))
    else:
        for i, slug in enumerate(order):
            rec = records[slug]
            if rec["lesson_number"] != i + 1:
                failures.append(
                    "%s: page says lesson %d, index.html puts it at %d"
                    % (rec["source"], rec["lesson_number"], i + 1))
            if rec["lesson_total"] != len(order):
                failures.append(
                    "%s: page says 'of %d', index.html lists %d lessons"
                    % (rec["source"], rec["lesson_total"], len(order)))

    total = len(pages())
    print("extract_lessons --check")
    print("  pages                 %d" % total)
    print("  rebuilt byte-identical %d of %d" % (rebuilt, total))
    print("  blocks in <main>      %d" % block_count)
    for k in LABELS:
        print("  %-21s %d" % (k, totals[k]))
    if failures:
        print("\n%d problem(s):" % len(failures))
        for f in failures[:40]:
            print("  " + f)
        return 1
    print("\nevery page rebuilds from its record byte for byte")
    return 0


def course_order():
    """The canonical lesson order, read from the course list on index.html.

    index.html is the published order, so it is the source of truth. Nothing
    here invents an order.
    """
    home = (ROOT / "index.html").read_text(encoding="utf-8")
    return re.findall(r'data-course-lesson="([^"]+)"', home)


def write():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    records = {}
    for path in pages():
        rec = extract(path)
        records[rec["slug"]] = rec
        (OUT_DIR / (rec["slug"] + ".json")).write_text(
            json.dumps(rec, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8")
    order = course_order()
    index = [{"slug": slug,
              "lesson_number": i + 1,
              "module": records[slug]["module"] if slug in records else -1,
              "title": records[slug]["title"] if slug in records else ""}
             for i, slug in enumerate(order)]
    (OUT_DIR.parent / "index.json").write_text(
        json.dumps({"total": len(order), "lessons": index},
                   indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("wrote %d lesson files to %s"
          % (len(records), OUT_DIR.relative_to(ROOT)))
    return 0


def main():
    if "--check" in sys.argv[1:]:
        return check()
    return write()


if __name__ == "__main__":
    sys.exit(main())
