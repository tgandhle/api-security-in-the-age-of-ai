#!/usr/bin/env python3
"""Extract three of the five non-lesson pages into content/pages.json.

Standard library only.

tools/extract_lessons.py handles topics/ and protocols/, which all share the
same page template. The home page, glossary, checklist and roadmap do not:
index.html has its own layout inside <main id="main-content">, and
checklist/index.html is generated.

What this captures, and what it deliberately does not:

  home      the hero and overview prose, verbatim. NOT the module list: that
            is regenerated from content/index.json, so adding a module does
            not need the home page edited.
  glossary  the intro prose, then every term as a structured pair, so the
            app can render and search them rather than carry a blob of markup.
  roadmap   the body prose, verbatim.
  checklist nothing. All 215 items already live in content/lessons/*.json and
            the app builds the page from them, the same source
            tools/build_checklist.py uses.
  coverage  nothing. tools/build_coverage.py generates that page and writes
            content/coverage.json for the app.

Usage:
    python3 tools/extract_pages.py            # write content/pages.json
    python3 tools/extract_pages.py --check    # exit 1 if it is stale
"""

import html.parser
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
TARGET = ROOT / "content" / "pages.json"

VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link",
        "meta", "source", "track", "wbr"}


class Offsets(html.parser.HTMLParser):
    """Byte offsets for every non-void element, so slices are verbatim."""

    def __init__(self, text):
        super().__init__(convert_charrefs=False)
        self.text = text
        starts = [0]
        for line in text.splitlines(keepends=True):
            starts.append(starts[-1] + len(line))
        self.line_starts = starts
        self.open = []
        self.elements = []

    def _abs(self):
        line, col = self.getpos()
        return self.line_starts[line - 1] + col

    def handle_starttag(self, tag, attrs):
        if tag in VOID:
            return
        parent = self.open[-1][2] if self.open else None
        self.open.append((tag, dict(attrs), self._abs(), parent))

    def handle_startendtag(self, tag, attrs):
        return

    def handle_endtag(self, tag):
        for i in range(len(self.open) - 1, -1, -1):
            if self.open[i][0] == tag:
                name, attrs, start, parent = self.open.pop(i)
                del self.open[i:]
                end = self._abs() + len("</%s>" % tag)
                self.elements.append(
                    {"tag": name, "attrs": attrs, "start": start,
                     "end": end, "parent": parent})
                return

    def done(self):
        self.elements.sort(key=lambda e: e["start"])

    def outer(self, el):
        return self.text[el["start"]:el["end"]]

    def inner(self, el):
        open_end = self.text.index(">", el["start"]) + 1
        return self.text[open_end:el["end"] - len("</%s>" % el["tag"])]

    def first(self, tag, **match):
        for el in self.elements:
            if el["tag"] == tag and all(
                    el["attrs"].get(k) == v for k, v in match.items()):
                return el
        return None


def parse(rel):
    path = ROOT / rel
    text = path.read_text(encoding="utf-8")
    doc = Offsets(text)
    doc.feed(text)
    doc.close()
    doc.done()
    return text, doc


def content_blocks(rel, skip_tags=("nav", "footer")):
    """The page's content blocks, in order, minus the shared chrome.

    Every one of these pages wraps its content in <main>, including
    index.html, whose <main id="main-content"> I first missed by grepping for
    the bare tag. So take main's children where there is a main, and body's
    where there is not.
    """
    text, doc = parse(rel)
    container = doc.first("main") or doc.first("body")
    if container is None:
        raise ValueError("%s: no <main> and no <body>" % rel)
    out = []
    for el in doc.elements:
        if el["parent"] != container["start"] or el["tag"] in skip_tags:
            continue
        out.append({"tag": el["tag"], "attrs": el["attrs"],
                    "html": doc.outer(el)})
    return out


def home():
    blocks = content_blocks("index.html")
    # The module list is regenerated, so the captured prose stops at the
    # Modules heading. Everything after it is derived from content/index.json.
    kept = []
    for block in blocks:
        # Stop at the first part heading. The Modules h2 and the sentence
        # under it are prose and are kept; the lists below are generated.
        if block["tag"] == "h3":
            break
        kept.append(block)
    return {"blocks": kept}


def glossary():
    text, doc = parse("glossary/index.html")
    main = doc.first("main")
    dl = doc.first("dl")
    intro = text[text.index(">", main["start"]) + 1:dl["start"]].strip()
    terms = []
    pending = None
    for el in doc.elements:
        if el["tag"] == "dt" and "id" in el["attrs"]:
            pending = {"id": el["attrs"]["id"], "term": doc.inner(el)}
        elif el["tag"] == "dd" and pending is not None:
            pending["definition"] = doc.inner(el)
            terms.append(pending)
            pending = None
    return {"intro": intro, "terms": terms}


def roadmap():
    return {"blocks": content_blocks("roadmap/index.html")}


def build():
    return {"home": home(), "glossary": glossary(), "roadmap": roadmap()}


def serialize(value):
    return json.dumps(value, indent=2, ensure_ascii=False) + "\n"


def report(data):
    print("  home blocks           %d" % len(data["home"]["blocks"]))
    print("  glossary terms        %d" % len(data["glossary"]["terms"]))
    print("  roadmap blocks        %d" % len(data["roadmap"]["blocks"]))


def check():
    data = build()
    print("extract_pages --check")
    report(data)
    problems = []
    if len(data["glossary"]["terms"]) < 50:
        problems.append("only %d glossary terms, expected the full list"
                        % len(data["glossary"]["terms"]))
    for term in data["glossary"]["terms"]:
        if not term.get("definition"):
            problems.append("glossary term %s has no definition" % term["id"])
    ids = [t["id"] for t in data["glossary"]["terms"]]
    if ids != sorted(ids):
        problems.append("glossary terms are not in alphabetical order")
    if not TARGET.is_file():
        problems.append("content/pages.json is missing")
    elif TARGET.read_text(encoding="utf-8") != serialize(data):
        problems.append("content/pages.json is out of date")
    if problems:
        print("\n%d problem(s): run python3 tools/extract_pages.py"
              % len(problems))
        for p in problems[:10]:
            print("  " + p)
        return 1
    print("\ncontent/pages.json matches the published pages")
    return 0


def write():
    data = build()
    TARGET.parent.mkdir(parents=True, exist_ok=True)
    TARGET.write_text(serialize(data), encoding="utf-8")
    print("wrote content/pages.json")
    report(data)
    return 0


def main():
    if "--check" in sys.argv[1:]:
        return check()
    return write()


if __name__ == "__main__":
    sys.exit(main())
