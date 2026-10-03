#!/usr/bin/env python3
"""Render the lesson pages from content/ through one shared template.

Standard library only.

Today the per-page skeleton is copied into all 27 lesson pages. Measured
with tools/extract_lessons.py, the copies are identical: the nav, the
<main> open and close, the footer and the closing tags have exactly one
distinct value across 27 pages, and the <head> varies only in <title> and
the body's data-course-lesson. The lesson-status line varies only in the
lesson number and the denominator.

So the skeleton is one file, tools/page_template.tmpl, and the numbering is
another, tools/lesson_status_template.tmpl. Changing the denominator, which
every module so far has needed, becomes one edit instead of 27.

Placeholders are substituted with str.replace, not str.format, because
lesson content contains braces.

Usage:
    python3 tools/render_site.py            # compare, write nothing
    python3 tools/render_site.py --write    # overwrite topics/<slug>/index.html

--write overwrites published pages, so it is not the default.
"""

import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
CONTENT = ROOT / "content"
PAGE_TEMPLATE = ROOT / "tools" / "page_template.tmpl"
STATUS_TEMPLATE = ROOT / "tools" / "lesson_status_template.tmpl"


def substitute(template, name, value, where):
    token = "{%s}" % name
    count = template.count(token)
    if count != 1:
        raise ValueError("%s: expected %s once, found %d times"
                         % (where, token, count))
    return template.replace(token, value)


def load():
    index = json.loads((CONTENT / "index.json").read_text(encoding="utf-8"))
    records = {}
    for entry in index["lessons"]:
        path = CONTENT / "lessons" / (entry["slug"] + ".json")
        if not path.is_file():
            raise ValueError("index.json lists %s, but %s is missing"
                             % (entry["slug"], path.relative_to(ROOT)))
        records[entry["slug"]] = json.loads(path.read_text(encoding="utf-8"))
    return index, records


def render(entry, record, shell, status_template):
    status = substitute(status_template, "lesson_number",
                        str(entry["lesson_number"]), "lesson status")
    status = substitute(status, "lesson_total", str(entry["total"]),
                        "lesson status")

    body = []
    seen_status = False
    for block in record["blocks"]:
        if block["attrs"].get("class") == "lesson-status":
            body.append(status)
            seen_status = True
        else:
            body.append(block["html"])
    if not seen_status:
        raise ValueError("%s: no lesson-status block" % entry["slug"])

    page = substitute(shell, "page_title", record["page_title"], "page shell")
    page = substitute(page, "lesson_key", record["lesson_key"], "page shell")
    return substitute(page, "blocks", "".join(body), "page shell")


def main():
    write = "--write" in sys.argv[1:]
    index, records = load()
    shell = PAGE_TEMPLATE.read_text(encoding="utf-8")
    status_template = STATUS_TEMPLATE.read_text(encoding="utf-8")

    identical = changed = 0
    differences = []
    for entry in index["lessons"]:
        entry = dict(entry, total=index["total"])
        record = records[entry["slug"]]
        target = ROOT / record["source"]
        out = render(entry, record, shell, status_template)
        current = target.read_text(encoding="utf-8") if target.is_file() else ""
        if out == current:
            identical += 1
            continue
        changed += 1
        at = next((i for i in range(min(len(out), len(current)))
                   if out[i] != current[i]), min(len(out), len(current)))
        differences.append("%s: rendered %d bytes, on disk %d, first differs at %d"
                           % (record["source"], len(out), len(current), at))
        if write:
            target.write_text(out, encoding="utf-8")

    print("render_site%s" % (" --write" if write else ""))
    print("  lessons                  %d" % len(index["lessons"]))
    print("  identical to disk        %d" % identical)
    print("  %-24s %d" % ("rewritten" if write else "would change", changed))
    for line in differences[:20]:
        print("  " + line)
    if changed and not write:
        return 1
    if not changed:
        print("\nthe template reproduces every published page byte for byte")
    return 0


if __name__ == "__main__":
    sys.exit(main())
