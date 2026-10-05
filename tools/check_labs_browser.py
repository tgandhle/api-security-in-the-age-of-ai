#!/usr/bin/env python3
"""Run every lab through the "Run this lab in your browser" button.

This is an author tool, like check_a11y.py. Learners never need it.

check_transcripts.py proves each published transcript matches the lab run by
Python on this machine. It says nothing about the button on the lesson page,
which runs the same lab under Pyodide in the reader's browser. That path has
failed in ways no other check saw: a package the runtime had to be asked to
load, a lab whose main() returns nothing, a lab that overflows the browser's
call stack. This tool presses the button on every lesson and reads the result.

For each lesson page of the React build it expects one of two things:
  - a button: after pressing it the panel must report exit code 0 and
    "matches the transcript published above: true";
  - no button and a stated reason: assets/course.js lists that lab in
    NOT_IN_BROWSER. The tool reads that list, so a lab that silently lost its
    button is a failure, not a pass.

Usage:
    python3 tools/check_labs_browser.py            serve app/dist and test it
    python3 tools/check_labs_browser.py --base URL test a site that is already
                                                   being served, for example
                                                   the hosted one (URL ends /)
    python3 tools/check_labs_browser.py --require  exit 1 instead of skipping
                                                   when the tooling is absent
    python3 tools/check_labs_browser.py --json F   also write the results to F

Needs playwright (see the install commands at the top of tools/check_a11y.py)
and, without --base, `npm run build` in app/ first. The page downloads the
Python runtime from the CDN named in assets/course.js, so the machine needs
network access to it; a run with no network fails every lab, which is the
truth about that run.

What this does not cover: any browser but the Chromium that Playwright
installs, and a slow or metered connection.
"""
import functools
import http.server
import json
import pathlib
import re
import sys
import threading

ROOT = pathlib.Path(__file__).resolve().parent.parent
DIST = ROOT / "app" / "dist"
COURSE_JS = ROOT / "assets" / "course.js"
PER_LAB_SECONDS = 240


def serve(directory):
    class Quiet(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *args):
            pass
    handler = functools.partial(Quiet, directory=str(directory))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def not_in_browser():
    """Lab file names assets/course.js says it does not offer in a browser."""
    text = COURSE_JS.read_text(encoding="utf-8")
    start = text.index("const NOT_IN_BROWSER = {")
    block = text[start:text.index("};", start)]
    return set(re.findall(r'^\s*"(\w+\.py)":', block, re.M))


def runtime_version():
    text = COURSE_JS.read_text(encoding="utf-8")
    found = re.search(r'PYODIDE_BASE = "[^"]*/pyodide/v([0-9.]+)/', text)
    return found.group(1) if found else "unknown"


def lessons():
    """Slug and lab file of each lesson, in course order, from index.html."""
    home = (ROOT / "index.html").read_text(encoding="utf-8")
    out = []
    for slug in re.findall(r'<li data-course-lesson="([^"]+)"', home):
        page = (ROOT / "topics" / slug / "index.html").read_text(encoding="utf-8")
        lab = re.search(r"\$ python3 labs/(\w+\.py)", page)
        out.append((slug, lab.group(1) if lab else None))
    return out


def run(base, on_context=None):
    """Press every button. Returns (rows, browser_version)."""
    from playwright.sync_api import sync_playwright
    skip = not_in_browser()
    rows = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        version = browser.version
        context = browser.new_context(viewport={"width": 1280, "height": 900})
        if on_context:
            on_context(context)
        page = context.new_page()
        for slug, lab in lessons():
            row = {"lesson": slug, "lab": lab, "result": "", "detail": ""}
            rows.append(row)
            if lab is None:
                row["result"] = "failed"
                row["detail"] = "the lesson page shows no lab transcript"
                continue
            page.goto(base + "topics/" + slug + "/index.html", wait_until="load")
            try:
                page.wait_for_selector(".lab-run", timeout=20000)
            except Exception:
                row["result"] = "failed"
                row["detail"] = "no lab panel appeared on the page"
                continue
            buttons = page.locator(".lab-run button")
            if buttons.count() == 0:
                if lab in skip:
                    row["result"] = "not offered"
                    row["detail"] = "listed in NOT_IN_BROWSER, reason shown on the page"
                else:
                    row["result"] = "failed"
                    row["detail"] = "no button, and the lab is not in NOT_IN_BROWSER"
                continue
            if lab in skip:
                row["result"] = "failed"
                row["detail"] = "listed in NOT_IN_BROWSER but the page offers a button"
                continue
            buttons.first.click()
            try:
                page.wait_for_function(
                    "() => { const o = document.querySelector('.lab-output');"
                    " const b = document.querySelector('.lab-run button');"
                    " return o && b && !b.disabled && (o.dataset.state === 'ok'"
                    " || o.dataset.state === 'bad'); }",
                    timeout=PER_LAB_SECONDS * 1000)
            except Exception:
                row["result"] = "failed"
                row["detail"] = "no result after %d seconds" % PER_LAB_SECONDS
                continue
            text = page.locator(".lab-output").text_content() or ""
            state = page.locator(".lab-output").get_attribute("data-state")
            code = re.search(r"exit code (\w+)", text)
            same = "matches the transcript published above: true" in text
            if state == "ok" and code and code.group(1) == "0" and same:
                row["result"] = "ran"
                row["detail"] = "exit code 0, matches the published transcript"
            else:
                row["result"] = "failed"
                row["detail"] = " ".join(text.split())[-200:]
        browser.close()
    return rows, version


def main():
    args = sys.argv[1:]
    require = "--require" in args
    base = args[args.index("--base") + 1] if "--base" in args else None
    out = args[args.index("--json") + 1] if "--json" in args else None
    try:
        import playwright  # noqa: F401
    except ImportError:
        print("check_labs_browser: playwright is not installed, skipped. "
              "See the install commands at the top of tools/check_a11y.py")
        return 1 if require else 0
    server = None
    if base is None:
        if not (DIST / "index.html").is_file():
            print("check_labs_browser: app/dist is missing. Run npm run build in app/ first.")
            return 1
        server = serve(DIST)
        base = "http://127.0.0.1:%d/" % server.server_address[1]
        where = "app/dist"
    else:
        where = base
    rows, browser_version = run(base)
    if server:
        server.shutdown()

    ran = [r for r in rows if r["result"] == "ran"]
    off = [r for r in rows if r["result"] == "not offered"]
    bad = [r for r in rows if r["result"] == "failed"]
    print("check_labs_browser")
    print("  site                        %s" % where)
    print("  browser                     Chromium %s" % browser_version)
    print("  Python runtime              Pyodide %s" % runtime_version())
    print("  lessons                     %d" % len(rows))
    print("  ran and matched             %d" % len(ran))
    print("  not offered, reason shown   %d" % len(off))
    print("  failed                      %d" % len(bad))
    for row in off:
        print("  not offered: %s (%s)" % (row["lab"], row["lesson"]))
    for row in bad:
        print("  FAILED: %s (%s): %s" % (row["lab"], row["lesson"], row["detail"]))
    if out:
        pathlib.Path(out).write_text(json.dumps({
            "site": where, "browser": "Chromium " + browser_version,
            "runtime": "Pyodide " + runtime_version(), "lessons": len(rows),
            "ran": len(ran), "not_offered": len(off), "failed": len(bad),
            "rows": rows}, indent=2) + "\n", encoding="utf-8")
    if bad:
        return 1
    print("\nevery lab offered in the browser ran and matched its transcript")
    return 0


if __name__ == "__main__":
    sys.exit(main())
