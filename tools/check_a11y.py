"""Accessibility check for the published site.

This is an author tool. Learners never need it. The site is still plain HTML
that opens from a file, and the labs in modules 1, 2 and 4 still need nothing
beyond Python 3.

Runs axe-core against every published page in light and dark mode, at desktop
and mobile width, against the WCAG 2.0, 2.1 and 2.2 A and AA rule sets plus
axe's best-practice rules. Exits 1 if any page reports a violation.

Install once, from the project root:
    python3 -m pip install playwright==1.56.0
    python3 -m playwright install chromium
    npm install axe-core@4.13.0

On Windows use py -3 in place of python3.

Then:
    python3 tools/check_a11y.py          the static pages, opened from disk
    python3 tools/check_a11y.py --app    the React build in app/dist, which is
                                         what the hosted site serves

The build has its own theme. A choice the reader made with the switch is kept
in localStorage and wins; with no stored choice the page follows the system
setting. With --app each mode stores the matching theme before the page loads,
and the emulated system setting is the same one, so the two light modes check
the light theme as a reader who chose it gets it, and the two dark modes the
dark theme.

--app needs `npm run build` in app/ first and exits 1 if app/dist is missing.
It serves app/dist from 127.0.0.1 on a free port for the length of the run,
because the build's module script does not load from a file:// page, and
checking it without its script would check something no reader gets.

If the tooling is not installed the script says so and exits 0, so it never
blocks someone who only wants to read or edit a page. The definition of done in
AGENTS.md requires the author to run it and paste the real output, so a skip is
visible in the report rather than silent.

What this does not cover: screen reader behavior, zoom to 400 percent, reflow,
and anything needing human judgment. Automated rules catch a minority of real
accessibility problems. Passing this is a floor, not a conformance claim.
"""
import functools
import http.server
import os
import pathlib
import sys
import threading

ROOT = pathlib.Path(__file__).resolve().parent.parent
SKIP_DIRS = {".git", ".venv", "venv", "env", "__pycache__", "node_modules", "dist", "react-poc"}
TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa", "best-practice"]
MODES = [("light", 1280), ("dark", 1280), ("light", 390), ("dark", 390)]
THEME_KEY = "course-theme"  # the key app/src/ThemeToggle.jsx stores the theme under
INSTALL_HINT = "see the install commands at the top of tools/check_a11y.py"


def axe_source():
    """Return (javascript, path) for axe-core, or (None, None) if not found."""
    candidates = []
    env = os.environ.get("AXE_CORE_PATH")
    if env:
        candidates.append(pathlib.Path(env))
    candidates.append(ROOT / "node_modules" / "axe-core" / "axe.min.js")
    for candidate in candidates:
        if candidate.is_file():
            return candidate.read_text(encoding="utf-8"), candidate
    return None, None


def pages():
    for path in sorted(ROOT.rglob("*.html")):
        if not SKIP_DIRS & set(path.relative_to(ROOT).parts):
            yield path


def serve(directory):
    """Serve a folder on 127.0.0.1, on a port the system picks. Quietly."""
    class Quiet(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *args):
            pass
    handler = functools.partial(Quiet, directory=str(directory))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def main():
    app = "--app" in sys.argv
    dist = ROOT / "app" / "dist"
    if app and not (dist / "index.html").is_file():
        print("check_a11y --app: app/dist is missing. Run npm run build in app/ first.")
        return 1
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("check_a11y: playwright is not installed, skipped. " + INSTALL_HINT)
        return 0
    source, source_path = axe_source()
    if source is None:
        print("check_a11y: axe-core was not found, skipped. " + INSTALL_HINT)
        return 0

    if app:
        server = serve(dist)
        base = "http://127.0.0.1:%d/" % server.server_address[1]
        targets = sorted(dist.rglob("*.html"))
        address = lambda t: base + t.relative_to(dist).as_posix()
        label = lambda t: "app/dist/" + t.relative_to(dist).as_posix()
    else:
        server = None
        targets = list(pages())
        address = lambda t: t.as_uri()
        label = lambda t: t.relative_to(ROOT).as_posix()
    violations = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        for scheme, width in MODES:
            context = browser.new_context(viewport={"width": width, "height": 900},
                                          color_scheme=scheme)
            if app:
                # A stored choice wins over the system setting on the build:
                # app/prerender.js writes a script into <head> that reads this
                # key before first paint. Setting it here, before any page
                # script runs, tests the explicit theme. The emulated system
                # setting above is the same scheme, so the two never disagree.
                context.add_init_script(
                    "try { window.localStorage.setItem(%r, %r); } catch (e) {}"
                    % (THEME_KEY, scheme))
            page = context.new_page()
            for target in targets:
                page.goto(address(target), wait_until="networkidle" if app else "load")
                if app:
                    applied = page.evaluate("document.documentElement.getAttribute('data-theme')")
                    if applied != scheme:
                        violations.append("%s @%dpx %s: the page applied the %s theme, so this mode was not tested" % (
                            label(target), width, scheme, applied))
                        continue
                page.add_script_tag(content=source)
                result = page.evaluate(
                    "async (tags) => await axe.run(document, {runOnly: {type: 'tag', values: tags}})",
                    TAGS)
                for violation in result["violations"]:
                    selectors = [node["target"][0] for node in violation["nodes"]][:3]
                    violations.append("%s @%dpx %s: %s [%s] %d node(s) %s" % (
                        label(target), width, scheme,
                        violation["id"], violation["impact"], len(violation["nodes"]),
                        ", ".join(selectors)))
            context.close()
        browser.close()
    if server:
        server.shutdown()

    print("checked %d %s in %d modes using %s" % (
        len(targets), "pages of the React build" if app else "pages",
        len(MODES), source_path))
    if violations:
        print("%d violation(s):" % len(violations))
        for line in violations:
            print("  " + line)
        return 1
    print("no accessibility violations")
    return 0


if __name__ == "__main__":
    sys.exit(main())
