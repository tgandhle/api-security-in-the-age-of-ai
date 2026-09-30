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

On Windows use py -3 in place of python3; there is no python3 command on a
default Windows install.

Then:
    python3 tools/check_a11y.py

If the tooling is not installed the script says so and exits 0, so it never
blocks someone who only wants to read or edit a page. The definition of done in
AGENTS.md requires the author to run it and paste the real output, so a skip is
visible in the report rather than silent.

What this does not cover: screen reader behavior, zoom to 400 percent, reflow,
and anything needing human judgment. Automated rules catch a minority of real
accessibility problems. Passing this is a floor, not a conformance claim.
"""
import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SKIP_DIRS = {".git", "node_modules", "dist", "react-poc"}
TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa", "best-practice"]
MODES = [("light", 1280), ("dark", 1280), ("light", 390), ("dark", 390)]
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


def main():
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("check_a11y: playwright is not installed, skipped. " + INSTALL_HINT)
        return 0
    source, source_path = axe_source()
    if source is None:
        print("check_a11y: axe-core was not found, skipped. " + INSTALL_HINT)
        return 0

    targets = list(pages())
    violations = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        for scheme, width in MODES:
            context = browser.new_context(viewport={"width": width, "height": 900},
                                          color_scheme=scheme)
            page = context.new_page()
            for target in targets:
                page.goto(target.as_uri(), wait_until="load")
                page.add_script_tag(content=source)
                result = page.evaluate(
                    "async (tags) => await axe.run(document, {runOnly: {type: 'tag', values: tags}})",
                    TAGS)
                for violation in result["violations"]:
                    selectors = [node["target"][0] for node in violation["nodes"]][:3]
                    violations.append("%s @%dpx %s: %s [%s] %d node(s) %s" % (
                        target.relative_to(ROOT).as_posix(), width, scheme,
                        violation["id"], violation["impact"], len(violation["nodes"]),
                        ", ".join(selectors)))
            context.close()
        browser.close()

    print("checked %d pages in %d modes using %s" % (len(targets), len(MODES), source_path))
    if violations:
        print("%d violation(s):" % len(violations))
        for line in violations:
            print("  " + line)
        return 1
    print("no accessibility violations")
    return 0


if __name__ == "__main__":
    sys.exit(main())
