#!/usr/bin/env python3
"""Check that every published lab transcript matches a live run.

Standard library only.

CONVENTIONS.md says: "Every code sample and lab is run before publishing, and
the page shows the real output." Nothing enforced it. A lab could change and
its page keep the old transcript, and every other check would still pass.

This tool finds each <pre> block on a lesson page whose first line is a shell
prompt running a lab, runs that lab, and compares the rest of the block to the
real output byte for byte. <pre> blocks that are not lab invocations, such as
request and response examples, are counted and skipped.

A lab that needs a package it cannot import prints an install hint and exits
cleanly. That is reported as skipped, not as a mismatch, so the tool is usable
without the optional dependency.

Usage:
    python3 tools/check_transcripts.py
    python3 tools/check_transcripts.py --verbose   # show each transcript's verdict
"""

import html
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
LABS = ROOT / "labs"

# The form every page is supposed to use. README and 25 of 26 pages use it.
CANONICAL = re.compile(r"python3 (labs/\w+\.py)$")
# Also recognised, so a deviation is reported rather than silently skipped.
LOOSE = re.compile(r"(?:python3|py -3|python) ((?:labs/)?\w+\.py)$")

NEEDS_PACKAGE = "This lab needs the"


def pages():
    return sorted(ROOT.glob("topics/*/index.html")) + \
           sorted(ROOT.glob("protocols/*/index.html"))


def pre_blocks(text):
    for raw in re.findall(r"<pre>(.*?)</pre>", text, re.S):
        yield html.unescape(re.sub(r"<[^>]+>", "", raw)).strip()


def resolve(script):
    """A lab path as written in the transcript, resolved against the repo."""
    direct = ROOT / script
    if direct.is_file():
        return direct
    bare = LABS / pathlib.PurePosixPath(script).name
    if bare.is_file():
        return bare
    return None


def main():
    verbose = "--verbose" in sys.argv[1:]
    checked = identical = skipped_dep = 0
    not_a_lab = 0
    problems = []
    deviations = []

    for path in pages():
        rel = path.relative_to(ROOT).as_posix()
        text = path.read_text(encoding="utf-8")
        for i, block in enumerate(pre_blocks(text)):
            lines = block.splitlines()
            if not lines or not lines[0].startswith("$ "):
                not_a_lab += 1
                continue
            command = lines[0][2:].strip()
            published = "\n".join(lines[1:]).strip()

            loose = LOOSE.fullmatch(command)
            if loose is None:
                not_a_lab += 1
                continue
            if CANONICAL.fullmatch(command) is None:
                deviations.append(
                    "%s pre[%d]: command is '%s', the other pages and README "
                    "use 'python3 labs/<lab>.py'" % (rel, i, command))

            script = loose.group(1)
            lab = resolve(script)
            if lab is None:
                problems.append("%s pre[%d]: %s does not exist"
                                % (rel, i, script))
                continue

            run = subprocess.run([sys.executable, str(lab)],
                                 capture_output=True, text=True, cwd=ROOT)
            live = run.stdout.strip()
            checked += 1

            if NEEDS_PACKAGE in live and live != published:
                skipped_dep += 1
                if verbose:
                    print("  skipped (needs a package): %s" % script)
                continue

            if run.returncode != 0:
                problems.append("%s pre[%d]: %s exited %d"
                                % (rel, i, script, run.returncode))
                continue

            if live == published:
                identical += 1
                if verbose:
                    print("  identical: %-34s %d lines"
                          % (script, len(published.splitlines())))
            else:
                at = next((n for n, (a, b) in enumerate(
                    zip(published.splitlines(), live.splitlines()), 1) if a != b),
                    min(len(published.splitlines()), len(live.splitlines())) + 1)
                problems.append(
                    "%s pre[%d]: %s output differs from the published "
                    "transcript, first at line %d (published %d lines, live %d)"
                    % (rel, i, script, at, len(published.splitlines()),
                       len(live.splitlines())))

    print("check_transcripts")
    print("  pages                      %d" % len(pages()))
    print("  lab transcripts found      %d" % checked)
    print("  identical to a live run    %d" % identical)
    print("  skipped, needs a package   %d" % skipped_dep)
    print("  other <pre> blocks         %d" % not_a_lab)
    print("  command form deviations    %d" % len(deviations))

    for line in deviations:
        print("  " + line)
    if problems:
        print("\n%d problem(s):" % len(problems))
        for line in problems[:20]:
            print("  " + line)
    if problems or deviations:
        return 1

    # Never claim more than was actually run. A skipped lab was not checked,
    # so the summary says so rather than folding it into a pass, the same way
    # check_a11y.py reports a skip instead of claiming no violations.
    if skipped_dep:
        print("\n%d of %d published lab transcripts match a live run."
              % (identical, checked))
        print("%d were not checked, because the lab needs a package that is "
              "not installed here." % skipped_dep)
        print("Install it with the command the lab prints, then run this "
              "again to cover them.")
    else:
        print("\nall %d published lab transcripts match a live run" % identical)
    return 0


if __name__ == "__main__":
    sys.exit(main())
