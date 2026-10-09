#!/usr/bin/env python3
"""Run every check and write down what was run, on what, and what it said.

This is a release tool. The release workflow runs it for a tag and attaches
what it writes to the release. It can also be run by hand.

It writes two files into the output folder (default: evidence/, which is not
tracked):
  evidence.json   the same facts for a program
  evidence.md     the same facts for a person

The record says which commit was checked, on what system, with which
versions of Python, the browser, the in-browser Python runtime and each
package, how many tests ran, how many were skipped, what each check printed
last, and the oldest and newest "Last reviewed" date on the lesson pages.

It is a record of one run. It is not a certification, and it says nothing
about any later commit. The checks it runs have the limits their own
docstrings state: automated accessibility rules catch a minority of real
problems, and the browser run covers one browser.

Usage:
    python3 tools/release_evidence.py [--out DIR]

Needs everything the checks need: `npm run build` in app/ first, the packages
in tools/requirements-release.txt, a Chromium installed by Playwright, and
axe-core (see tools/check_a11y.py). Nothing is skipped quietly: a check that
cannot run fails, and the record shows it. Exits 1 if any check failed, after
writing the record, so a failed run still leaves its evidence.
"""
import datetime
import json
import os
import pathlib
import platform
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
PY = sys.executable

CHECKS = [
    ("pages, links, dashes, secrets", ["tools/check_site.py"]),
    ("content matches the pages", ["tools/extract_lessons.py", "--check"]),
    ("template reproduces the pages", ["tools/render_site.py"]),
    ("other pages match", ["tools/extract_pages.py", "--check"]),
    ("search index is current", ["tools/build_search_index.py", "--check"]),
    ("lab bundles are current", ["tools/build_lab_bundles.py", "--check"]),
    ("checklist is current", ["tools/build_checklist.py", "--check"]),
    ("coverage page is current", ["tools/build_coverage.py", "--check"]),
    ("checklist applicability data is valid", ["tools/check_applicability.py"]),
    ("every lesson is within its review limit", ["tools/check_review_dates.py", "--strict"]),
    ("lab transcripts match a live run", ["tools/check_transcripts.py", "--no-skips"]),
    ("accessibility, static pages", ["tools/check_a11y.py", "--require"]),
    ("accessibility, built site", ["tools/check_a11y.py", "--app", "--require"]),
    ("labs run in the browser", ["tools/check_labs_browser.py", "--require", "--json", "{out}/labs-browser.json"]),
]


def sh(args):
    try:
        return subprocess.run(args, capture_output=True, text=True, cwd=ROOT).stdout.strip()
    except OSError:
        return ""


def package_version(name):
    try:
        from importlib import metadata
        return metadata.version(name)
    except Exception:
        return "not installed"


def axe_version():
    candidates = []
    env = os.environ.get("AXE_CORE_PATH")
    if env:
        candidates.append(pathlib.Path(env).parent / "package.json")
    candidates.append(ROOT / "node_modules" / "axe-core" / "package.json")
    for candidate in candidates:
        if candidate.is_file():
            return json.loads(candidate.read_text(encoding="utf-8")).get("version", "unknown")
    return "not installed"


def reviewed_dates():
    dates = {}
    for page in sorted(ROOT.glob("topics/*/index.html")):
        found = re.search(r"Last reviewed (\d{4}-\d\d-\d\d)", page.read_text(encoding="utf-8"))
        if found:
            dates[page.parent.name] = found.group(1)
    return dates


def course_counts():
    lessons = sorted(ROOT.glob("topics/*/index.html"))
    checks = sum(len(re.findall(r"<li data-check=", p.read_text(encoding="utf-8"))) for p in lessons)
    glossary = (ROOT / "glossary" / "index.html").read_text(encoding="utf-8")
    return {
        "lessons": len(lessons),
        "labs": len(list((ROOT / "labs").glob("*_lab.py"))),
        "checklist_items": checks,
        "glossary_terms": len(re.findall(r"<dt id=", glossary)),
    }


def main():
    args = sys.argv[1:]
    out = pathlib.Path(args[args.index("--out") + 1]) if "--out" in args else ROOT / "evidence"
    out.mkdir(parents=True, exist_ok=True)

    results = []
    for name, command in CHECKS:
        command = [part.replace("{out}", str(out)) for part in command]
        print("running: %s" % " ".join(command), flush=True)
        run = subprocess.run([PY] + command, capture_output=True, text=True, cwd=ROOT)
        lines = [line for line in (run.stdout + run.stderr).splitlines() if line.strip()]
        results.append({
            "check": name,
            "command": "python " + " ".join(c if not c.startswith(str(out)) else "<out>/" + pathlib.Path(c).name
                                            for c in command),
            "exit_code": run.returncode,
            "last_line": lines[-1] if lines else "",
            "output": "\n".join(lines[-40:]),
        })
        print("  exit %d: %s" % (run.returncode, results[-1]["last_line"]), flush=True)

    by_name = {r["check"]: r for r in results}
    transcripts = by_name["lab transcripts match a live run"]["output"]

    def number(label):
        found = re.search(re.escape(label) + r"\s+(\d+)", transcripts)
        return int(found.group(1)) if found else None

    labs_file = out / "labs-browser.json"
    labs = json.loads(labs_file.read_text(encoding="utf-8")) if labs_file.is_file() else {}

    dates = reviewed_dates()
    app_pkg = json.loads((ROOT / "app" / "package.json").read_text(encoding="utf-8"))
    env = os.environ
    run_url = ""
    if env.get("GITHUB_RUN_ID"):
        run_url = "%s/%s/actions/runs/%s" % (env.get("GITHUB_SERVER_URL", ""),
                                             env.get("GITHUB_REPOSITORY", ""), env["GITHUB_RUN_ID"])
    record = {
        "what_this_is": "A record of one run of the project's checks against one commit. "
                        "Not a certification, and not a statement about any other commit.",
        "commit": sh(["git", "rev-parse", "HEAD"]),
        "ref": env.get("GITHUB_REF_NAME", sh(["git", "rev-parse", "--abbrev-ref", "HEAD"])),
        "working_tree_clean": sh(["git", "status", "--porcelain", "--untracked-files=no"]) == "",
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "workflow_run": run_url,
        "system": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "node": sh(["node", "--version"]),
            "browser": labs.get("browser", "unknown"),
            "in_browser_python": labs.get("runtime", "unknown"),
        },
        "packages": {
            "cryptography": package_version("cryptography"),
            "cffi": package_version("cffi"),
            "playwright": package_version("playwright"),
            "axe-core": axe_version(),
            "app": dict(sorted({**app_pkg.get("dependencies", {}), **app_pkg.get("devDependencies", {})}.items())),
        },
        "course": course_counts(),
        "tests": {
            "checks_run": len(results),
            "checks_failed": sum(1 for r in results if r["exit_code"] != 0),
            "lab_transcripts_found": number("lab transcripts found"),
            "lab_transcripts_identical": number("identical to a live run"),
            "lab_transcripts_skipped": number("skipped, needs a package"),
            "accessibility_static": by_name["accessibility, static pages"]["last_line"],
            "accessibility_built_site": by_name["accessibility, built site"]["last_line"],
            "labs_in_browser_ran": labs.get("ran"),
            "labs_in_browser_not_offered": labs.get("not_offered"),
            "labs_in_browser_failed": labs.get("failed"),
        },
        "standards_review": {
            "note": "Each lesson page carries the date its sources were last checked against the page.",
            "oldest_last_reviewed": min(dates.values()) if dates else None,
            "newest_last_reviewed": max(dates.values()) if dates else None,
            "lessons_by_date": {d: sum(1 for v in dates.values() if v == d) for d in sorted(set(dates.values()))},
        },
        "checks": results,
    }
    (out / "evidence.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")

    t, s, p, c, sr = record["tests"], record["system"], record["packages"], record["course"], record["standards_review"]
    failed = [r for r in results if r["exit_code"] != 0]
    md = ["# Release evidence", "",
          record["what_this_is"], "",
          "| | |", "|---|---|",
          "| Commit | `%s` |" % record["commit"],
          "| Ref | %s |" % record["ref"],
          "| Working tree clean | %s |" % ("yes" if record["working_tree_clean"] else "no"),
          "| Generated (UTC) | %s |" % record["generated_utc"],
          "| Workflow run | %s |" % (run_url or "not run in a workflow"),
          "| Result | %s |" % ("all %d checks passed" % len(results) if not failed
                               else "%d of %d checks FAILED" % (len(failed), len(results))),
          "", "## System", "", "| | |", "|---|---|",
          "| Platform | %s |" % s["platform"], "| Python | %s |" % s["python"], "| Node | %s |" % s["node"],
          "| Browser | %s |" % s["browser"], "| Python runtime in the browser | %s |" % s["in_browser_python"],
          "| cryptography | %s |" % p["cryptography"], "| cffi | %s |" % p["cffi"],
          "| playwright | %s |" % p["playwright"], "| axe-core | %s |" % p["axe-core"],
          "| App packages | %s |" % ", ".join("%s %s" % kv for kv in p["app"].items()),
          "", "## Course", "", "| | |", "|---|---|",
          "| Lessons | %d |" % c["lessons"], "| Labs | %d |" % c["labs"],
          "| Review checklist items | %d |" % c["checklist_items"], "| Glossary terms | %d |" % c["glossary_terms"],
          "", "## Tests", "", "| | |", "|---|---|",
          "| Checks run | %d |" % t["checks_run"], "| Checks failed | %d |" % t["checks_failed"],
          "| Lab transcripts found | %s |" % t["lab_transcripts_found"],
          "| Identical to a live run | %s |" % t["lab_transcripts_identical"],
          "| Skipped | %s |" % t["lab_transcripts_skipped"],
          "| Accessibility, static pages | %s |" % t["accessibility_static"],
          "| Accessibility, built site | %s |" % t["accessibility_built_site"],
          "| Labs run in the browser | %s ran, %s not offered, %s failed |" % (
              t["labs_in_browser_ran"], t["labs_in_browser_not_offered"], t["labs_in_browser_failed"]),
          "", "## Standards review", "", sr["note"], "", "| | |", "|---|---|",
          "| Oldest \"Last reviewed\" | %s |" % sr["oldest_last_reviewed"],
          "| Newest \"Last reviewed\" | %s |" % sr["newest_last_reviewed"]]
    md += ["| Lessons reviewed %s | %d |" % kv for kv in sr["lessons_by_date"].items()]
    md += ["", "## Each check", "", "| Check | Command | Exit | Last line |", "|---|---|---|---|"]
    md += ["| %s | `%s` | %d | %s |" % (r["check"], r["command"], r["exit_code"], r["last_line"].replace("|", "/"))
           for r in results]
    md += ["", "## What this does not cover", "",
           "- Any browser other than the one named above.",
           "- Screen readers, zoom, reflow and anything that needs a person's judgment. "
           "Automated accessibility rules catch a minority of real problems.",
           "- Whether the sources a lesson cites have changed since its \"Last reviewed\" date.",
           "- Any commit other than the one named above.", ""]
    (out / "evidence.md").write_text("\n".join(md), encoding="utf-8")

    print("\nwrote %s and %s" % ((out / "evidence.json").relative_to(ROOT) if out.is_relative_to(ROOT) else out / "evidence.json",
                                 (out / "evidence.md").relative_to(ROOT) if out.is_relative_to(ROOT) else out / "evidence.md"))
    if failed:
        print("%d of %d checks failed" % (len(failed), len(results)))
        return 1
    print("all %d checks passed" % len(results))
    return 0


if __name__ == "__main__":
    sys.exit(main())
