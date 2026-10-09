#!/usr/bin/env python3
"""Check that every lesson was reviewed recently enough.

Usage:
  python3 tools/check_review_dates.py             warn about stale lessons, exit 0
  python3 tools/check_review_dates.py --strict    exit 1 if any lesson is stale
  python3 tools/check_review_dates.py --today 2026-12-31   pretend today is that date

Standard library only. Reads the "Last reviewed YYYY-MM-DD" line on each
lesson page, which is the source of truth, and compares its age in days with
the review cadence in CONVENTIONS.md:

  - every lesson: at most 92 days (quarterly);
  - the MCP and A2A lessons: at most 31 days (monthly). A new release of
    either specification also calls for a review, which a date cannot show.

Both modes exit 1 if a lesson has no review date, more than one, or a date in
the future, because those are mistakes in the page rather than the passage of
time.

Why two modes. The age of a date changes with the calendar, so the same commit
can pass today and fail next month. pages.yml uses the warning mode, so a
stale lesson elsewhere does not stop an unrelated fix from publishing.
release.yml (through tools/release_evidence.py) and the daily
.github/workflows/freshness.yml use --strict, so no release ships with a stale
review, and a lesson that goes stale is reported within a day.
"""
import datetime
import os
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
PAGES = sorted(ROOT.glob("topics/*/index.html"))
DEFAULT_LIMIT = 92
# Lesson directories under topics/ that CONVENTIONS.md puts on a monthly cadence.
MONTHLY = {"mcp-server-authorization": 31, "agent-to-agent": 31}
DATE = re.compile(r"Last reviewed (\d{4}-\d{2}-\d{2})")


def today():
    if "--today" in sys.argv:
        return datetime.date.fromisoformat(sys.argv[sys.argv.index("--today") + 1])
    return datetime.datetime.now(datetime.timezone.utc).date()


def main():
    strict = "--strict" in sys.argv
    now = today()
    annotate = os.environ.get("GITHUB_ACTIONS") == "true"
    broken, stale, oldest = [], [], None
    for page in PAGES:
        slug = page.parent.name
        rel = page.relative_to(ROOT).as_posix()
        found = DATE.findall(page.read_text(encoding="utf-8"))
        if len(found) != 1:
            broken.append(f"{rel}: {len(found)} 'Last reviewed' dates, expected exactly one")
            continue
        try:
            reviewed = datetime.date.fromisoformat(found[0])
        except ValueError:
            broken.append(f"{rel}: 'Last reviewed {found[0]}' is not a valid date")
            continue
        age = (now - reviewed).days
        if age < 0:
            broken.append(f"{rel}: reviewed {reviewed}, which is after today ({now})")
            continue
        limit = MONTHLY.get(slug, DEFAULT_LIMIT)
        if oldest is None or age > oldest[0]:
            oldest = (age, slug)
        if age > limit:
            stale.append((rel, reviewed, age, limit))

    for problem in broken:
        print(("::error::" if annotate else "") + problem)
    for rel, reviewed, age, limit in stale:
        message = (f"{rel}: last reviewed {reviewed}, {age} days ago; "
                   f"the limit for this lesson is {limit} days")
        level = "error" if strict else "warning"
        print((f"::{level} file={rel}::" if annotate else "") + message)

    if broken or (strict and stale):
        print(f"{len(broken) + (len(stale) if strict else 0)} problem(s) "
              f"in {len(PAGES)} lessons, checked against {now}")
        return 1
    if stale:
        print(f"{len(stale)} of {len(PAGES)} lessons are past their review date "
              f"(warning only; --strict fails on this), checked against {now}")
        return 0
    print(f"all {len(PAGES)} lessons are within their review limits on {now}; "
          f"oldest review {oldest[0]} days ({oldest[1]})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
