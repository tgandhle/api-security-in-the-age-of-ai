#!/usr/bin/env python3
"""Generate coverage/index.html: which lesson cites each OWASP entry.

Usage:
  python3 tools/build_coverage.py          rewrite coverage/index.html and
                                           content/coverage.json
                                           (the same table as data, and
                                           the page body for app/ to render)
  python3 tools/build_coverage.py --check  exit 1 if either is out of date,
                                           or if the coverage rules fail

Standard library only.

The three lists and their entry names are fixed below, copied from the
editions the course pins. Which lessons cite an entry is not written here: it
is read from the lesson pages, by searching each one for the entry's id. So
the page cannot claim a lesson covers an entry that the lesson never cites.

Citing is a low bar. A lesson that names an entry once, in passing, is listed
next to one that is built around it. The page says so.

The rules --check enforces, beyond freshness:
  - every entry is cited by at least one lesson, or is listed in NOT_COVERED
    with the reason;
  - an entry listed in NOT_COVERED is cited by no lesson, so the reason is
    removed when a lesson starts to cite it.
"""
import html
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "coverage" / "index.html"
DATA = ROOT / "content" / "coverage.json"

LISTS = [
    {
        "key": "api",
        "title": "OWASP API Security Top 10 2023",
        "href": "https://api-security.owasp.org/editions/2023/en/0x11-t10/",
        "edition": "2023 edition, the newest.",
        "pattern": r"\b%s:2023\b",
        "entries": [
            ("API1", "API1:2023", "Broken Object Level Authorization"),
            ("API2", "API2:2023", "Broken Authentication"),
            ("API3", "API3:2023", "Broken Object Property Level Authorization"),
            ("API4", "API4:2023", "Unrestricted Resource Consumption"),
            ("API5", "API5:2023", "Broken Function Level Authorization"),
            ("API6", "API6:2023", "Unrestricted Access to Sensitive Business Flows"),
            ("API7", "API7:2023", "Server Side Request Forgery"),
            ("API8", "API8:2023", "Security Misconfiguration"),
            ("API9", "API9:2023", "Improper Inventory Management"),
            ("API10", "API10:2023", "Unsafe Consumption of APIs"),
        ],
    },
    {
        "key": "llm",
        "title": "OWASP GenAI LLM Top 10 2026",
        "href": "https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/",
        "edition": "Version 2026, August 2026. The title page of the document "
                   "reads \"OWASP Top 10 for LLM Applications 2026\".",
        "pattern": r"\b%s:2026\b",
        "entries": [
            ("LLM01", "LLM01:2026", "Prompt Injection"),
            ("LLM02", "LLM02:2026", "Sensitive Information Disclosure"),
            ("LLM03", "LLM03:2026", "Excessive Agency"),
            ("LLM04", "LLM04:2026", "Supply Chain"),
            ("LLM05", "LLM05:2026", "Data and Model Poisoning"),
            ("LLM06", "LLM06:2026", "Unbounded Consumption"),
            ("LLM07", "LLM07:2026", "Misinformation"),
            ("LLM08", "LLM08:2026", "Hidden Context Exposure"),
            ("LLM09", "LLM09:2026", "Vector and Embedding Weaknesses"),
            ("LLM10", "LLM10:2026", "Improper Output Handling"),
        ],
    },
    {
        "key": "agentic",
        "title": "OWASP Top 10 for Agentic Applications for 2026",
        "href": "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",
        "edition": "Version 2026, released 9 December 2025.",
        "pattern": r"\b%s\b",
        "entries": [
            ("ASI01", "ASI01", "Agent Goal Hijack"),
            ("ASI02", "ASI02", "Tool Misuse and Exploitation"),
            ("ASI03", "ASI03", "Identity and Privilege Abuse"),
            ("ASI04", "ASI04", "Agentic Supply Chain Vulnerabilities"),
            ("ASI05", "ASI05", "Unexpected Code Execution (RCE)"),
            ("ASI06", "ASI06", "Memory & Context Poisoning"),
            ("ASI07", "ASI07", "Insecure Inter-Agent Communication"),
            ("ASI08", "ASI08", "Cascading Failures"),
            ("ASI09", "ASI09", "Human-Agent Trust Exploitation"),
            ("ASI10", "ASI10", "Rogue Agents"),
        ],
    },
]

# An entry no lesson teaches, and why. --check fails if a lesson cites one.
NOT_COVERED = {
    "LLM07:2026": "No lesson covers this entry. It is about model output that "
                  "is incorrect or misleading and is trusted anyway. This "
                  "course teaches the controls around a model (what its output "
                  "may do, who approves it, what it can reach), not how to make "
                  "its answers correct.",
}

# A caveat on an entry that is cited. Shown under the lessons.
NOTES = {
    "LLM04:2026": "Module 32 teaches the entry: models, adapters, converted "
                  "files and packages taken in from outside. Module 25 "
                  "teaches the data side only. On-device models are named "
                  "in module 32 and not taught.",
}

LESSON = re.compile(
    r'<li data-course-lesson="([^"]+)"[^>]*><span class="num">(\d+)</span>'
    r'<span><a href="([^"]+)">(.*?)</a>')


def lessons():
    """Slug, module number, link and title, in the order index.html gives."""
    text = (ROOT / "index.html").read_text(encoding="utf-8")
    found = []
    for slug, num, href, title in LESSON.findall(text):
        page = ROOT / href
        found.append({"slug": slug, "number": int(num), "href": href,
                      "title": html.unescape(title),
                      "text": page.read_text(encoding="utf-8")})
    if not found:
        sys.exit("no lessons found in index.html")
    return found


def collect():
    course = lessons()
    problems = []
    lists = []
    for spec in LISTS:
        rows = []
        for short, ident, name in spec["entries"]:
            pattern = re.compile(spec["pattern"] % re.escape(short))
            cited = [{"number": l["number"], "title": l["title"],
                      "href": l["href"]}
                     for l in course if pattern.search(l["text"])]
            if ident in NOT_COVERED and cited:
                problems.append(
                    "%s is listed as not covered but is cited by: %s"
                    % (ident, ", ".join(c["title"] for c in cited)))
            if ident not in NOT_COVERED and not cited:
                problems.append(
                    "%s %s is cited by no lesson and has no reason in "
                    "NOT_COVERED" % (ident, name))
            rows.append({"id": ident, "name": name, "lessons": cited,
                         "not_covered": NOT_COVERED.get(ident, ""),
                         "note": NOTES.get(ident, "")})
        lists.append({"key": spec["key"], "title": spec["title"],
                      "href": spec["href"], "edition": spec["edition"],
                      "entries": rows})
    return {"lists": lists, "lesson_count": len(course)}, problems


def render(data):
    e = html.escape
    sections = []
    for group in data["lists"]:
        rows = []
        for entry in group["entries"]:
            if entry["lessons"]:
                cell = "; ".join(
                    '<a href="../%s">Module %d, %s</a>'
                    % (e(l["href"]), l["number"], e(l["title"]))
                    for l in entry["lessons"])
                if entry["note"]:
                    cell += '<br><span class="meta">%s</span>' % e(entry["note"])
            else:
                cell = e(entry["not_covered"])
            rows.append("<tr><td>%s %s</td><td>%s</td></tr>"
                        % (e(entry["id"]), e(entry["name"]), cell))
        sections.append(
            '<section aria-labelledby="%s">\n<h2 id="%s">%s</h2>\n'
            '<p class="meta"><a href="%s">%s</a>. %s</p>\n'
            '<div class="wrap"><table>\n'
            '<thead><tr><th>Entry</th><th>Lessons that cite it</th></tr></thead>\n'
            '<tbody>\n%s\n</tbody></table></div>\n</section>'
            % (group["key"], group["key"], e(group["title"]),
               e(group["href"]), e(group["title"]), e(group["edition"]),
               "\n".join(rows)))
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OWASP coverage | API Security in the Age of AI</title>
<link rel="stylesheet" href="../assets/site.css">
</head>
<body>
<nav class="site-nav" aria-label="Site"><div><a class="home" href="../index.html">API Security in the Age of AI</a><a href="../index.html#course">Course</a><a href="../index.html#path">Modules</a><a href="../roadmap/index.html">Roadmap</a><a href="../checklist/index.html">Checklist</a><a href="../glossary/index.html">Glossary</a></div></nav>
<main>
<p class="kicker">Course coverage</p>
<h1>OWASP coverage</h1>
<p class="prose">Three OWASP lists, entry by entry, with the lessons that cite each entry. Use it to find the lesson for a finding, and to see what the course leaves out.</p>
<p class="prose meta">Generated from the %d lesson pages by <code>tools/build_coverage.py</code>. Do not edit this file by hand. A lesson is listed when its page names the entry's id. That is a low bar: a lesson that names an entry once is listed beside one that is built around it. These lists set no requirements, and covering every entry does not make an API secure.</p>
%s
<section aria-labelledby="not-covered">
<h2 id="not-covered">What the course does not cover</h2>
<ul class="prose">
<li>The entries marked above as not covered or partly covered.</li>
<li>GraphQL, gRPC and WebSocket beyond module 33. That module shows where the controls of earlier modules stop applying under each protocol. It leaves out GraphQL subscriptions, gRPC-Web, attacks on HTTP/2 itself, and injection through these protocols as a subject of its own.</li>
<li>How to test an API's security from the outside. The lessons list the negative tests their own controls must pass. No lesson teaches a testing method or a tool.</li>
</ul>
</section>
</main>
<footer>Part of API Security in the Age of AI.</footer>
</body>
</html>
""" % (data["lesson_count"], "\n".join(sections))


def serialize(data):
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"


def main_html(page):
    """What is between <main> and </main>, for the app to render as it is."""
    start = page.index("<main>\n") + len("<main>\n")
    return page[start:page.index("</main>")]


if __name__ == "__main__":
    data, problems = collect()
    page = render(data)
    data["html"] = main_html(page)
    record = serialize(data)
    if "--check" in sys.argv:
        if not OUT.is_file() or OUT.read_text(encoding="utf-8") != page:
            problems.append("coverage/index.html is out of date: run "
                            "python3 tools/build_coverage.py")
        if not DATA.is_file() or DATA.read_text(encoding="utf-8") != record:
            problems.append("content/coverage.json is out of date: run "
                            "python3 tools/build_coverage.py")
        if problems:
            sys.exit("%d problem(s):\n  %s" % (len(problems),
                                               "\n  ".join(problems)))
        print("the coverage page matches the lesson pages")
    else:
        if problems:
            sys.exit("%d problem(s):\n  %s" % (len(problems),
                                               "\n  ".join(problems)))
        OUT.parent.mkdir(exist_ok=True)
        OUT.write_text(page, encoding="utf-8")
        DATA.write_text(record, encoding="utf-8")
        entries = sum(len(g["entries"]) for g in data["lists"])
        print("wrote coverage/index.html and content/coverage.json: "
              "%d entries across %d lists" % (entries, len(data["lists"])))
