#!/usr/bin/env python3
"""Generate the independent review packets from the lesson pages.

Usage:
  python3 tools/build_review_packets.py          rewrite review/packets/ and review/manifest.json
  python3 tools/build_review_packets.py --check  exit 1 if any of them is out of date

Standard library only. For each lesson, a packet lists what a reviewer is asked
to confirm, read from the page itself so the packet cannot drift from it:

  - every control in the Reference section labelled Standard (a claim
    attributed to a cited source), Baseline (the project's default) or Option;
  - the sources the page cites, as pinned there;
  - the lab the page runs;
  - the checklist items the page contributes, with severity and the
    applicability condition from checklist/checklist.json.

The 38 lessons are split into five packets by area of expertise (PACKETS
below), so no reviewer needs to cover the whole course. Each claim has an id,
such as 05-S3, that a review record cites. Ids are positions on the page, so
they are only meaningful together with the commit the packet was generated
at; a review record names that commit.

What a reviewer does with a packet, and how a review is recorded, is in
review/README.md. Never edit the generated files by hand.
"""
import html
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
LESSONS = ROOT / "content" / "lessons"
CHECKLIST = ROOT / "checklist" / "checklist.json"
OUT_DIR = ROOT / "review" / "packets"
MANIFEST = ROOT / "review" / "manifest.json"
SITE = "https://tgandhle.github.io/api-security-in-the-age-of-ai/"

# Five packets by the expertise a reviewer needs. Every module is in exactly
# one; main() fails if a lesson is missing or listed twice.
PACKETS = [
    ("a-identity", "Identity, credentials and tokens",
     "API keys, request signing, OAuth, JWT and JWKS, sender-constrained tokens, workload identity, "
     "delegation, authentication endpoints, OpenID Connect, advanced OAuth and SAML.",
     [1, 2, 3, 4, 5, 6, 7, 8, 19, 27, 35, 36, 37]),
    ("b-core", "Core API and web application security",
     "Security foundations, object, property and function authorization, business flows, request and "
     "response contracts, rate limiting, CORS, browser sessions and CSRF, misconfiguration.",
     [0, 9, 10, 11, 13, 15, 17, 28, 29]),
    ("c-integration", "Integration and protocols",
     "Gateways, SSRF and unsafe consumption of APIs, webhooks, versioning, GraphQL, gRPC and WebSocket.",
     [12, 14, 16, 18, 33]),
    ("d-ai", "AI, agents, MCP and A2A",
     "MCP authorization, agent-to-agent, prompt injection and output handling, agent authority and "
     "approvals, data in model context, retrieval and memory, agent containment, model supply chain.",
     [20, 21, 22, 23, 24, 25, 31, 32]),
    ("e-assurance", "Assurance, testing and operations",
     "Design review, logging, detection and response, security testing.",
     [26, 30, 34]),
]
LABEL = {"std": "S", "base": "B", "opt": "O"}
CLAIM = re.compile(r'<li><span class="label (std|base|opt)">[A-Za-z]+</span>(.*?)</li>', re.S)


def text(fragment):
    return " ".join(html.unescape(re.sub(r"<[^>]+>", "", fragment)).split())


def lesson_data():
    out = {}
    for path in sorted(LESSONS.glob("*.json")):
        d = json.loads(path.read_text(encoding="utf-8"))
        page = (ROOT / "topics" / d["slug"] / "index.html").read_text(encoding="utf-8")
        claims = {"S": [], "B": [], "O": []}
        for kind, body in CLAIM.findall(page):
            claims[LABEL[kind]].append(text(body))
        labs = []
        for block in d["blocks"]:
            for lab in re.findall(r"labs/(\w+\.py)", block["html"]):
                if lab not in labs:
                    labs.append(lab)
        out[d["module"]] = {
            "module": d["module"], "slug": d["slug"], "title": d["title"],
            "reviewed": d["reviewed"], "claims": claims, "labs": labs,
            "sources": [{"title": s["title"], "href": s["href"], "note": text(s["html"])}
                        for s in d["sources"]],
        }
    return out


def build():
    lessons = lesson_data()
    listed = [m for p in PACKETS for m in p[3]]
    if sorted(listed) != sorted(lessons) or len(listed) != len(set(listed)):
        sys.exit("PACKETS must list every lesson module exactly once: "
                 f"missing {sorted(set(lessons) - set(listed))}, "
                 f"unknown {sorted(set(listed) - set(lessons))}")
    checklist = json.loads(CHECKLIST.read_text(encoding="utf-8"))
    checks = {}
    for item in checklist["items"]:
        slug = item["lesson_path"].split("/")[1]
        checks.setdefault(slug, []).append(item)
    show = lambda c: "always" if c == "always" else " AND ".join(
        m if isinstance(m, str) else "(" + " OR ".join(m["any_of"]) + ")" for m in c["all_of"])

    manifest = {"schema_version": "1", "packets": []}
    files = {}
    for pid, name, scope, modules in PACKETS:
        lines = [f"# Review packet {pid[0].upper()}: {name}", "",
                 "Generated by `tools/build_review_packets.py` from the lesson pages. Do not edit by hand.",
                 "Read `review/README.md` first: it says what you are asked to confirm, what you are not, "
                 "and how to record what you find.", "",
                 f"Scope: {scope}", "",
                 "| Module | Lesson | Claims | Checklist items |", "|---|---|---|---|"]
        entry = {"id": pid, "name": name, "modules": []}
        for m in modules:
            L = lessons[m]
            n = sum(len(v) for v in L["claims"].values())
            lines.append(f"| {m} | {L['title']} | {n} | {len(checks.get(L['slug'], []))} |")
        lines.append("")
        for m in modules:
            L = lessons[m]
            items = sorted(checks.get(L["slug"], []), key=lambda i: i["id"])
            url = SITE + f"topics/{L['slug']}/index.html"
            lines += [f"## Module {m}: {L['title']}", "",
                      f"- Lesson: <{url}> (source: `topics/{L['slug']}/index.html`)",
                      f"- Last reviewed by the author: {L['reviewed']}",
                      f"- Lab: " + ", ".join(f"`labs/{x}`, run with `python3 labs/{x}`" for x in L["labs"]), ""]
            claim_ids = {}
            for kind, heading, ask in [
                ("S", "Claims attributed to a source (Standard)",
                 "Confirm the cited source says this, at the strength stated: must, should or may."),
                ("B", "The project's defaults (Baseline)",
                 "Confirm each is technically sound. These are the project's position, not a source's."),
                ("O", "Alternatives (Option)",
                 "Confirm each is technically sound where the page says it applies."),
            ]:
                if not L["claims"][kind]:
                    continue
                lines += [f"### {heading}", "", ask, ""]
                for i, claim in enumerate(L["claims"][kind], 1):
                    cid = f"{m:02d}-{kind}{i}"
                    claim_ids[cid] = claim
                    lines.append(f"- **{cid}** {claim}")
                lines.append("")
            lines += ["### Sources as the page pins them", ""]
            lines += [f"- [{s['title']}]({s['href']}): {s['note']}" for s in L["sources"]]
            lines += ["", "### Lab", "",
                      "The publishing workflow already checks that the lab's output matches the page byte for "
                      "byte. The question for you is whether the lab demonstrates what the lesson says it "
                      "demonstrates, and whether anything it shows is technically wrong.", "",
                      "### Checklist items from this lesson", "",
                      "Review the title and detail for technical correctness. Severity and the applicability "
                      "condition are shown for context; reviewing them is optional (see `review/README.md`).", "",
                      "| Id | Severity | Applies when | Item |", "|---|---|---|---|"]
            for i in items:
                lines.append(f"| {i['id']} | {i['severity']} | `{show(i['applicability']['condition'])}` | "
                             f"**{i['title']}** {i['detail']} |".replace("\n", " "))
            lines.append("")
            entry["modules"].append({
                "module": m, "slug": L["slug"], "title": L["title"], "labs": L["labs"],
                "claims": claim_ids, "checklist_items": [i["id"] for i in items],
                "sources": [s["href"] for s in L["sources"]],
            })
        manifest["packets"].append(entry)
        files[OUT_DIR / f"packet-{pid}.md"] = "\n".join(lines).rstrip() + "\n"
    files[MANIFEST] = json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"
    return files, manifest


def main():
    files, manifest = build()
    stale = sorted(p.name for p in OUT_DIR.glob("*.md") if p not in files) if OUT_DIR.exists() else []
    if "--check" in sys.argv:
        bad = [p.relative_to(ROOT).as_posix() for p, t in files.items()
               if not p.exists() or p.read_text(encoding="utf-8") != t] + stale
        if bad:
            sys.exit("review packets are out of date: run python3 tools/build_review_packets.py "
                     f"({', '.join(bad)})")
        print("the review packets match the lesson pages")
        return 0
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for name in stale:
        sys.exit(f"review/packets/{name} is not a packet this tool writes: remove it by hand")
    for path, t in files.items():
        path.write_text(t, encoding="utf-8", newline="")
    claims = sum(len(m["claims"]) for p in manifest["packets"] for m in p["modules"])
    print(f"wrote {len(manifest['packets'])} packets covering "
          f"{sum(len(p['modules']) for p in manifest['packets'])} lessons and {claims} claims")
    return 0


if __name__ == "__main__":
    sys.exit(main())
