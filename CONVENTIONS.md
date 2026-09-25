# Conventions

## Audience
New security engineers. Assume they can read Python and HTTP, not that they know the vocabulary.

## Page template (topics and protocols)
Each page has two layers, in this order.

**Learn**
1. The attack: a worked example, with a table of which variants succeed.
2. Why it works: the broken assumptions.
3. The control: what gets signed, checked, or enforced, in order.
4. Defaults and when to change them.
5. What it proves, and what it doesn't.
6. Prove it: the negative tests an implementation must pass.
7. Lab: link, run command, and real output.
8. Check your understanding: two or three questions with answers in `<details>`.

**Reference** (anchor `#reference`)
- Controls, each labeled Standard, Baseline, or Option.
- Review checklist items as `<li data-check="id" data-severity="Critical|High|Medium">` with a `<strong>` title and a `<span>` detail.
- Sources: primary sources only, with pinned revisions where a spec is versioned.

## Claim labels
- **Standard:** backed by a cited specification.
- **Baseline:** this project's default. The Learn section explains why.
- **Option:** valid depending on the threat model.

## Rules
- No secrets in examples. Use placeholders such as `<secret from vault>`. Labs generate keys at runtime or read a file.
- Every code sample and lab is run before publishing, and the page shows the real output.
- Fictional companies only, with the reserved `.example` domain.
- Link a glossary term the first time a page uses it.
- After editing any checklist item, run `python3 tools/build_checklist.py`.
- Record the review date at the top of each page.

## Review cadence
- Topic pages: quarterly.
- Protocol pages (MCP, A2A): on each spec release, or monthly, whichever comes first.
