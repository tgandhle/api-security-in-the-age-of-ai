# Conventions

## Audience
New security engineers. Assume they can read Python and HTTP, not that they know the vocabulary.

## Page template
Each page has two layers, in this order.

**Learn**
1. The attack: a worked example, with a table of which variants succeed.
2. Why it works: the broken assumptions.
3. The control: what gets signed, checked, or enforced, in order.
4. Defaults and when to change them.
5. What it proves, and what it doesn't.
6. Prove it: the negative tests an implementation must pass.
7. Lab: link, run command, and real output.
8. Check your understanding, in three parts:
   - Three or four questions with answers in a bare `<details>`.
   - One quick check, a single multiple-choice question in `<section class="course-quiz" data-quiz>`. This is the only assessment the course dashboard counts.
   - Two to four exercises in `<section class="course-exercises" data-exercises>`, each an `<article data-exercise>` that changes one thing in the lab and asks what the run prints.

**Reference** (anchor `#reference`)
- Controls, each labeled Standard, Baseline, or Option.
- Review checklist items as `<li data-check="id" data-severity="Critical|High|Medium">` with a `<strong>` title and a `<span>` detail.
- Sources: primary sources only, with pinned revisions where a spec is versioned.

## Claim labels
- **Standard:** backed by a cited specification, and stated at the strength the source states it: requires, recommends or allows.
- **Baseline:** this project's default. The Learn section explains why.
- **Option:** valid depending on the threat model.

## Rules
- No secrets in examples. Use placeholders such as `<secret from vault>`. Labs generate keys at runtime or read a file.
- Every code sample and lab is run before publishing, and the page shows the real output.
- An exercise's correct answer is the measured output of that variant of the lab, run before publishing, not a reading of the code. Do not write an exercise you have not run both ways.
- Every exercise option carries a reason, published as `<li data-option="value">` inside one `<details class="exercise-answers">` in that exercise, so a reader with JavaScript off sees all of them and nothing is written twice. `tools/extract_lessons.py --check` requires exactly one correct option per exercise and a reason for every option offered.
- An exercise names the checklist item it covers with `data-covers`. Never `data-check`: that attribute means "this element is a checklist item" to `tools/build_checklist.py` and to the extractor's audit.
- Fictional companies only, with the reserved `.example` domain.
- Link a glossary term the first time a page uses it.
- After editing any checklist item, run `python3 tools/build_checklist.py`.
- Record the review date at the top of each page.
- Every page must pass `python3 tools/check_a11y.py` with no violations, in light and dark mode at desktop and mobile width. Automated rules are a floor, not a conformance claim.
- Every lab section must carry the Windows note, because `python3` is not the recommended command on Windows and the audience includes Windows users.
- A lab that needs a package installs it into a virtual environment, and the page says that inside one the command is `python`, not `py -3`.
- `react-poc/` is an unpublished experiment and is exempt from these conventions. Lesson content is authored in `topics/`, never there.

## Review cadence
- Topic pages: quarterly.
- The MCP and A2A topic pages: on each spec release, or monthly, whichever comes first.
