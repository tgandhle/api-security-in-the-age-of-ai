# Quality criteria

This file defines what this project means when it calls itself enterprise-grade, and records whether it meets that definition today.

"Enterprise-grade" here means satisfying the nine criteria below. It is a standard this project sets for itself and publishes so that anyone can check it. It is not an external certification, and no outside body has assessed the project against it.

The project may describe itself as enterprise-grade only while all nine criteria are recorded as **Pass**. A release may be cut before that, but it does not carry the claim.

## Current status

**Not yet meeting all enterprise-quality criteria.** The project meets 7 of 9 criteria. Independent content review and an evidence-bearing release are outstanding.

Last updated 2026-10-11. Each status is as of the commit that last changed this file.

| # | Criterion | Status |
|---|---|---|
| 1 | Written criteria | Pass |
| 2 | Independent content review | Not met |
| 3 | Applicability filter shipped | Pass |
| 4 | Applicability rules in the repository | Pass |
| 5 | Stable checklist IDs and machine-readable checklist | Pass |
| 6 | Repository governance | Pass |
| 7 | Review freshness enforced | Pass |
| 8 | Manual accessibility review | Pass |
| 9 | Evidence-bearing release | Not met |

When every row reads Pass, this section will say: **The project meets the enterprise-quality criteria defined in `QUALITY.md`.**

## How this file is kept

- A status changes only in a commit that also adds or links the evidence for it.
- A criterion that was Pass and stops being true goes back to Partial or Not met in the next commit that touches the area, and the current status line changes with it.
- Changing a criterion's acceptance condition is a stop-and-ask item, like changing the severity rubric.
- Status values are Pass, Partial and Not met. Partial means some of the acceptance condition is met; the row says which part.

## The criteria

### 1. Written criteria

**Acceptance.** This file defines the criteria, records Pass, Partial or Not met for each with links to evidence, and states that enterprise-grade means meeting this project-specific standard, not holding an external certification.

**Status: Pass.** This file.

### 2. Independent content review

**Acceptance.** Every published lesson is covered by at least one review by a human subject-matter expert who is independent of the author. One reviewer may cover several modules. A review log records, for each review: the reviewer, their relevant role or expertise, the modules reviewed, the date, the findings and what was decided about each, and the changes that resulted. Review by an AI model, including the models used to build this project, does not count.

**Status: Not met.** No lesson has been reviewed by anyone other than the author. The process is ready: `review/README.md` says what a reviewer confirms and how a review is recorded, and `review/packets/` splits the 38 lessons into five packets by expertise, generated from the pages and checked on every publish. The author used AI assistance throughout. The severity audit and the applicability assignment were checked by several instances of one language model plus the author, which is recorded in `AGENTS.md` under Decisions and does not meet this criterion.

### 3. Applicability filter shipped

**Acceptance.** The hosted checklist implements the frozen applicability model (version 3, 28 facts, 8 implications):

- an unanswered fact hides nothing;
- a child answered Yes makes its parent Yes, a parent answered No makes its child No, and nothing else follows;
- an answer that contradicts a declared implication is refused, naming both answers;
- only a condition that is provably false hides an item;
- every hidden item stays viewable, with the answers that excluded it;
- automated tests of the evaluator and the accessibility checks pass.

The static `checklist/index.html` continues to show all 331 items.

**Status: Pass.** `app/src/ApplicabilityFilter.jsx` on the hosted checklist, evaluated by `app/src/applicability.js`. Its tests (`app/src/applicability.test.js`) cover each rule above and run against all 331 conditions, and both workflows run them before the build. On the commit that added it, the browser evaluator gave the same hidden items as `tools/check_applicability.py` on 5,000 random answer sets, and axe-core found no violations on the checklist page with every question panel open, answers given, a refused answer shown and the set-aside list open, in light and dark at desktop and mobile width. The static `checklist/index.html` is unchanged. Version 1 of the model declared `oidc` implies `jwt`, which is not a guarantee; version 2 (2026-10-09) removes it. The removal only ever shows more: over every assignment of `oidc`, `jwt` and `oauth` valid under both versions, 14 evaluations go from false to unknown and none from shown to hidden (`AGENTS.md`, Decisions, 2026-10-09). The tests now assert that `oidc` Yes with `jwt` No is accepted and that `jwt` No no longer hides the OpenID Connect items. Version 3 (2026-10-25) adds the fact `sse` with no implications, for three new items; the tests assert that `sse` No hides those three and nothing else. The 5,000-set comparison and the accessibility run described above were made on the commit that added the filter and were not repeated for version 3.

### 4. Applicability rules in the repository

**Acceptance.** The frozen rules for assigning a condition to a checklist item are in `CONVENTIONS.md`. The vocabulary, the implications, the conditions and their reasons stay in `data/checklist-applicability.json` and are not written out a second time anywhere.

**Status: Pass.** "Checklist applicability" in `CONVENTIONS.md` holds the terms, the grammar, the evaluation, the eleven assignment rules, the precedence between them and the doubt rules. The facts and implications are declared only in `data/checklist-applicability.json`.

### 5. Stable checklist IDs and machine-readable checklist

**Acceptance.** Checklist IDs are never reused. Retired IDs are listed in a registry that a check enforces. The published checklist carries a schema version and a data version and can be downloaded as JSON and as CSV in a form other tools can import.

**Status: Pass.** `data/retired-checklist-ids.json` lists the three retired IDs (`a2a-05`, `cors-02`, `cors-07`). `tools/build_checklist.py`, which runs on every publish and in the release gate, fails if a retired ID is on a topic page, or if an ID that the committed `checklist/checklist.json` publishes leaves the pages without being retired; both failures were tested on the commit that added them. The same tool writes `checklist/checklist.json` and `checklist/checklist.csv` with a schema version, a data version that is a hash of the data, and each item's applicability condition. Both checklist pages link them. They are licensed CC BY 4.0 by `CHECKLIST-LICENSE.md` so they can be imported into other tools; the rest of the repository keeps the terms in `LICENSE`.

### 6. Repository governance

**Acceptance.** `SECURITY.md`, `CONTRIBUTING.md` and `CODEOWNERS` exist. `main` is protected by a GitHub ruleset that requires the publishing checks to pass, blocks force pushes and deletion, and requires signed commits.

**Status: Pass.** `SECURITY.md`, `CONTRIBUTING.md` and `.github/CODEOWNERS` exist, and private vulnerability reporting is switched on, so Security, Advisories offers "Report a vulnerability" as `SECURITY.md` says. Ruleset 24830310, named `main`, was created on 2026-10-09 with enforcement active, targets the default branch and has an empty bypass list (`current_user_can_bypass` is `never`). `GET /repos/tgandhle/api-security-in-the-age-of-ai/rules/branches/main` lists its five rules: `deletion` (deletion restricted), `non_fast_forward` (force pushes blocked), `required_signatures`, `pull_request` (0 approvals, so the one maintainer can merge; merge and squash only) and `required_status_checks` (the `build` job of `.github/workflows/pages.yml`, branch up to date). `.github/workflows/pages.yml` runs that job on pull requests into `main` without publishing. This status change was itself merged through a pull request under the ruleset.

### 7. Review freshness enforced

**Acceptance.** An automated check enforces the review cadence in `CONVENTIONS.md`: a lesson's "Last reviewed" date may be at most 92 days old, and at most 31 days for the MCP and A2A lessons. A date check does not show that a cited specification is unchanged, so a new version of a pinned specification still requires a manual review of the lessons that cite it.

**Status: Pass.** `tools/check_review_dates.py` checks every lesson against those limits. It warns in `.github/workflows/pages.yml`, so a stale lesson does not block an unrelated fix, and fails with `--strict` in the release gate (`tools/release_evidence.py`) and in `.github/workflows/freshness.yml`, which runs daily so a lesson is reported within a day of passing its limit. A missing, duplicated or future date fails in every mode.

### 8. Manual accessibility review

**Acceptance.** At least one recorded manual pass over a representative lesson, the hosted checklist with the filter, and a runnable lab, using NVDA, keyboard-only navigation, and 200% zoom with reflow. The record gives the browser and operating system, the steps, every failure found, and what was done about each.

**Status: Pass.** `accessibility/log/2026-10-10-gandhle.md` records one manual pass of the 40 steps in `accessibility/README.md` (keyboard only, NVDA 2026.2, and zoom at 200% and 400%) over the webhooks lesson, its in-browser lab and the filtered checklist, by the author, in Chrome 154 (Guest window) on Windows 11 at 125% display scale, against site commit `6c74dde`. 39 steps passed. K1 failed: the skip link left focus on the page body because `main` could not take focus. It was fixed in `092e68f` (PR #4), and K1 passed when redone on `f454f1a`. The record gives the setup, every step, the failure and its disposition. It is one tester, one screen reader and one browser over three parts of the site, so it is not a conformance claim. Accessibility is also checked automatically with axe-core on every static page and the built site, in light and dark mode at desktop and mobile width.

### 9. Evidence-bearing release

**Acceptance.** The release commit passes the release gate (`.github/workflows/release.yml`) and the Firefox and WebKit workflow (`.github/workflows/browser-compat.yml`) at that same commit. It is a signed tag with the release evidence attached. The first release that carries the enterprise-grade claim also requires criteria 1 to 8 to be Pass at that commit.

**Status: Not met.** v1.0.0 (`a133973`) passed the release gate and has its evidence and the severity audit archive attached. The Firefox and WebKit workflow did not exist at that commit; its first run was at `f2c92ca`, which is not released.
