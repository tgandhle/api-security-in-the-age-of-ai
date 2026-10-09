# Quality criteria

This file defines what this project means when it calls itself enterprise-grade, and records whether it meets that definition today.

"Enterprise-grade" here means satisfying the nine criteria below. It is a standard this project sets for itself and publishes so that anyone can check it. It is not an external certification, and no outside body has assessed the project against it.

The project may describe itself as enterprise-grade only while all nine criteria are recorded as **Pass**. A release may be cut before that, but it does not carry the claim.

## Current status

**Not yet meeting all enterprise-quality criteria.** The project meets 1 of 9 criteria. Independent content review, the applicability filter, and repository governance are among those outstanding.

Last updated 2026-10-09, at commit `7901ce3`.

| # | Criterion | Status |
|---|---|---|
| 1 | Written criteria | Pass |
| 2 | Independent content review | Not met |
| 3 | Applicability filter shipped | Not met |
| 4 | Applicability rules in the repository | Not met |
| 5 | Stable checklist IDs and machine-readable checklist | Not met |
| 6 | Repository governance | Not met |
| 7 | Review freshness enforced | Not met |
| 8 | Manual accessibility review | Not met |
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

**Status: Not met.** No lesson has been reviewed by anyone other than the author. The author used AI assistance throughout. The severity audit and the applicability assignment were checked by several instances of one language model plus the author, which is recorded in `AGENTS.md` under Decisions and does not meet this criterion.

### 3. Applicability filter shipped

**Acceptance.** The hosted checklist implements the frozen applicability model (version 1, 27 facts, 9 implications):

- an unanswered fact hides nothing;
- a child answered Yes makes its parent Yes, a parent answered No makes its child No, and nothing else follows;
- an answer that contradicts a declared implication is refused, naming both answers;
- only a condition that is provably false hides an item;
- every hidden item stays viewable, with the answers that excluded it;
- automated tests of the evaluator and the accessibility checks pass.

The static `checklist/index.html` continues to show all 325 items.

**Status: Not met.** The data and its check exist: `data/checklist-applicability.json` and `tools/check_applicability.py`, which runs on every publish. Nothing on the site reads the file yet.

### 4. Applicability rules in the repository

**Acceptance.** The frozen rules for assigning a condition to a checklist item are in `CONVENTIONS.md`. The vocabulary, the implications, the conditions and their reasons stay in `data/checklist-applicability.json` and are not written out a second time anywhere.

**Status: Not met.** The rules exist only outside the repository. `AGENTS.md` says so.

### 5. Stable checklist IDs and machine-readable checklist

**Acceptance.** Checklist IDs are never reused. Retired IDs are listed in a registry that a check enforces. The published checklist carries a schema version and a data version and can be downloaded as JSON and as CSV in a form other tools can import.

**Status: Not met.** Three IDs have been retired (`cors-02`, `cors-07`, `a2a-05`) and `AGENTS.md` says they are not reused, but no registry or check enforces it. There is no checklist download.

### 6. Repository governance

**Acceptance.** `SECURITY.md`, `CONTRIBUTING.md` and `CODEOWNERS` exist. `main` is protected by a GitHub ruleset that requires the publishing checks to pass, blocks force pushes and deletion, and requires signed commits.

**Status: Not met.** None of the three files exist. When the owner checked on 2026-10-08, GitHub reported no ruleset on the repository. The owner has signed every commit pushed to `main` since v1.0.0, but nothing enforces it.

### 7. Review freshness enforced

**Acceptance.** An automated check enforces the review cadence in `CONVENTIONS.md`: a lesson's "Last reviewed" date may be at most 92 days old, and at most 31 days for the MCP and A2A lessons. A date check does not show that a cited specification is unchanged, so a new version of a pinned specification still requires a manual review of the lessons that cite it.

**Status: Not met.** The dates are extracted into `content/` by `tools/extract_lessons.py`, but their age is not checked.

### 8. Manual accessibility review

**Acceptance.** At least one recorded manual pass over a representative lesson, the hosted checklist with the filter, and a runnable lab, using NVDA, keyboard-only navigation, and 200% zoom with reflow. The record gives the browser and operating system, the steps, every failure found, and what was done about each.

**Status: Not met.** Accessibility is checked automatically with axe-core on every static page and the built site, in light and dark mode at desktop and mobile width. Automated rules are a floor, as `CONVENTIONS.md` says, and no manual pass has been recorded.

### 9. Evidence-bearing release

**Acceptance.** The release commit passes the release gate (`.github/workflows/release.yml`) and the Firefox and WebKit workflow (`.github/workflows/browser-compat.yml`) at that same commit. It is a signed tag with the release evidence attached. The first release that carries the enterprise-grade claim also requires criteria 1 to 8 to be Pass at that commit.

**Status: Not met.** v1.0.0 (`a133973`) passed the release gate and has its evidence and the severity audit archive attached. The Firefox and WebKit workflow did not exist at that commit; its first run was at `f2c92ca`, which is not released.
