# Conventions

## Audience
Security engineers, architects and developers, including people new to security. Assume they can read Python and HTTP, not that they know the vocabulary.

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
   - Two to five exercises in `<section class="course-exercises" data-exercises>`, each an `<article data-exercise>` that changes one thing in the lab and asks what the run prints.

**Reference** (anchor `#reference`)
- Controls, each labeled Standard, Baseline, or Option.
- Review checklist items as `<li data-check="id" data-severity="Critical|High|Medium">` with a `<strong>` title and a `<span>` detail. The severity is the item's default, set by the severity rubric below. It is not the severity of a finding, which depends on what the API exposes, who can reach it and what else stands in the way. The checklist page says so to the reader.
- Sources: primary sources only, with pinned revisions where a spec is versioned.

## Claim labels
- **Standard:** backed by a cited specification, and stated at the strength the source states it: requires, recommends or allows.
- **Baseline:** this project's default. The Learn section explains why.
- **Option:** valid depending on the threat model.

## Severity rubric

Version 3.1, frozen 2026-10-05. Every checklist item's default severity comes from this rubric. Rate a new item with it before the item is published. Do not change the rubric to fit one item: a change to the rubric means every item is rated again.

The default answers one question: what is the consequence of losing the security decision or property this item itself provides, giving no credit to any other independent control that makes the same decision or provides the same property?

### Reference model

- An API reachable from the internet, holding other parties' data or able to move money.
- Own-property rule. Rate the security property the item itself provides. Another control that makes the same decision gets no credit: for rating purposes it is absent. Two items that make the same decision can both get the same rating.
- Do not remove a different security decision merely because it also mitigates the same overall attack. A control does not inherit the consequence of a separate authorization, execution or containment decision it does not itself make. Those decisions, and all unrelated controls, stay in place.
- A control whose own effect is to raise attack cost, improve provenance or framing, reduce discoverability, or otherwise provide defence in depth is rated on that direct effect. It is not Critical only because another boundary control is imagined absent.
- The attacker is anonymous, an ordinary authenticated user or tenant, or anyone who can put content in front of a model the system runs. The attacker has no position inside the deployment's network and is not a party the system trusts, unless a precondition below is counted.
- Applicability is assumed from the item's scope. An agent item is rated with an agent present, a webhook item with a webhook endpoint present. Applicability does not lower severity.
- Not considered: how common the flaw is, how hard the fix or the attack is, or whether a standard requires the control.

### Step 1: classify the item

The detail text decides. The title is shorthand.

| Class | Test |
|---|---|
| Enforcing | Its absence changes what a request, or a piece of content, can do. |
| Detecting | Its absence changes what the owner knows about an event. |
| Recovering | Its absence changes what the owner can contain, revoke, restore or reverse after an event. |
| Assuring | It is a test, review, record or named owner for another control. |

- An item that is an input an enforcement decision consumes is Enforcing and takes that decision's rating. This applies only when the item's own text says the decision reads it. A list or record that is only said to be written down is Assuring.
- An item worded as "tested", "documented" or "recorded" whose detail states a behaviour the system must have is classified by that behaviour.
- An item that restates a control another item states is the same control and gets the same rating.
- If an item both detects and recovers, rate each and keep the higher.

### Step 2: rate it

**Enforcing.** A Critical-class outcome is any of: (a) read or change another party's data; (b) act as another identity, increase privilege, or obtain a credential, token or session the attacker is not authorized to obtain; (c) run code or commands, or reach a network the caller should not; (d) cause an unauthorized consequential action, such as a payment, message, deletion, external side effect or irreversible state change.

- **Critical:** one request or one attacker-supplied piece of content directly causes a Critical-class outcome, with no precondition.
- **High:** a Critical-class outcome needs exactly one precondition from the list below; or it needs repeated attempts and nothing else (guessing, brute force, timing); or, with no precondition, the missing control allows unbounded availability or cost impact; or the item is about a known but unspecified unpatched flaw, which is fixed at High because the item does not say what the flaw yields.
- **Medium:** anything lower that still has a security effect: bounded disclosure of internals, a Critical-class outcome needing two or more preconditions, availability or cost impact that needs a precondition, limited degradation.
- An item with no security effect at all is not a checklist item. Reword it or leave it out.

Preconditions. Each is something the attacker does not get for free. The failure of another control is never a precondition.

- P1: holds a stolen or leaked credential, token, key or session.
- P2: can read or alter traffic on the network path, or read a log or a proxy.
- P4: a victim must act (visit a page, follow a link, start a flow, approve, rely on an answer).
- P5: holds a trusted-party position: insider, administrator, partner, supplier or publisher of an artifact the system adopts, upstream or allowlisted host, or a sibling client or resource server of the same issuer.
- P6: an ordinary fault with no attacker (a retry, a duplicate delivery, a crash, a wrong clock).
- P7: a network position inside the deployment.

There is no P3. Use the smallest set of preconditions that makes the attack work.

**Detecting.** High if it is the only item performing that same detection or alerting function for a Critical-class event, otherwise Medium. Recording and alerting are different functions. An item that covers only part of the event is not an equivalent. If two items perform the same function for the same event, both are Medium. A refused attempt at a Critical-class outcome counts as a Critical-class event.

**Recovering.** High if it is the only item performing that same containment, revocation, restore or reversal function for a Critical-class event, otherwise Medium, with the same qualifications. A detecting item is not an equivalent for a recovering item.

**Assuring.** If the item's text identifies a control behaviour closely enough that there is one defensible smallest set of checklist items it assures, rate it one level below the highest of them, with a floor of Medium. If several different target sets are plausible and give different levels, reword the item. An item that assures the review, the test programme or the checklist in general is Medium.

### Tie rules

- Rate the item as written, including any scope stated in its title or detail.
- Bundle rule. An item is bundled only when its own title or detail imposes two or more co-equal security requirements. An explanation, example, consequence, implementation note, or restatement of another control is not a second requirement. Rate the principal subject. If there really are two co-equal requirements, rate the worse.
- Explicit-scope rule. When the item itself says exploitation occurs through an alternate, bypass, internal or non-entry-point path, keep that scope when counting preconditions. If reaching that path needs a position inside the deployment, count P7 once.
- A third-party client that exceeds what a user granted needs that grant first (P4). An authenticated counterparty agent holds a partner position (P5).

## Rules
- No secrets in examples. Use placeholders such as `<secret from vault>`. Labs generate keys at runtime or read a file.
- Every code sample and lab is run before publishing, and the page shows the real output.
- An exercise's correct answer is the measured output of that variant of the lab, run before publishing, not a reading of the code. Do not write an exercise you have not run both ways.
- Every exercise option carries a reason, published as `<li data-option="value">` inside one `<details class="exercise-answers">` in that exercise, so a reader with JavaScript off sees all of them and nothing is written twice. `tools/extract_lessons.py --check` requires exactly one correct option per exercise and a reason for every option offered.
- An exercise names the checklist item it covers with `data-covers`. Never `data-check`: that attribute means "this element is a checklist item" to `tools/build_checklist.py` and to the extractor's audit. An exercise that teaches protocol or conformance behaviour with no checklist item carries no `data-covers`; three do (`cors-x2`, `cors-x3`, `a2a-x1`).
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
