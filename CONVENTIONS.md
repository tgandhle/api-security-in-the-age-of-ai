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

Version 3.1, frozen 2026-10-05. Every checklist item's default severity comes from this rubric. Rate a new item with it before the item is published. Do not change the rubric to fit one item: a change to the rubric means every item is rated again. The short form readers see on the checklist page is `data/severity-rubric-summary.json`. When the version here changes, update that file and its `rubric_version`; `tools/build_checklist.py` fails until the two agree.

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

## Checklist applicability

Version 1, frozen 2026-10-07. Every checklist item records the facts about a system under which the item applies, so a reviewer can set aside items that cannot apply to the system in front of them. The conditions, their reasons, the facts and the implications between them are in `data/checklist-applicability.json`, and are not repeated here. This section holds the rules for writing a condition. `tools/check_applicability.py` enforces the grammar, the declared facts and the redundancy rule; it cannot check that a condition is the right one, which is what the rules below are for.

A new checklist item gets its condition from these rules before it is published, like its severity. Do not change a rule, a fact or an implication to fit one item: the model is frozen, and a change to it means every item is assigned again. If an item stays ambiguous under these rules, take the weaker condition; if no clearly weaker condition is safe, use `always`. Record the ambiguity in the commit message.

### Terms

- **Fact.** A yes or no statement about the architecture of the system under review, such as "a browser client calls the API". A fact is never a security control and never an attack. The facts are declared in `data/checklist-applicability.json`, with the question a reviewer answers for each.
- **Answer.** What the reviewer says about a fact: Yes, No or Unknown. Every fact starts as Unknown.
- **Condition.** What an item needs in order to apply, written in the grammar below.
- **Assignment.** One answer for every fact.

### What a fact means

1. A fact is about the whole system under review. Yes means "present anywhere in scope". A system with one cookie-authenticated admin page has a cookie session.
2. A fact describes what the system is or does, not how well it is defended. "A browser calls the API" is a fact. "CORS is configured" is a control and is not a fact.
3. A fact must be answerable from a design document or by asking the team one question.
4. Three things that are true of almost every API are deliberately not facts, and items that depend only on them are `always`: the API holds resources that belong to different users or tenants; it has fields or functions that not every caller may use; it has requests that change state. A mistaken No on any of these would hide the authorization items, which are among the most important on the list.

### Implications

Some facts guarantee others. `data/checklist-applicability.json` declares each one in the child's `implies` list. An implication is declared only when it is a guarantee, not when it is merely usual.

Two rules follow from each declared implication, and only these two:

- Child Yes makes parent Yes.
- Parent No makes child No.

Nothing follows from child No, and nothing follows from parent Yes. Implications chain: if A implies B and B implies C, then A implies C.

**Resolving answers.** Start from the reviewer's answers. Apply the two rules until nothing changes. Any fact not settled by an answer or by a rule stays Unknown.

**Contradictions.** An assignment in which a child is Yes and its parent is No is invalid. The interface must refuse it and say which two answers conflict. It must not pick one silently.

**Writing conditions.** A condition names the most specific fact only. If an item needs a cookie session, the condition says `cookie_session` and does not add `browser_client`. The filter derives the rest.

### Condition grammar

A condition is exactly one of these two forms.

```json
"always"
```

```json
{ "all_of": [ "fact_a", { "any_of": ["fact_b", "fact_c"] } ] }
```

- `all_of` is a list with at least one member.
- Each member is a fact id or an `any_of` group. An `all_of` may hold more than one group.
- An `any_of` group is a list of at least two fact ids. It contains facts only.
- There is no negation, no nesting beyond this, and no other operator.

A single required fact is written `{ "all_of": ["fact_a"] }`. A choice between facts with nothing else required is written `{ "all_of": [ { "any_of": ["fact_b", "fact_c"] } ] }`.

Every item also carries a `reason`: one sentence saying why the condition is what it is. For `always` the reason says why no architecture fact can rule the item out.

### Evaluation

Evaluate a condition against the resolved answers. The result is true, false or unknown.

| Form | False when | True when | Otherwise |
|---|---|---|---|
| a fact | its answer is No | its answer is Yes | unknown |
| `any_of` | every member is false | at least one member is true | unknown |
| `all_of` | at least one member is false | every member is true | unknown |
| `always` | never | always | |

**Only false hides an item.** True and unknown both leave it visible. An item is hidden only when the reviewer's own answers, with the implication rules, prove its condition cannot be met.

Every hidden item stays reachable. With "show excluded" on, each one is listed with the answers that excluded it, for example "Not applicable because: webhook receiver = No".

### Rules for assigning a condition to an item

1. **Read the item as written.** Use its title and detail. Use the lesson to understand what the item means, not to add requirements it does not state.
2. **Necessary, not typical.** Include a fact only if the item cannot make sense without it. Do not include a fact because it is usually present alongside. A webhook item needs a webhook receiver. It does not also need an internet-facing API or request signing.
3. **Minimal.** State the smallest condition under which the item applies.
4. **Most specific fact only, and nothing redundant.** In an `all_of`, do not list a fact that another listed fact implies, directly or through a chain. In an `any_of`, do not list a fact that implies another member, because the broader member already covers it. The test is the same in both places: if deleting a fact would not change the result under any valid assignment, it does not belong.
5. **An item that applies in more than one setting** gets an `any_of` over those settings, so it stays visible if any of them is present.
6. **An item with multiple independent parts applies whenever any part applies.** Work out the minimal condition for each part. If one of those conditions is logically weaker than all the others, use it. If they are incomparable, use a condition that preserves their logical union within the grammar. For example, "GraphQL with a cookie session, or gRPC" is `all_of` of two groups: `any_of [graphql, grpc]` and `any_of [cookie_session, grpc]`. If the union is unclear or materially more complex than that, use `always` under the doubt rule, so no applicable part can be hidden.
7. **Process items.** An item about how a review, a test or an inventory is done applies to every review and is `always`, unless its own text limits it to something specific.
8. **Protocol and source scope.** A protocol, standard or specification cited in an item's detail does not by itself make that protocol's fact necessary. Include the protocol fact only when the item's title or detail depends on a protocol-specific object, operation, role or behaviour, such that the item cannot be read coherently without that protocol.
9. **Discovery rule.** Do not condition an item on an architecture fact that the item itself is intended to establish or verify. If performing the check can reveal that the fact is present, gate the item on the weakest prerequisite fact that must already be true for the check to make sense, or use `always` when there is no such fact. A fact is a discovery fact only when performing the checklist item can itself establish whether that fact is present. A control that merely becomes important when a fact is true is not a discovery item.
10. **Independent-fact conjunction.** Two facts with no implication between them belong in the same `all_of` only when every applicable instance of the item requires both. If the item remains meaningful with either fact absent, do not conjoin them. Apply rule 6 where there are genuinely separate cases; otherwise use the weaker single condition under the doubt rules.
11. **Do not generalize an item merely because its control principle would also be useful elsewhere.** Use the lesson to resolve what otherwise-generic nouns in the item refer to. A citation alone does not scope an item, but the item's actual technical subject does.

**Precedence between the rules.**

1. **Near-universal precedence.** The fourth point under "What a fact means" wins over protocol scoping. If an item's substantive security property is one of the three things deliberately treated as `always`, rule 11 cannot narrow it unless the item itself depends on a protocol-specific object or operation.
2. **Protocol-subject precedence.** Rules 8 and 11 are read together: include a protocol fact when the protocol-specific object, role, behaviour or requirement is the actual subject of the item. A citation or lesson location alone is insufficient, but a requirement whose meaning changes outside that protocol is protocol-scoped.
3. **Safety precedence over extra conjunctions.** Rule 10 does not require adding every fact that happens to be true in a valid instance. When a protocol fact already identifies the security subject, do not add a second independent fact merely to suppress irrelevant variants if a mistaken No on that second fact could hide the check. Conjoin only when the item's own applicability plainly depends on both architecture facts. This is the fail-visible principle applied to conjunctions.

**When in doubt, in this order:**

1. If unsure whether a fact is necessary, leave it out.
2. If unsure whether the item has any condition at all, use `always`.
3. When two defensible conditions differ only in how restrictive they are, the weaker one stands, unless the item's text clearly requires the stronger.

These rules bias the model toward showing an item that did not need showing. That is intended.

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
