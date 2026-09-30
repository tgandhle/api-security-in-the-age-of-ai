# AGENTS.md

Instructions for coding agents working in this repository. Read this file, `CONVENTIONS.md`, and `topics/hmac-request-signing/index.html` before starting any task. The HMAC page is the reference implementation of the page template: match its structure, tone, and markup.

## What this project is

A static learning site that teaches API security to new security engineers. Each topic page teaches one attack and the controls that stop it, with a runnable lab, then gives a reference section for design reviews.

- Audience: new security engineers. Assume they can read Python and HTTP. Do not assume they know the vocabulary.
- Format: hand-written HTML and one shared stylesheet, `assets/site.css`. No site generator, no framework, no JavaScript build. This applies to every published page and to `assets/`.
- Exception, `react-poc/`: an isolated Vite and React experiment asking whether a framework would pay for itself across 27 modules. It is not published, not deployed, and not checked by `tools/check_site.py`. It is not the source of truth for any lesson. Never author or correct lesson content there first, and never copy content out of it into a published page. If its copy of a lesson drifts from the HTML, delete the copy rather than reconcile it. Its existing dependencies (React, React DOM, Vite, oxlint, `@types/*`) are already in the lockfile; rule 7 still applies to anything new.
- Labs: Python 3, standard library only. Modules 3, 5, 6 and 7 may also use `cryptography==50.0.1`, because Python has no asymmetric primitives. Those labs must exit with a clear message rather than a traceback when it is absent, and their page must say a package is needed.
- The site must work when opened from local files (`file://`) as well as on GitHub Pages. Use relative links only.

## Current state

For module status, read `index.html`. A module with a plain link is published. A module
with `class="planned"` links to its roadmap entry and is not built. Do not restate module
status here; this file goes stale and `index.html` does not.

These do not change:

| Path | Role |
|---|---|
| `topics/hmac-request-signing/` | The reference implementation of the page template. Copy its structure, tone, and markup. |
| `topics/<slug>/index.html` | One module per directory. Learn layer, then Reference layer. |
| `labs/<topic>_lab.py` | One lab per module. Python 3, standard library only. |
| `glossary/index.html` | Alphabetical. Add terms as modules need them. |
| `checklist/index.html` | Generated. Never edit by hand. |
| `assets/site.css`, `assets/course.js` | The only stylesheet and the only script the site uses. |
| `tools/build_checklist.py` | Regenerates the checklist from topic pages. `--check` exits 1 if stale. |
| `tools/check_site.py` | Links, anchors, dashes, secrets, checklist freshness. Skips `react-poc/`. |
| `tools/check_a11y.py` | axe-core against every page, light and dark, desktop and mobile. Author tool. Skips cleanly if not installed. |
| `react-poc/` | Out of scope. See Format above. |

## Hard rules

These apply to every change. If a task seems to require breaking one, stop and ask.

1. **Never invent facts.** No made-up RFC numbers, spec sections, header names, library functions, CVEs, statistics, or quotes. Before citing a source, open it and confirm it says what the page claims. If you cannot verify something, leave it out or mark it as unknown in your report. Do not guess.
2. **Primary sources only** in the Sources list: RFCs, NIST, OWASP, official specifications, and official language or library documentation. No vendor blogs, no Medium posts, no AI-generated summaries. Pin versioned specs to a named revision and date.
3. **Label every control** in the Reference section as Standard, Baseline, or Option (see `CONVENTIONS.md`). A Standard label needs a citation that actually requires it. If a spec only recommends something, say "recommends," not "requires."
4. **No secrets anywhere.** Not in code, examples, comments, or screenshots. Use placeholders such as `<secret from vault>` or `<api-key>`. Labs generate keys at runtime or read them from a file passed on the command line. Do not read secrets from environment variables in labs, and do not present environment variables as the production pattern.
5. **Fictional names only.** Use companies such as ExampleAir and ExampleHotels, and the reserved `.example` domain. Do not name real companies, real products as examples of victims, or real people. Do not reference any employer.
6. **Run everything you publish.** Every lab and every code sample that shows output must be executed, and the page must show the real output, pasted from the run. Never type expected output by hand.
7. **Dependencies are decided, not assumed.** Two are approved, both as of 2026-09-29:
   - `cryptography==50.0.1` for labs that need asymmetric keys, which is modules 3, 5, 6 and 7. It requires Python 3.9 or later.
   - `playwright==1.56.0` and `axe-core@4.13.0` for `tools/check_a11y.py`.

   The distinction that matters: a dependency in `labs/` is a **learner** dependency and breaks the promise that the course runs with Python 3 alone, so it needs a reason, a graceful skip, and a note on the page. A dependency in `tools/` is an **author** dependency and costs the learner nothing. Anything beyond the two above, in either place, including CDN scripts and fonts: stop and ask, and propose a specific package and version.
8. **Never edit `checklist/index.html` by hand.** Edit checklist items on topic pages, then run `python3 tools/build_checklist.py`.
9. **Smallest change that does the job.** Do not refactor, rename, or restyle existing pages while adding a module. If the shared CSS needs a change, make it minimal and check the HMAC page still renders correctly.
10. **Writing style:**
    - Plain English, active voice, short sentences.
    - Sentence case headings.
    - No buzzwords and no marketing tone.
    - Never use em dashes or en dashes. Use a comma, period, colon, or parentheses. `tools/check_site.py` enforces this.

## Stop and ask before

- Adding any dependency beyond the two approved in rule 7.
- Adding anything to `react-poc/`, or moving published content into it.
- Deciding for or against the React migration.
- Deleting or renaming any file.
- Changing the page template structure or the claim-label scheme.
- Any git history rewrite or force push.
- Adding CI configuration.
- Publishing claims about a spec you could not open and read.

## How to build one module

Work on one module per task unless told otherwise.

1. **Research.** Open the primary sources for the topic. Note the exact revision and date of each. Write down the claims you will make and where each comes from.
2. **Write the lab first.** Put it in `labs/<topic>_lab.py`. It must:
   - Demonstrate the attack succeeding without the control, then failing with it.
   - Use deterministic inputs where possible, so the page output matches every run.
   - Bind any local server to `127.0.0.1` only.
   - Exit non-zero on unexpected results.
3. **Run the lab** and keep the real output.
4. **Write the page** at `topics/<topic-slug>/index.html` by copying the HMAC page structure:
   - The Learn layer has eight numbered sections: attack, why it works, control, defaults, what it proves, prove it, lab, check your understanding.
   - The Reference layer has controls, checklist items, and sources.
   - Include "Last reviewed YYYY-MM-DD" with today's date.
   - Link glossary terms on first use, and add any missing terms to `glossary/index.html`. Keep the glossary alphabetical, and give each term an `id` in lowercase with hyphens.
5. **Checklist items** use this exact markup, with ids prefixed by the topic, for example `jwt-01`:
   ```html
   <li data-check="jwt-01" data-severity="Critical"><strong>Title</strong> <span>Detail sentence.</span></li>
   ```
   Severity is one of `Critical`, `High`, `Medium`.
6. **Link the module** from `index.html`. Replace its `<span class="planned">` with a link.
7. **Regenerate and verify:**
   ```sh
   python3 tools/build_checklist.py
   python3 tools/check_site.py
   python3 tools/check_a11y.py
   python3 labs/<topic>_lab.py
   ```
8. **Visual check.** If you have a browser available, open the new page in light and dark mode and at a narrow width. If you do not, say "not visually checked" in your report.
9. **Commit** with a plain, factual message, for example `Add module 5: JWT validation`. One module per commit.

## Definition of done for a module

- [ ] `python3 tools/check_site.py` prints `all checks passed`.
- [ ] `python3 tools/check_a11y.py` prints `no accessibility violations`, or your report says it was skipped and why.
- [ ] The lab runs, and the page shows its real output.
- [ ] Every Standard label has a primary source that you opened.
- [ ] Every Sources entry is a primary source with a pinned revision if the spec is versioned.
- [ ] New glossary terms are added and linked.
- [ ] The module is linked from `index.html`.
- [ ] Your report lists what you ran, the real output, anything you could not verify, and anything not visually checked.

## Report format

End each task with:

- **Changed:** files added or edited.
- **Ran:** each command and its actual output (trimmed if long).
- **Unverified:** claims or sources you could not confirm, or "none".
- **Questions:** anything that needs a decision, or "none".

Do not claim a check passed unless you ran it and saw it pass.

## Module plan

Build in this order. Each line gives the core attack and the lab idea. Details and extra sources come from your research. Do not treat this list as a source.

**Primer** (`topics/primer/`)
- Hash vs HMAC vs signature, symmetric vs asymmetric keys, what TLS and mTLS prove, authentication vs authorization, bearer vs sender-constrained credentials, trust boundaries.
- Lab: hash vs HMAC vs signature. Signature parts use `cryptography` per rule 7.
- The primer does not need the full eight-section attack structure. Keep the Reference layer, and include checklist items only if they are real review items.

**Part 1: Proving who is calling**
1. **API keys.** Attack: a key leaked in a URL or log is reused. Lab: a log scanner that finds credentials in query strings.
2. **HMAC request signing.** Done.
3. **Asymmetric request signing** (RFC 9421). Attack: a receiver with a shared key forges caller requests. Lab: sign with a private key, verify with a public key, show the verifier cannot sign. Uses `cryptography` per rule 7.
4. **OAuth basics.** Client credentials, authorization code with PKCE, and why the implicit and password grants are obsolete. Lab: walk a client credentials exchange against a local stub.
5. **JWT validation.** Attacks: `alg:none`, RS256 to HS256 confusion, wrong audience. Lab: a vulnerable and a fixed verifier. RSA keys come from `cryptography` per rule 7; write the validation by hand rather than calling a JWT library, because the validation is the lesson.
6. **JWKS, revocation, and introspection.** Attacks: stale or ambiguous keys, tokens that cannot be revoked. Lab: JWKS cache states, including unknown `kid`, duplicate `kid`, and malformed refresh.
7. **Sender-constrained tokens: mTLS and DPoP.** Attack: stolen bearer token replay. Lab: replay of a bound vs an unbound token.
8. **Workload and agent identity lifecycle.** Attack: orphaned credentials. This is a design exercise, not a code lab.

**Part 2: Deciding what they may do**
9. **Object-level authorization.** Attack: BOLA. Lab: a toy API returns another user's order, then the fix.
10. **Property and function authorization.** Attack: mass assignment and admin routes. Lab: `PATCH` with `"role": "admin"`.
11. **Business flows and idempotency.** Attack: duplicate credit on retry. Lab: a retry with a new request ID credits twice without an idempotency key.

**Part 3: Edges and boundaries**
12. **Gateway enforcement.** Attack: direct service access around the gateway. Design exercise.
13. **Request and response contracts.** Attacks: duplicate keys, deep nesting, oversized decoded bodies. Lab: schema fuzzing.
14. **SSRF and unsafe consumption of APIs.** Attack: metadata-endpoint fetch via redirect. Lab: a local fetcher with redirect revalidation. Local addresses only; never call real cloud metadata endpoints.
15. **Rate limiting and cost.** Attack: low-rate abuse and token-cost exhaustion. Lab: compare fixed window and token bucket.
16. **Webhooks.** Attack: replayed or forged events. Lab: a webhook receiver with replay.
17. **CORS.** Attack: origin reflection with credentials. Lab: a reflecting server vs an allowlist.
18. **Versioning and deprecation.** Attack: an unpatched old version. Inventory exercise.

**Part 4: AI and agents**
19. **Delegation and token exchange** (RFC 8693). Attack: token passthrough and confused deputy.
20. **MCP.** Pin to MCP specification revision 2026-07-28, and check whether a newer revision exists before writing. Attacks: token passthrough, tool-description injection, unauthenticated servers.
21. **A2A.** The current specification version is unknown: find it and confirm it before writing. Also confirm whether agent card signing exists in that version; do not assume it does. Attacks: agent card impersonation, credential requests mid-task, push-notification URL used for SSRF.
22. **Prompt injection and output handling.** Attack: indirect injection via retrieved content.
23. **Agent authority and approvals.** Attack: an approval reused after parameters change.
24. **Data in model context.** Attack: secrets and personal data leaking through prompts and logs.
25. **Supply chain, retrieval, and memory.** Attacks: poisoned documents, cross-tenant vector matches.

**Capstone.** A design review of a sample architecture using the checklist.

Labs for Part 4 must not call real model APIs. Use local stubs that simulate model behavior.

## Candidate primary sources

These are starting points to open and verify, not citations to copy. Confirm each one says what you claim before citing it.

- OAuth 2.0: RFC 6749. PKCE: RFC 7636. OAuth security best current practice: RFC 9700.
- JWT: RFC 7519. JWT best current practices: RFC 8725. JWT access token profile: RFC 9068. JWK: RFC 7517.
- Revocation: RFC 7009. Introspection: RFC 7662. mTLS-bound tokens: RFC 8705. DPoP: RFC 9449. Token exchange: RFC 8693. Rich authorization requests: RFC 9396. Resource indicators: RFC 8707. Protected resource metadata: RFC 9728.
- HTTP message signatures: RFC 9421. Digest fields: RFC 9530. HMAC: RFC 2104 and NIST FIPS 198-1.
- OWASP API Security Top 10 2023, OWASP Top 10 for LLM Applications 2025, OWASP Top 10 for Agentic Applications 2026.
- MCP specification, revision 2026-07-28. A2A specification: version to be confirmed.
