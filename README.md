# API Security in the Age of AI

## Start learning

Work through the published modules in order. Each lesson includes an attack example, controls, a runnable lab, and questions with answers.

| Module | Lesson | Python lab |
|---|---|---|
| 0 | [Security concepts for the course](topics/security-foundations/index.html) | [`foundations_lab.py`](labs/foundations_lab.py) |
| 1 | [API keys](topics/api-keys/index.html) | [`api_keys_lab.py`](labs/api_keys_lab.py) |
| 2 | [HMAC request signing](topics/hmac-request-signing/index.html) | [`hmac_lab.py`](labs/hmac_lab.py) |
| 3 | [Asymmetric request signing](topics/asymmetric-request-signing/index.html) | [`asymmetric_signing_lab.py`](labs/asymmetric_signing_lab.py) |
| 4 | [OAuth basics](topics/oauth-basics/index.html) | [`oauth_lab.py`](labs/oauth_lab.py) |
| 5 | [JWT validation](topics/jwt-validation/index.html) | [`jwt_lab.py`](labs/jwt_lab.py) |
| 6 | [JWKS, revocation and introspection](topics/jwks-and-revocation/index.html) | [`jwks_lab.py`](labs/jwks_lab.py) |
| 7 | [Sender-constrained tokens: mTLS and DPoP](topics/sender-constrained-tokens/index.html) | [`bound_tokens_lab.py`](labs/bound_tokens_lab.py) |
| 8 | [Workload and agent identity lifecycle](topics/credential-lifecycle/index.html) | [`credential_inventory_lab.py`](labs/credential_inventory_lab.py) |
| 9 | [Object-level authorization](topics/object-level-authorization/index.html) | [`object_authorization_lab.py`](labs/object_authorization_lab.py) |
| 10 | [Property and function authorization](topics/property-and-function-authorization/index.html) | [`property_function_lab.py`](labs/property_function_lab.py) |
| 11 | [Business flows and idempotency](topics/business-flows-and-idempotency/index.html) | [`idempotency_lab.py`](labs/idempotency_lab.py) |
| 12 | [Gateway enforcement](topics/gateway-enforcement/index.html) | [`gateway_paths_lab.py`](labs/gateway_paths_lab.py) |
| 13 | [Request and response contracts](topics/request-and-response-contracts/index.html) | [`contracts_lab.py`](labs/contracts_lab.py) |
| 14 | [SSRF and unsafe consumption of APIs](topics/ssrf-and-unsafe-consumption/index.html) | [`ssrf_lab.py`](labs/ssrf_lab.py) |
| 15 | [Rate limiting and cost controls](topics/rate-limiting-and-cost/index.html) | [`rate_limit_lab.py`](labs/rate_limit_lab.py) |
| 16 | [Webhooks](topics/webhooks/index.html) | [`webhook_lab.py`](labs/webhook_lab.py) |
| 17 | [CORS](topics/cors/index.html) | [`cors_lab.py`](labs/cors_lab.py) |
| 18 | [Versioning and deprecation](topics/versioning-and-deprecation/index.html) | [`versions_lab.py`](labs/versions_lab.py) |
| 19 | [Delegation and token exchange](topics/delegation-and-token-exchange/index.html) | [`token_exchange_lab.py`](labs/token_exchange_lab.py) |
| 20 | [MCP server authorization](topics/mcp-server-authorization/index.html) | [`mcp_auth_lab.py`](labs/mcp_auth_lab.py) |
| 21 | [Agent-to-agent (A2A)](topics/agent-to-agent/index.html) | [`a2a_lab.py`](labs/a2a_lab.py) |
| 22 | [Prompt injection and output handling](topics/prompt-injection-and-output-handling/index.html) | [`injection_lab.py`](labs/injection_lab.py) |
| 23 | [Agent authority and approvals](topics/agent-authority-and-approvals/index.html) | [`approvals_lab.py`](labs/approvals_lab.py) |
| 24 | [Data in model context](topics/data-in-model-context/index.html) | [`context_data_lab.py`](labs/context_data_lab.py) |
| 25 | [Supply chain, retrieval, and memory](topics/supply-chain-retrieval-and-memory/index.html) | [`retrieval_lab.py`](labs/retrieval_lab.py) |
| 26 | [Design review of a sample architecture using the checklist](topics/design-review/index.html) | [`design_review_lab.py`](labs/design_review_lab.py) |
| 27 | [Attacks on authentication endpoints](topics/authentication-endpoints/index.html) | [`auth_endpoints_lab.py`](labs/auth_endpoints_lab.py) |
| 28 | [Browser sessions, cookies and CSRF](topics/browser-sessions-and-csrf/index.html) | [`csrf_lab.py`](labs/csrf_lab.py) |
| 29 | [Security misconfiguration](topics/security-misconfiguration/index.html) | [`misconfiguration_lab.py`](labs/misconfiguration_lab.py) |
| 30 | [Logging, detection and response](topics/logging-and-detection/index.html) | [`detection_lab.py`](labs/detection_lab.py) |
| 31 | [Agent code execution and containment](topics/agent-containment/index.html) | [`containment_lab.py`](labs/containment_lab.py) |
| 32 | [Model and artifact supply chain](topics/model-supply-chain/index.html) | [`model_supply_chain_lab.py`](labs/model_supply_chain_lab.py) |
| 33 | [GraphQL, gRPC and WebSocket APIs](topics/graphql-grpc-and-websocket/index.html) | [`protocols_lab.py`](labs/protocols_lab.py) |
| 34 | [Testing API security](topics/security-testing/index.html) | [`security_testing_lab.py`](labs/security_testing_lab.py) |

[Full module plan](index.html#path) · [Glossary](glossary/index.html) · [Review checklist](checklist/index.html) · [OWASP coverage](coverage/index.html)

**Reading the lessons:** Open the [hosted learning site](https://tgandhle.github.io/api-security-in-the-age-of-ai/) in a browser. The hosted site is the React build in `app/`: the same lessons, with a lesson rail and site-wide search. You can also choose **Code > Download ZIP**, extract the archive, and open `index.html` locally. That opens the static pages the build is made from, and reading them needs no installation or build.

The lab links open Python source files. Download the project and run a lab with Python as described below.

## Running the labs on Windows

Use `py -3` in place of `python3` on Windows. The Python install manager does add a `python3` command, but the Python documentation says it "is not meant to be widely used or recommended".

For the modules that need a package, install it into a virtual environment so it does not change the Python the rest of your machine uses:

```
py -3 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install cryptography==50.0.1
python labs/jwks_lab.py
```

Inside an activated environment use `python`, not `py -3`. The `py` command uses an active environment only when no version is requested: "If you are running in an active virtual environment, have not requested a particular version, and there is no shebang line, the default runtime will be that virtual environment" (Python 3.14 documentation, Using Python on Windows, Python install manager, Basic use). On macOS and Linux the equivalent is `python3 -m venv .venv` then `source .venv/bin/activate`.

The labs are pure in-process Python with no shell or subprocess, and the only file access is the optional `--key-file` in `hmac_lab.py`, so their output does not vary by platform. Checked, not assumed: `tools/check_transcripts.py` runs every lab whose output is published and compares it to the page byte for byte. All 35 match on Windows (Python 3.14.6, `python` in an activated environment) and on Linux (Python 3.13.16 and 3.14.6, `python3`), all with `cryptography==50.0.1`. `tools/check_site.py` also produces identical output on both. Where that package is absent, the four labs that need it are reported as skipped rather than as passing.

## Licence

Copyright (c) 2026 tgandhle. All rights reserved. This repository is readable, not open source: see [LICENSE](LICENSE) for what that permits. Quoted specifications remain the property of their publishers and are cited on the page that quotes them.

## Working on the site

Plain HTML. Open `index.html` in any browser, or publish the folder with GitHub Pages. No build step is needed to view the site.

- Labs: `python3 labs/<lab>.py`. Every module except 3, 5, 6 and 7 needs Python 3 and nothing else. Modules 3, 5, 6 and 7 additionally need `python3 -m pip install cryptography==50.0.1`, because Python has no built-in asymmetric cryptography. Those labs say so and exit cleanly if it is missing.
- After editing any checklist item on a topic page: `python3 tools/build_checklist.py`.
- To confirm the checklist is current: `python3 tools/build_checklist.py --check` (exits 1 if stale).
- After editing any lesson page: `python3 tools/extract_lessons.py`, which regenerates `content/lessons/`.
- After editing the home page, the glossary or the roadmap: `python3 tools/extract_pages.py`, which regenerates `content/pages.json`.
- After either of those: `python3 tools/build_search_index.py`, which regenerates `assets/search-index.js`.

The lesson pages share one skeleton, `tools/page_template.tmpl`, and `tools/render_site.py` builds them from `content/`. The published HTML stays the source of truth: `content/` is extracted from it, not the other way round. Nothing in `content/` is edited by hand.

See `CONVENTIONS.md` for the page template and writing rules.

`app/` is the React build that the hosted site serves. It reads `content/`, prerenders every lesson and the five other pages so the HTML is the same text a crawler read before, and adds a lesson rail and site-wide search. `cd app`, `npm ci`, `npm run build`; the output is `app/dist/`, which is not tracked. `.github/workflows/pages.yml` runs the standard-library checks, builds the app and publishes `app/dist` on every push to `main`. The static pages stay in the repository as the source of truth, and both have to pass their checks. The reasons are under Decisions in `AGENTS.md`.

Before committing:

```
python3 tools/check_site.py              # links, anchors, dashes, secrets, checklist freshness
python3 tools/extract_lessons.py --check # pages rebuild from content/, numbering, staleness
python3 tools/render_site.py             # the shared template still reproduces every page
python3 tools/build_lab_bundles.py --check  # the .lab.js copies still match the .py files
python3 tools/extract_pages.py --check   # content/pages.json matches the home, glossary and roadmap
python3 tools/build_search_index.py --check  # assets/search-index.js matches content/
python3 tools/check_transcripts.py       # runs every lab and compares its output to the page
python3 tools/check_a11y.py              # axe-core, light and dark, desktop and mobile
python3 tools/check_a11y.py --app        # the same against app/dist, after npm run build in app/
```

All eight exit 0 when the site is clean, and 1 with a named reason otherwise.

`check_a11y.py` is an author tool and needs Playwright and axe-core, installed once with the commands in its file header. It skips cleanly and exits 0 if they are absent, so it never blocks reading or editing a page.

Instructions for coding agents are in `AGENTS.md`.
