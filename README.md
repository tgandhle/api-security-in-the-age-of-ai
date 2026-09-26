# API security learning path

## Start learning

Work through the published modules in order. Each lesson includes an attack example, controls, a runnable lab, and questions with answers.

| Module | Lesson | Python lab |
|---|---|---|
| 1 | [API keys](topics/api-keys/index.html) | [Run the API keys lab](labs/api_keys_lab.py) |
| 2 | [HMAC request signing](topics/hmac-request-signing/index.html) | [Run the HMAC lab](labs/hmac_lab.py) |

[Full module plan](index.html#path) · [Glossary](glossary/index.html) · [Review checklist](checklist/index.html)

**Reading the lessons:** Open the [hosted learning site](https://tgandhle.github.io/api-security-in-the-age-of-ai/) in a browser. You can also choose **Code > Download ZIP**, extract the archive, and open `index.html` locally. No installation or build is needed.

The lab links open Python source files. Download the project and run a lab with Python as described below.

## Working on the site

Plain HTML. Open `index.html` in any browser, or publish the folder with GitHub Pages. No build step is needed to view the site.

- Labs: `python3 labs/<lab>.py` (Python 3, standard library only).
- After editing any checklist item on a topic page: `python3 tools/build_checklist.py`.
- To confirm the checklist is current: `python3 tools/build_checklist.py --check` (exits 1 if stale).

See `CONVENTIONS.md` for the page template and writing rules.

Before committing: `python3 tools/check_site.py` (links, anchors, dashes, secrets, checklist freshness).

Instructions for coding agents are in `AGENTS.md`.
