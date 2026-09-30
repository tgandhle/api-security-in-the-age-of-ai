# API Security in the Age of AI

## Start learning

Work through the published modules in order. Each lesson includes an attack example, controls, a runnable lab, and questions with answers.

| Module | Lesson | Python lab |
|---|---|---|
| 1 | [API keys](topics/api-keys/index.html) | [Run the API keys lab](labs/api_keys_lab.py) |
| 2 | [HMAC request signing](topics/hmac-request-signing/index.html) | [Run the HMAC lab](labs/hmac_lab.py) |

[Full module plan](index.html#path) · [Glossary](glossary/index.html) · [Review checklist](checklist/index.html)

**Reading the lessons:** Open the [hosted learning site](https://tgandhle.github.io/api-security-in-the-age-of-ai/) in a browser. You can also choose **Code > Download ZIP**, extract the archive, and open `index.html` locally. Reading the lessons needs no installation or build.

The lab links open Python source files. Download the project and run a lab with Python as described below.

## Working on the site

Plain HTML. Open `index.html` in any browser, or publish the folder with GitHub Pages. No build step is needed to view the site.

- Labs: `python3 labs/<lab>.py`. Modules 1, 2 and 4 need Python 3 and nothing else. Modules 3, 5, 6 and 7 additionally need `python3 -m pip install cryptography==50.0.1`, because Python has no built-in asymmetric cryptography. Those labs say so and exit cleanly if it is missing.
- After editing any checklist item on a topic page: `python3 tools/build_checklist.py`.
- To confirm the checklist is current: `python3 tools/build_checklist.py --check` (exits 1 if stale).

See `CONVENTIONS.md` for the page template and writing rules.

Before committing:

```
python3 tools/check_site.py   # links, anchors, dashes, secrets, checklist freshness
python3 tools/check_a11y.py   # axe-core, light and dark, desktop and mobile
```

`check_a11y.py` is an author tool and needs Playwright and axe-core, installed once with the commands in its file header. It skips cleanly and exits 0 if they are absent, so it never blocks reading or editing a page.

Instructions for coding agents are in `AGENTS.md`.
