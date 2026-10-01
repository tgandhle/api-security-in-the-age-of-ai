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

## Running the labs on Windows

`python3` is not a working command on a default Windows install. Use `py -3` in place of `python3`.

For the modules that need a package, install it into a virtual environment so it does not change the Python the rest of your machine uses:

```
py -3 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install cryptography==50.0.1
python labs/jwks_lab.py
```

Inside an activated environment use `python`, not `py -3`. The launcher ignores an active environment when given an explicit version: "To run the global interpreter, either deactivate the virtual environment, or explicitly specify the global Python version" (Python documentation, Using Python on Windows, Virtual environments). On macOS and Linux the equivalent is `python3 -m venv .venv` then `source .venv/bin/activate`.

The labs are pure in-process Python with no shell, subprocess or path handling, so their output does not vary by platform. Checked, not assumed: `labs/oauth_lab.py` produces output byte-identical to the transcript published on its page on Windows (Python 3.14.6, `py -3`) and on Linux (Python 3.11.15, `python3`). `tools/check_site.py` also produces identical output on both.

## Licence

Copyright (c) 2026 Tich Gandhle. All rights reserved. This repository is readable, not open source: see [LICENSE](LICENSE) for what that permits. Quoted specifications remain the property of their publishers and are cited on the page that quotes them.

## Working on the site

Plain HTML. Open `index.html` in any browser, or publish the folder with GitHub Pages. No build step is needed to view the site.

- Labs: `python3 labs/<lab>.py`. Modules 1, 2 and 4 need Python 3 and nothing else. Modules 3, 5, 6 and 7 additionally need `python3 -m pip install cryptography==50.0.1`, because Python has no built-in asymmetric cryptography. Those labs say so and exit cleanly if it is missing.
- After editing any checklist item on a topic page: `python3 tools/build_checklist.py`.
- To confirm the checklist is current: `python3 tools/build_checklist.py --check` (exits 1 if stale).
- After editing any lesson page: `python3 tools/extract_lessons.py`, which regenerates `content/`.

The lesson pages share one skeleton, `tools/page_template.tmpl`, and `tools/render_site.py` builds them from `content/`. The published HTML stays the source of truth: `content/` is extracted from it, not the other way round. Nothing in `content/` is edited by hand.

See `CONVENTIONS.md` for the page template and writing rules.

Before committing:

```
python3 tools/check_site.py              # links, anchors, dashes, secrets, checklist freshness
python3 tools/extract_lessons.py --check # pages rebuild from content/, numbering, staleness
python3 tools/render_site.py             # the shared template still reproduces every page
python3 tools/check_a11y.py              # axe-core, light and dark, desktop and mobile
```

All four exit 0 when the site is clean, and 1 with a named reason otherwise.

`check_a11y.py` is an author tool and needs Playwright and axe-core, installed once with the commands in its file header. It skips cleanly and exits 0 if they are absent, so it never blocks reading or editing a page.

Instructions for coding agents are in `AGENTS.md`.
