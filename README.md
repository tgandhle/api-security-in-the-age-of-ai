# API security learning path

Plain HTML. Open `index.html` in any browser, or publish the folder with GitHub Pages. No build step is needed to view the site.

- Labs: `python3 labs/<lab>.py` (Python 3, standard library only).
- After editing any checklist item on a topic page: `python3 tools/build_checklist.py`.
- To confirm the checklist is current: `python3 tools/build_checklist.py --check` (exits 1 if stale).

See `CONVENTIONS.md` for the page template and writing rules.

Before committing: `python3 tools/check_site.py` (links, anchors, dashes, secrets, checklist freshness).

Instructions for coding agents are in `AGENTS.md`.
