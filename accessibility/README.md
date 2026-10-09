# Manual accessibility test

Automated checks (`tools/check_a11y.py`, axe-core) run on every page in light and dark mode at desktop and mobile width. They find a floor of problems, not all of them. This script is the manual pass that criterion 8 of [QUALITY.md](../QUALITY.md) asks for: a screen reader, the keyboard alone, and zoom, on three representative parts of the hosted site.

Record the result in a copy of [RECORD-TEMPLATE.md](RECORD-TEMPLATE.md), saved in `log/` as `YYYY-MM-DD-<tester>.md`. Every failure gets a disposition: fixed (with the commit), accepted (with the reason), or open.

It takes about an hour and a half. Test the published site, not a local build, and write down the commit the site was built from (the latest successful run of "Publish the site").

## What is tested

| Part | Address |
|---|---|
| A lesson, with its quick check, exercises and diagrams | <https://tgandhle.github.io/api-security-in-the-age-of-ai/topics/webhooks/index.html> |
| Its lab, run in the browser | the "Run this lab in your browser" button on the same page |
| The checklist with the applicability filter | <https://tgandhle.github.io/api-security-in-the-age-of-ai/checklist/index.html> |

The webhooks lesson is used because it has every kind of content a lesson has (headings, tables, diagrams, expandable answers, a quick check, exercises) and a lab that needs only Python's standard library, so it runs in the browser without the extra download the five `cryptography` labs need.

## Before you start

- Windows with NVDA. The key names below are those of the NVDA 2026.2 User Guide. NVDA's modifier key is `insert` by default, written `NVDA` below.
- One browser, Chrome or Firefox, at 100% zoom, with no extensions that change pages. Record its version.
- Clear the site's stored data for a clean start: the theme choice and completed lessons are kept in the browser.
- Keep the record open beside the browser and fill it in as you go. A step passes only if everything in its "Expect" column happens.

## Part 1. Keyboard only, no screen reader

Do not touch the mouse. Use `Tab`, `shift+Tab`, `Enter`, `Space` and the arrow keys.

| Step | Do | Expect |
|---|---|---|
| K1 | Open the lesson. Press `Tab` once. | A "Skip to content" link appears and has a visible focus outline. `Enter` moves focus to the lesson text. |
| K2 | Reload. `Tab` through the site header: course name, links, search box, theme switch. | Every one is reached in reading order and has a visible focus outline. Nothing focusable is invisible. |
| K3 | Operate the theme switch with `Enter` or `Space`. Operate it again. | The theme changes each time. Text stays readable. Focus stays on the switch. |
| K4 | Type a word such as "webhook" in the search box. Move into the results with the keyboard. Open one. | Results can be reached and opened without a mouse. `Escape` or `Tab` leaves the results without trapping focus. |
| K5 | On a narrow window, or at 200% zoom, find the lesson list control ("rail"). Open it and close it. | It opens and closes from the keyboard, and focus is not lost behind it. |
| K6 | `Tab` through the lesson body to the first expandable answer. Open it with `Enter` and close it again. | It opens and closes. Focus stays on its summary line. |
| K7 | At the quick check, choose an answer with the arrow keys, then reach "Check answer" with `Tab` and press `Enter`. | The answer can be chosen without a mouse, and feedback appears. |
| K8 | Do the same in one exercise. | Same as K7. |
| K9 | Reach "Mark lesson complete" and press it. Press it again. | It toggles each time, and its pressed state is visible. |
| K10 | Reach "Run this lab in your browser" and press it. Wait for the output. Then `Tab` to the output box. | The lab runs and prints its output. The output box can be focused and scrolled with the arrow keys. |
| K11 | Throughout Part 1: watch every focused element. | It is never hidden under the sticky site header or anything else. |
| K12 | Open the checklist. `Tab` to the filter. Open "Application shape" with `Enter`. | The group opens. |
| K13 | In the first question, use the arrow keys to choose "No". | The choice moves with the arrows, the count under the filter changes, and items disappear from the list below. |
| K14 | Choose "No" for "Is the API called from a web browser". Then choose "Yes" for "Does a browser authenticate to the system with a cookie". | The cookie answer is not applied, a message explains the conflict, and the radio stays on "Not known". |
| K15 | `Tab` to "Clear answers" and press it. | All answers return to "Not known" and the count returns to 325 of 325. |
| K16 | Answer one question "No" again, then open "Items set aside". | The list of set-aside items opens and each says which answer ruled it out. |
| K17 | Tick and untick one checklist item with `Space`. Reach the `checklist.json` and `checklist.csv` links. | Both work from the keyboard. |

## Part 2. NVDA

Start NVDA, then open the lesson. Stay in browse mode unless a step says otherwise; NVDA switches to focus mode in form fields. Press `control` at any time to stop speech.

| Step | Do | Expect |
|---|---|---|
| S1 | Load the lesson. | NVDA reads the page title, "Webhooks", with the site name. |
| S2 | Press `NVDA+f7` and look at the headings list. | One level 1 heading, the lesson title, and level 2 headings for the sections, in order, with no skipped levels that hide structure. |
| S3 | Press `d` repeatedly. | Landmarks are announced: the site navigation, the lessons navigation, the main content and the lesson navigation, each with a name that says what it is. |
| S4 | Press `h` through the page, then `2` through the level 2 headings. | Each heading is read with its level. |
| S5 | Press `t` to reach the first table. Use `control+alt+rightArrow` and `control+alt+downArrow` inside it. | The table is announced with its size, and moving between cells reads the column and row headers with each cell. |
| S6 | Reach each diagram. | Each is announced as a graphic with a text alternative that says what the diagram shows. The small icons in the header are not announced at all. |
| S7 | Reach an expandable answer and open it with `Enter`. | NVDA says whether it is collapsed or expanded, and reads the answer once it is open. |
| S8 | At the quick check, choose an answer and press "Check answer". | The question is read as the group's label when you enter the choices. The feedback is read out after pressing the button, without having to look for it. |
| S9 | Press "Mark lesson complete". | NVDA reports the change of state (pressed, or not pressed). |
| S10 | Press "Run this lab in your browser" and wait. | NVDA announces when the output arrives, without you moving to it. |
| S11 | Press `k` to move through links in the lesson body. | Every link's text says where it goes; none is just "here" or a bare address unless the address is the point. |
| S12 | Open the checklist. Press `NVDA+downArrow` from the top for a minute, then stop. | The introduction and severity explanation read in a sensible order. |
| S13 | Press `f` to reach the filter's first question. | NVDA reads the question as the group's label, then the choices "Yes", "No", "Not known" with the selected one. |
| S14 | Answer "No" to the webhook question. | NVDA announces the new count ("Showing 316 of 325 items. 9 set aside.") without you moving to it. |
| S15 | Repeat K14 (browser "No", then cookie "Yes"). | NVDA reads the conflict message straight away. |
| S16 | Move to the cookie question after answering "No" to the browser question. | NVDA can reach and read the note under it, "Treated as No, from your answer to ...". |
| S17 | Open "Items set aside" and read the first item. | Title, severity, id, the answer that ruled it out, and the reason are all read. |
| S18 | Press `l` to the checklist and read two items. | Each item's checkbox is announced with the item's title as its label. |

## Part 3. Zoom and reflow

Use the browser's own zoom (`control` with `+` and `-`), with the window maximised on a 1280 pixel wide screen or wider. At 400% on a 1280 pixel window the page is 320 CSS pixels wide, which is the width WCAG 2.2 uses for reflow (1.4.10).

| Step | Do | Expect |
|---|---|---|
| Z1 | Lesson at 200%. Read from top to bottom. | No text is cut off or overlaps other text. Every control is still usable. |
| Z2 | Lesson at 400%. | The page scrolls only vertically, except inside tables, diagrams and code, which may scroll inside their own box. Note any part that makes the whole page scroll sideways. |
| Z3 | At 400%, repeat K6, K7 and K10 with the keyboard. | They still work, and focus is never hidden under the site header. |
| Z4 | Checklist at 200% and 400%. Repeat K13 to K16. | The filter is usable, the questions and choices are not cut off, and the count and the conflict message are visible. |
| Z5 | Switch to the dark theme and repeat Z1 at 200%. | Same as Z1. |

## What this does not cover

Other screen readers (JAWS, VoiceOver, TalkBack), mobile devices, speech input, and every lesson. One pass over three parts is the minimum the criterion asks for, not a conformance claim. The record says so.
