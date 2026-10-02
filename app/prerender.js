// Writes one real HTML file per lesson, so the lesson text is in the source a
// crawler reads and a page opened from disk still shows its content.
//
// React owns two regions, the lesson rail and the previous/next pair, and
// hydrates those. The lesson body is left as the markup extract_lessons.py
// captured; nothing re-renders it, so assets/course.js keeps working on it
// exactly as it does on the static site, including the lab runner.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const { routes, renderRegions, sitePages, renderSitePage, course } =
  await import("./dist-ssr/entry-server.js");

const manifest = JSON.parse(
  fs.readFileSync(path.join(here, "dist/.vite/manifest.json"), "utf8"));
const entry = manifest["src/entry-client.jsx"];
if (!entry) throw new Error("no client entry in the manifest");

// The published folder has to be complete on its own: the stylesheet and
// script the pages load, and the labs they link to and the runner fetches.
function copyInto(fromRel, toRel, keep) {
  const from = path.join(here, "..", fromRel);
  const to = path.join(here, "dist", toRel);
  fs.mkdirSync(to, { recursive: true });
  let n = 0;
  for (const name of fs.readdirSync(from)) {
    if (keep && !keep(name)) continue;
    const src = path.join(from, name);
    if (fs.statSync(src).isDirectory()) continue;
    fs.copyFileSync(src, path.join(to, name));
    n++;
  }
  return n;
}
const copiedAssets = copyInto("assets", "assets");
const copiedLabs = copyInto("labs", "labs",
  (name) => name.endsWith(".py") || name.endsWith(".lab.js"));

let written = 0;
for (const route of routes()) {
  const r = renderRegions(route);
  const up = route.up;
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${route.title}</title>
<link rel="stylesheet" href="${up}assets/site.css">
<script src="${up}assets/course.js" defer></script>
<script type="module" crossorigin src="${up}${entry.file}"></script>
</head>
<body data-course-lesson="${route.slug}" data-up="${up}">
${r.nav}
<div class="course-layout">
<div id="rail">${r.rail}</div>
<div class="course-main">
${r.body}
<div id="lesson-nav">${r.lessonNav}</div>
</div>
</div>
${r.footer}
</body>
</html>
`;
  const target = path.join(here, "dist", route.path);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, html, "utf8");
  written++;
}
// The four pages that are not lessons. No rail on these: they are the course
// surface, not a place you are part way through.
let others = 0;
for (const page of sitePages()) {
  const r = renderSitePage(page);
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${page.title}</title>
<link rel="stylesheet" href="${page.up}assets/site.css">
<script src="${page.up}assets/course.js" defer></script>
<script type="module" crossorigin src="${page.up}${entry.file}"></script>
</head>
<body data-up="${page.up}">
${r.nav}
${r.body}
${r.footer}
</body>
</html>
`;
  const target = path.join(here, "dist", page.path);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, html, "utf8");
  others++;
}
console.log(`prerendered ${written} of ${course.total} lessons and ${others} other pages`);
console.log(`copied ${copiedAssets} assets and ${copiedLabs} lab files`);
