import { createRoot, hydrateRoot } from "react-dom/client";
import Search from "./Search.jsx";
import ThemeToggle from "./ThemeToggle.jsx";
import Sidebar from "./Sidebar.jsx";
import LessonNav from "./LessonNav.jsx";
import { course, lessons } from "./course-index.js";

const slug = document.body.dataset.courseLesson;
// Not `|| "../../"`: the home page's data-up is the empty string, which is
// falsy, so that form sent every link on it two directories up.
const up = document.body.dataset.up ?? "../../";
const at = lessons.findIndex((lesson) => lesson.slug === slug);

const rail = document.getElementById("rail");
if (rail) {
  // Hydrated with no ticks, which is what was prerendered. Sidebar reads the
  // saved progress itself once it has mounted.
  hydrateRoot(rail, <Sidebar lessons={lessons} current={slug} up={up}
                             completed={[]} />);
}

// Bring the lesson the reader is on into view inside whichever box scrolls:
// the whole rail on a wide screen, the bounded list on a narrow one.
// Enhancement only: with JavaScript off the list still contains every link.
if (rail) {
  requestAnimationFrame(() => {
    const here = rail.querySelector('[aria-current="page"]');
    if (!here) return;
    const boxes = [rail.querySelector(".course-rail"),
                   rail.querySelector(".rail-list")];
    for (const box of boxes) {
      if (box && box.scrollHeight > box.clientHeight + 1) {
        // Measured, not offsetTop: the list item is positioned, so offsetTop
        // resolves against it rather than against the scrolling box.
        const item = here.getBoundingClientRect();
        const list = box.getBoundingClientRect();
        box.scrollTop += (item.top - list.top) - (list.height - item.height) / 2;
      }
    }
  });
}

const foot = document.getElementById("lesson-nav");
if (foot) {
  hydrateRoot(foot, <LessonNav
    previous={at > 0 ? lessons[at - 1] : null}
    next={at >= 0 && at < lessons.length - 1 ? lessons[at + 1] : null}
    up={up} />);
}

export { course };

// Search is client only. The box is created rather than hydrated, so the
// prerendered page offers nothing that will not work, and a reader with
// JavaScript off sees a nav without a search box instead of a dead one.
const mount = document.getElementById("search-mount");
if (mount) {
  createRoot(mount).render(<Search up={up} />);
}

// The theme switch is client only for the same reason. The theme itself is
// already applied: a stored choice by the inline script in <head>, and
// otherwise the system setting by theme.css. The switch is created, not
// hydrated, so it reads the theme in effect and there is nothing to mismatch.
// The checklist filter is client only too, and loaded only on the checklist
// page: it carries the applicability data, which no other page needs.
const applicabilityMount = document.getElementById("applicability-mount");
if (applicabilityMount) {
  import("./ApplicabilityFilter.jsx").then(({ default: ApplicabilityFilter }) => {
    createRoot(applicabilityMount).render(<ApplicabilityFilter />);
  });
}

const themeMount = document.getElementById("theme-mount");
if (themeMount) {
  createRoot(themeMount).render(<ThemeToggle />);
}
