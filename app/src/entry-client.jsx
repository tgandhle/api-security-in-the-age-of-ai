import { createRoot, hydrateRoot } from "react-dom/client";
import Search from "./Search.jsx";
import Sidebar from "./Sidebar.jsx";
import LessonNav from "./LessonNav.jsx";
import { course, lessons } from "./course-index.js";

const storageKey = "api-security-in-the-age-of-ai-progress-v1";

function completed() {
  try {
    const saved = JSON.parse(window.localStorage.getItem(storageKey));
    if (saved && Array.isArray(saved.completed)) return saved.completed;
  } catch {
    // The rail renders without ticks if browser storage is unavailable.
  }
  return [];
}

const slug = document.body.dataset.courseLesson;
// Not `|| "../../"`: the home page's data-up is the empty string, which is
// falsy, so that form sent every link on it two directories up.
const up = document.body.dataset.up ?? "../../";
const at = lessons.findIndex((lesson) => lesson.slug === slug);

const rail = document.getElementById("rail");
if (rail) {
  hydrateRoot(rail, <Sidebar lessons={lessons} current={slug} up={up}
                             completed={completed()} />);
}

// On a narrow screen the rail is a short scrolling list, so bring the lesson
// the reader is on into view. Enhancement only: with JavaScript off the list
// still contains every link.
if (rail) {
  requestAnimationFrame(() => {
    const here = rail.querySelector('[aria-current="page"]');
    if (here && rail.querySelector("ol")) {
      const box = rail.querySelector("ol");
      if (box.scrollHeight > box.clientHeight + 1) {
        // Measured, not offsetTop: the list item is positioned, so offsetTop
        // resolves against it rather than against the scrolling list.
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
