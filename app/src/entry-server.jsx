import { renderToString } from "react-dom/server";
import Lesson from "./Lesson.jsx";
import Sidebar from "./Sidebar.jsx";
import LessonNav from "./LessonNav.jsx";
import { SiteNav, SiteFooter, SkipLink } from "./Shell.jsx";
import Home from "./Home.jsx";
import Glossary from "./Glossary.jsx";
import Checklist from "./Checklist.jsx";
import Roadmap from "./Roadmap.jsx";
import Coverage from "./Coverage.jsx";
import { course, lessons } from "./content.js";
import { home, glossary, roadmap } from "./pages.js";

export function sitePages() {
  return [
    { path: "index.html", up: "", title:
        "API Security in the Age of AI",
      render: (up) => <Home blocks={home.blocks} lessons={lessons} up={up} /> },
    { path: "glossary/index.html", up: "../", title:
        "Glossary | API Security in the Age of AI",
      render: () => <Glossary intro={glossary.intro} terms={glossary.terms} /> },
    { path: "checklist/index.html", up: "../", title:
        "Review checklist | API Security in the Age of AI",
      render: (up) => <Checklist lessons={lessons} up={up} /> },
    { path: "roadmap/index.html", up: "../", title:
        "Course roadmap | API Security in the Age of AI",
      render: () => <Roadmap blocks={roadmap.blocks} /> },
    { path: "coverage/index.html", up: "../", title:
        "OWASP coverage | API Security in the Age of AI",
      render: () => <Coverage /> }
  ];
}

export function renderSitePage(page) {
  return {
    nav: renderToString(<><SkipLink /><SiteNav up={page.up} /></>),
    body: renderToString(page.render(page.up)),
    footer: renderToString(<SiteFooter />)
  };
}

export function routes() {
  return lessons.map((lesson, at) => ({
    path: "topics/" + lesson.slug + "/index.html",
    up: "../../",
    slug: lesson.slug,
    title: lesson.record.page_title,
    at,
    lesson
  }));
}

// Three regions, rendered apart so the client can hydrate the two that need
// interactivity and leave the lesson body as the static markup it already is.
export function renderRegions(route) {
  return {
    nav: renderToString(<><SkipLink /><SiteNav up={route.up} /></>),
    rail: renderToString(
      <Sidebar lessons={lessons} current={route.slug} up={route.up}
               completed={[]} />),
    body: renderToString(<Lesson lesson={route.lesson} total={course.total} />),
    lessonNav: renderToString(
      <LessonNav
        previous={route.at > 0 ? lessons[route.at - 1] : null}
        next={route.at < lessons.length - 1 ? lessons[route.at + 1] : null}
        up={route.up} />),
    footer: renderToString(<SiteFooter />)
  };
}

export { course };
