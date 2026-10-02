import Lesson from "./Lesson.jsx";
import Sidebar from "./Sidebar.jsx";
import LessonNav from "./LessonNav.jsx";
import { SiteNav, SiteFooter } from "./Shell.jsx";

export default function App({ lessons, slug, total, up, completed }) {
  const at = lessons.findIndex((lesson) => lesson.slug === slug);
  const lesson = lessons[at];
  return (
    <>
      <SiteNav up={up} />
      <div className="course-layout">
        <Sidebar lessons={lessons} current={slug} up={up} completed={completed} />
        <div className="course-main">
          <Lesson lesson={lesson} total={total} />
          <LessonNav
            previous={at > 0 ? lessons[at - 1] : null}
            next={at < lessons.length - 1 ? lessons[at + 1] : null}
            up={up}
          />
        </div>
      </div>
      <SiteFooter />
    </>
  );
}
