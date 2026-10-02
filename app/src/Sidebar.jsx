// The lesson list, on every page. This is the thing the static site never had:
// a reader finishing one module could not reach the next without going back to
// the dashboard. It is prerendered, so it works with JavaScript off too.
export default function Sidebar({ lessons, current, up, completed }) {
  return (
    <nav className="course-rail" aria-label="Lessons">
      <p className="rail-title">Modules</p>
      <ol>
        {lessons.map((lesson) => {
          const here = lesson.slug === current;
          const done = completed && completed.indexOf(lesson.slug) !== -1;
          return (
            <li key={lesson.slug} className={here ? "here" : undefined}>
              <a
                href={up + "topics/" + lesson.slug + "/index.html"}
                aria-current={here ? "page" : undefined}
              >
                <span className="rail-num">{lesson.module}</span>
                <span className="rail-name">{lesson.title}</span>
                {done ? <span className="rail-done" aria-label="completed">done</span> : null}
              </a>
            </li>
          );
        })}
      </ol>
    </nav>
  );
}
