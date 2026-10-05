import { PARTS } from "./parts.js";

// The hero and overview are the prose the static home page already had, block
// for block. Between them sits a row of numbers, every one counted from
// content/ by entry-server.jsx at build time. The module list below is
// generated, so a new module needs no edit here.
export default function Home({ blocks, lessons, up, stats }) {
  const hero = blocks.filter(
    (b) => b.attrs && b.attrs.class === "course-hero");
  const rest = blocks.filter(
    (b) => !(b.attrs && b.attrs.class === "course-hero"));
  return (
    <main id="main-content" className="home">
      {hero.map((block, i) => (
        <div key={"hero" + i} className="home-hero"
             dangerouslySetInnerHTML={{ __html: block.html }} />
      ))}
      <section className="course-stats" aria-label="The course in numbers">
        <dl>
          {stats.map((stat) => (
            <div key={stat.label}>
              <dt>{stat.label}</dt>
              <dd>{stat.value}</dd>
            </div>
          ))}
        </dl>
      </section>
      {rest.map((block, i) => (
        <div key={i} className="home-block"
             dangerouslySetInnerHTML={{ __html: block.html }} />
      ))}
      <div className="parts">
        {PARTS.map((part) => {
          const mine = lessons.filter(
            (l) => l.module >= part.from && l.module <= part.to);
          if (!mine.length) return null;
          return (
            <section key={part.name} className="part">
              <div className="part-head">
                <h3>{part.name}</h3>
                <p className="part-count">
                  {mine.length} {mine.length === 1 ? "module" : "modules"}
                </p>
              </div>
              <ul className="path">
                {mine.map((lesson) => (
                  <li key={lesson.slug} data-course-lesson={lesson.slug}
                      data-course-quiz={lesson.slug + "-check"}>
                    <span className="num">{lesson.module}</span>
                    <span>
                      <a href={up + "topics/" + lesson.slug + "/index.html"}>
                        {lesson.title}
                      </a>
                      <span className="course-state" data-course-state>Ready</span>
                      <span className="course-state" data-course-assessment>
                        Quick check required
                      </span>
                    </span>
                  </li>
                ))}
              </ul>
            </section>
          );
        })}
      </div>
    </main>
  );
}
