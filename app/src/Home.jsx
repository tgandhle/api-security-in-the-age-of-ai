import { PARTS } from "./parts.js";

// The hero and overview are the prose the static home page already had. The
// module list below them is generated, so a new module needs no edit here.
export default function Home({ blocks, lessons, up }) {
  return (
    <main id="main-content">
      {blocks.map((block, i) => (
        <div key={i} dangerouslySetInnerHTML={{ __html: block.html }} />
      ))}
      {PARTS.map((part) => {
        const mine = lessons.filter(
          (l) => l.module >= part.from && l.module <= part.to);
        if (!mine.length) return null;
        return (
          <section key={part.name}>
            <h3>{part.name}</h3>
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
    </main>
  );
}
