// Previous and next, at the foot of every lesson. Zero of the 27 static pages
// had this.
export default function LessonNav({ previous, next, up }) {
  if (!previous && !next) return null;
  return (
    <nav className="lesson-nav" aria-label="Lesson">
      {previous ? (
        <a className="prev" href={up + "topics/" + previous.slug + "/index.html"}>
          <span>Previous</span>
          <strong>{previous.title}</strong>
        </a>
      ) : <span />}
      {next ? (
        <a className="next" href={up + "topics/" + next.slug + "/index.html"}>
          <span>Next</span>
          <strong>{next.title}</strong>
        </a>
      ) : <span />}
    </nav>
  );
}
