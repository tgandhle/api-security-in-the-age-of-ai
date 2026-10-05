// A lesson renders the blocks extract_lessons.py captured, in order, as the
// markup they already are. The one block it replaces is the lesson-status
// line, which is numbering rather than content and belongs to the course.
export default function Lesson({ lesson, total }) {
  const blocks = lesson.record.blocks;
  return (
    <main id="main-content">
      {blocks.map((block, i) =>
        block.attrs && block.attrs.class === "lesson-status" ? (
          <LessonStatus key={i} number={lesson.lesson_number} total={total} />
        ) : (
          <div key={i} dangerouslySetInnerHTML={{ __html: block.html }} />
        )
      )}
    </main>
  );
}

function LessonStatus({ number, total }) {
  return (
    <section className="lesson-status" aria-label="Lesson progress">
      <div>
        <strong>Lesson {number} of {total}</strong>
        <span>Complete the lesson and quick check, then record your progress.</span>
      </div>
      <button className="button" type="button" data-mark-complete aria-pressed="false">
        Mark lesson complete
      </button>
    </section>
  );
}
