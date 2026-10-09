import { Fragment } from "react";

// What a severity means. One authored file, which tools/build_checklist.py
// reads too, so this page and the static page cannot say different things.
import summary from "../../data/severity-rubric-summary.json";

const ORDER = { Critical: 0, High: 1, Medium: 2 };

// Built from the same data tools/build_checklist.py reads, and laid out the
// way that tool lays it out: title, severity, detail, then the source lesson.
// The source text is the lesson's page title up to the pipe, which is what
// build_checklist.py:55 uses.
export default function Checklist({ lessons, up }) {
  const items = [];
  lessons.forEach((lesson) => {
    const source = lesson.record.page_title.split("|")[0].trim();
    lesson.record.checks.forEach((check) => {
      items.push({ check, slug: lesson.slug, source });
    });
  });
  items.sort((a, b) =>
    (ORDER[a.check.severity] - ORDER[b.check.severity]) ||
    a.check.id.localeCompare(b.check.id));
  return (
    <main id="main-content">
      <h1>Review checklist</h1>
      <p className="prose meta">
        Generated from the reference section of each lesson. {items.length} items,
        sorted by severity. Ticks are not saved.
      </p>
      <p className="prose meta">
        {summary.question}{" "}
        {summary.levels.map((level) => (
          <Fragment key={level.name}>
            <strong>{level.name}:</strong> {level.rule}{" "}
          </Fragment>
        ))}
        {summary.detecting_recovering} {summary.assuring}{" "}
        {summary.full_rubric.before} <code>{summary.full_rubric.file}</code>{" "}
        {summary.full_rubric.after}
      </p>
      <p className="prose meta">{summary.not_a_finding}</p>
      <p className="prose meta">
        For other tools: <a href="checklist.json">checklist.json</a> and{" "}
        <a href="checklist.csv">checklist.csv</a>, with each item&rsquo;s
        applicability condition. The checklist data is licensed{" "}
        <a href="https://creativecommons.org/licenses/by/4.0/">CC BY 4.0</a>;
        the lessons are not.
      </p>
      {/* Filled in the browser by ApplicabilityFilter.jsx. Empty here, so a
          reader with JavaScript off sees every item and no dead controls. */}
      <div id="applicability-mount" />
      <ul className="checks">
        {items.map(({ check, slug, source }) => (
          <li key={check.id} data-check={check.id}>
            <label>
              <input type="checkbox" />
              <span>
                <strong dangerouslySetInnerHTML={{ __html: check.title }} />
                <span className={"sev " + check.severity}>{check.severity}</span>
                <br />
                <span className="meta">
                  <span dangerouslySetInnerHTML={{ __html: check.detail }} />
                  {" Source: "}
                  <a href={up + "topics/" + slug + "/index.html#reference"}>{source}</a>.
                </span>
              </span>
            </label>
          </li>
        ))}
      </ul>
    </main>
  );
}
