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
      {/* The next two paragraphs repeat the ones tools/build_checklist.py
          writes on the static page. Change both together. */}
      <p className="prose meta">
        Each item carries a default severity: Critical, High or Medium. The
        default answers one question: what does losing this one control allow,
        with no credit for any other control that makes the same decision?{" "}
        <strong>Critical:</strong> one request, or one piece of content an
        attacker supplies, directly reads or changes another party's data,
        takes over an identity or a credential, runs code or reaches a network
        it should not, or causes a consequential action nobody authorized.{" "}
        <strong>High:</strong> the same outcome needs exactly one thing first
        (a stolen credential, a position on the network path or inside the
        deployment, a victim's action, a trusted party, or an ordinary fault),
        or needs only repeated attempts, or the missing control allows
        unbounded cost or loss of availability. <strong>Medium:</strong>{" "}
        anything lower that still has a security effect. An item that detects
        or recovers is High when no other item does that job for a
        Critical-class event, and Medium otherwise. A test, review or record is
        rated one level below the control it assures. The full rubric is in{" "}
        <code>CONVENTIONS.md</code> in the repository.
      </p>
      <p className="prose meta">
        The default is a starting point and not the severity of a finding. Rate
        a finding in your own review by what the API exposes, who can reach it
        and what else stands in the way. An item that does not apply to your
        design is not a finding.
      </p>
      <ul className="checks">
        {items.map(({ check, slug, source }) => (
          <li key={check.id}>
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
