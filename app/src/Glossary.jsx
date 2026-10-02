export default function Glossary({ intro, terms }) {
  return (
    <main id="main-content">
      <div dangerouslySetInnerHTML={{ __html: intro }} />
      <dl className="gloss">
        {terms.map((term) => (
          <div key={term.id}>
            <dt id={term.id} dangerouslySetInnerHTML={{ __html: term.term }} />
            <dd dangerouslySetInnerHTML={{ __html: term.definition }} />
          </div>
        ))}
      </dl>
    </main>
  );
}
