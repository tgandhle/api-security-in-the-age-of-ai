export default function Roadmap({ blocks }) {
  return (
    <main id="main-content" tabIndex={-1}>
      {blocks.map((block, i) => (
        <div key={i} dangerouslySetInnerHTML={{ __html: block.html }} />
      ))}
    </main>
  );
}
