// The site chrome. Kept identical in wording to the static site so nothing a
// crawler already indexed disappears, and so the two look the same during the
// changeover.
// Only index.html carried a skip link. The other 30 pages had none, which is
// a bypass-block gap automated checks do not catch because the pages have a
// main landmark. Every page in the app gets one.
export function SkipLink() {
  return <a className="skip-link" href="#main-content">Skip to content</a>;
}

export function SiteNav({ up }) {
  return (
    <nav className="site-nav" aria-label="Site">
      <div>
        <a className="home" href={up + "index.html"}>API Security in the Age of AI</a>
        <a href={up + "index.html#course"}>Course</a>
        <a href={up + "index.html#path"}>Modules</a>
        <a href={up + "roadmap/index.html"}>Roadmap</a>
        <a href={up + "checklist/index.html"}>Checklist</a>
        <a href={up + "glossary/index.html"}>Glossary</a>
        <span id="search-mount" />
      </div>
    </nav>
  );
}

export function SiteFooter() {
  return (
    <footer>
      Part of API Security in the Age of AI. Examples use fictional companies
      and the reserved <code>.example</code> domain. No real keys appear on
      this site.
    </footer>
  );
}
