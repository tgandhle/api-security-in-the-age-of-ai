// The site chrome. The wording is the static site's, so nothing a crawler
// already indexed disappears. The layout is the hosted site's own: a sticky
// header with a mark, the five links, and two mounts the client fills (search
// and the theme switch). Both are created on the client rather than
// prerendered, so a reader with JavaScript off is never shown a control that
// does nothing.
// Only index.html carried a skip link. The other 30 pages had none, which is
// a bypass-block gap automated checks do not catch because the pages have a
// main landmark. Every page in the app gets one.
export function SkipLink() {
  return <a className="skip-link" href="#main-content">Skip to content</a>;
}

// An original mark drawn for this site: a shield outline holding a prompt.
// It is decoration beside the course name, so it is hidden from assistive
// technology.
export function Mark() {
  return (
    <svg className="mark" viewBox="0 0 24 24" width="22" height="22"
         aria-hidden="true" focusable="false">
      <path d="M12 2.5 4.5 5.2v6.1c0 4.6 3 8.4 7.5 10.2 4.5-1.8 7.5-5.6 7.5-10.2V5.2Z"
            fill="none" stroke="currentColor" strokeWidth="1.6"
            strokeLinejoin="round" />
      <path d="m8.6 9.4 2.6 2.3-2.6 2.3M12.7 14.3h2.9"
            fill="none" stroke="currentColor" strokeWidth="1.6"
            strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export function SiteNav({ up }) {
  return (
    <nav className="site-nav" aria-label="Site">
      <span className="nav-inner">
        <a className="home" href={up + "index.html"}>
          <Mark />
          <span>API Security in the Age of AI</span>
        </a>
        <span className="nav-links">
          <a href={up + "index.html#course"}>Course</a>
          <a href={up + "index.html#path"}>Modules</a>
          <a href={up + "roadmap/index.html"}>Roadmap</a>
          <a href={up + "checklist/index.html"}>Checklist</a>
          <a href={up + "glossary/index.html"}>Glossary</a>
        </span>
        <span className="nav-tools">
          <span id="search-mount" />
          <span id="theme-mount" />
        </span>
      </span>
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
