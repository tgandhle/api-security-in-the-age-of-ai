import coverage from "../../content/coverage.json";

// The page body tools/build_coverage.py generated, rendered as it is. The
// tool decides which lessons cite which OWASP entry by reading the lesson
// pages, so nothing about coverage is written here.
export default function Coverage() {
  return (
    <main id="main-content"
          dangerouslySetInnerHTML={{ __html: coverage.html }} />
  );
}
