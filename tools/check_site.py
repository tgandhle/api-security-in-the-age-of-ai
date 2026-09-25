"""Site checks. Run before every commit: python3 tools/check_site.py

Checks:
  1. Every internal link and #anchor resolves.
  2. No em dashes or en dashes in any site file.
  3. No strings that look like real secrets.
  4. checklist/index.html is up to date.
Exits 1 on any failure. Standard library only.
"""
import pathlib, re, subprocess, sys
from html.parser import HTMLParser

ROOT = pathlib.Path(__file__).resolve().parent.parent
SKIP_DIRS = {".git"}
TEXT_SUFFIXES = {".html", ".css", ".py", ".md", ".txt"}
SECRET_PATTERNS = [
    (r"sk_live_[A-Za-z0-9]{6,}", "live-style API key"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "private key block"),
    (r"AKIA[0-9A-Z]{16}", "AWS-style access key ID"),
    (r"(?i)(secret|password|api[_-]?key)\s*=\s*b?['\"][^'\"<>{}]{8,}['\"]", "hard-coded credential assignment"),
]


def files():
    for p in ROOT.rglob("*"):
        if p.is_file() and not SKIP_DIRS & set(p.relative_to(ROOT).parts):
            yield p


class Collect(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids, self.links = set(), []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if "id" in a:
            self.ids.add(a["id"])
        for attr in ("href", "src"):
            if a.get(attr):
                self.links.append(a[attr])


def main():
    errors = []
    pages = {}
    for p in files():
        if p.suffix == ".html":
            c = Collect()
            c.feed(p.read_text(encoding="utf-8"))
            pages[p.resolve()] = c
    n_links = 0
    for page, c in pages.items():
        for link in c.links:
            if re.match(r"^[a-z]+:", link):
                continue
            n_links += 1
            path, _, frag = link.partition("#")
            target = (page.parent / path).resolve() if path else page
            rel = page.relative_to(ROOT)
            if not target.exists():
                errors.append(f"{rel}: broken link {link}")
            elif frag and target in pages and frag not in pages[target].ids:
                errors.append(f"{rel}: missing anchor {link}")
    for p in files():
        if p.suffix not in TEXT_SUFFIXES or p.name == "check_site.py":
            continue
        rel = p.relative_to(ROOT)
        for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
            if "\u2014" in line or "\u2013" in line:
                errors.append(f"{rel}:{i}: em or en dash")
            for pattern, label in SECRET_PATTERNS:
                if re.search(pattern, line):
                    errors.append(f"{rel}:{i}: possible secret ({label})")
    result = subprocess.run([sys.executable, str(ROOT / "tools" / "build_checklist.py"), "--check"],
                            capture_output=True, text=True)
    if result.returncode != 0:
        errors.append((result.stderr or result.stdout).strip())
    print(f"checked {len(pages)} pages, {n_links} internal links")
    if errors:
        print(f"{len(errors)} problem(s):")
        for e in errors:
            print("  " + e)
        sys.exit(1)
    print("all checks passed")


if __name__ == "__main__":
    main()
