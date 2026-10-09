# Security policy

## Reporting a vulnerability

Report it privately, through GitHub's private vulnerability reporting: open the repository's **Security** tab, go to **Advisories**, and choose **Report a vulnerability**. Only the maintainer sees the report.

Please do not open a public issue, pull request or discussion for a vulnerability.

There is one maintainer and no fixed response time. Reports are read, answered, and fixed in the order of their severity, and you will be told what was decided. If you would like credit in the advisory or the fix, say so in the report.

## What to report privately

- The hosted site and the code that builds it: `app/`, `assets/`, and the pages it serves.
- The build, publishing and release machinery: `.github/workflows/`, `tools/`, and the pinned dependencies they install.
- A lab that does something it should not to the machine that runs it, such as reading or writing outside what its page describes, or running a command.
- An error in the course material that would lead a reader to deploy something exploitable, where saying so in public would put existing deployments at risk.

## What to report as a public issue

Ordinary corrections to the course: a wrong statement, a citation that does not say what the page claims, a broken link, a lab whose output no longer matches its page, an accessibility problem. Open an issue in this repository.

## Not vulnerabilities

- Deliberately weak code in a lab or a lesson that exists to show an attack. Each one is labelled on its page. Report it only if it can harm the machine running it, as above.
- Behaviour of GitHub Pages, of GitHub itself, or of a specification the course cites. Report those to their owners.

## Supported versions

The current `main` branch and the site published from it. Released versions are not patched separately; a fix goes into `main` and the next release.
