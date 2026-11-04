# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately, through GitHub's
[private vulnerability reporting](https://github.com/ErwinQuantum/shorwatch/security/advisories/new),
not in a public issue. Say what you found, how to reproduce it, and what it
lets an attacker do. You will get an answer within a week; once a fix is
released, the advisory is published with credit to you, unless you prefer
otherwise.

Only the latest release receives security fixes.

## What counts

Shorwatch reads repositories that may not be trustworthy (a pull request
from a fork, a dependency's sources) and writes reports that travel (CI
artifacts, job summaries, e-mail). Issues in that path are in scope, for
example:

- a scanned file that crashes the scan, hangs it or exhausts memory;
- text from a scanned file that runs script in the HTML report, injects
  markup into the Markdown job summary, or escape sequences or CI workflow
  commands into the terminal and logs;
- secrets from a scanned file (private keys) reaching a report;
- anything that makes Shorwatch read or write outside the paths it is given,
  its reports and its own cache folder, or run a program.

A missed detection or a false positive is not a vulnerability: open a
regular issue.

## What Shorwatch does to stay safe

- It never runs code from what it scans: sources are parsed, class files
  (`--classpath`) are read for signatures only.
- Binary formats (DER, keystores, class files, jars) are read by bounded,
  hand-written parsers; files over 4 MB are skipped, and so are jar entries
  over 16 MB.
- Source files are bounded in shape as well as size: one whose syntax tree
  nests deeper than 2,500 levels (real code, generated tables included, stays
  far below) is skipped with a warning, and every scanning thread has a large
  stack for what is left. A skipped file is reported on stderr, never
  silently: if a scan matters, read its warnings.
- Build files (`pom.xml`, Gradle scripts, version catalogs) are read as
  data: XML external entities and DTDs are never fetched, nesting and resolved
  coordinates are bounded, and every reader is linear in the file; a script is
  never evaluated.
- Private key bodies are redacted from the text reports show.
- Text from scanned files reaches the terminal and the CI log without
  control characters, and the HTML report as text only (`textContent`),
  under a Content-Security-Policy that forbids any network access; links
  are limited to the web, the report's own routes and the editor.
- Rules from other people (`--rules`) are data: their references must be
  web links, and their regular expressions run in linear time.
- Reports written for the terminal go to a per-user folder, and `shorwatch
  open` opens HTML files only.
- Release archives come with SHA-256 checksums and build provenance
  attestations (`gh attestation verify <file> --repo ErwinQuantum/shorwatch`).
- Shorwatch opens no network connection, listens on no port and runs no
  program but the system's opener for `shorwatch open`.

## Using it safely

- **Arguments are yours.** `--html`, `--out-dir`, `--output`, `--rules`,
  `--classpath` and `--baseline` read or write the paths you give them. In a
  pipeline that builds a pull request from a fork, never take those values
  from the branch under review.
- **Rules are code you trust.** A rule directory from someone else decides what
  is reported: read it as you would a script. It cannot run anything, but it
  can hide a finding.
- **A baseline hides what it records.** Review `shorwatch-baseline.json` in
  pull requests like any other file; the reports count what it leaves out.
- **Check the warnings.** A file Shorwatch could not read, or skipped for its
  size or nesting, is named on stderr and is not in the results.
