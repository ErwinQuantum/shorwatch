//! The human-readable terminal report.
//!
//! [`render`] produces the summary (by default nothing else: the HTML report
//! is where findings are browsed), optionally preceded by the findings (an
//! overview, every finding in detail, or one line each), and where to look
//! next;
//! [`banner`] is printed separately by the CLI, only on interactive terminals.

mod banner;
mod compact;
mod detailed;
mod overview;
mod style;
#[cfg(test)]
mod tests;
mod wrap;

use std::collections::BTreeSet;
use std::fmt::Write as _;

pub use banner::banner;
use style::{accent, bold, dim, failure as rgb_red, paint};

use crate::Scan;
use crate::summary::severity_label;

#[derive(Debug, Clone, Default)]
pub struct Options {
    pub view: View,
    /// Where the HTML report of this scan can be opened (a `file://` URL or
    /// wherever CI publishes it), shown below the summary.
    pub report: Option<String>,
    /// The report was opened in the browser already.
    pub opened: bool,
    /// A CI log: no hints about commands to run next.
    pub ci: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum View {
    /// Counts only.
    #[default]
    Summary,
    /// Files with findings and the most urgent ones explained.
    Overview,
    /// Every finding, explained.
    Details,
    /// One line per finding.
    Compact,
}

pub fn render(scan: &Scan, options: &Options) -> String {
    let mut out = String::new();
    match options.view {
        View::Summary => {}
        View::Overview => out.push_str(&overview::render(scan)),
        View::Compact => out.push_str(&compact::render(scan)),
        View::Details => {
            let blocks: Vec<_> = scan
                .findings
                .iter()
                .map(|f| detailed::render(scan, f))
                .collect();
            out.push_str(&blocks.join("\n"));
        }
    }
    out.push_str(&summary(scan));
    out.push_str(&next(scan, options));
    out
}

/// Where to look next: the HTML report, and the findings here for whoever
/// prefers the terminal.
fn next(scan: &Scan, options: &Options) -> String {
    let mut out = String::new();
    if scan.findings.is_empty() {
        return out;
    }
    let arrow = paint("→", accent());
    let terminal = !options.ci && matches!(options.view, View::Summary | View::Overview);
    let mut hints = Vec::new();
    if let Some(report) = &options.report {
        let _ = writeln!(
            out,
            "\n{} {}",
            paint(" Report  ", accent()),
            paint(report, bold())
        );
        // Terminals may open a `file://` link in an editor, not a browser.
        if report.starts_with("file://") && !options.opened && !options.ci {
            hints.push(("shorwatch open", "open it in your browser"));
        }
    } else if terminal {
        hints.push(("--html shorwatch.html", "a report to browse"));
    }
    if terminal {
        hints.push(("--details", "every finding, here"));
    }
    if !hints.is_empty() {
        out.push('\n');
    }
    for (command, what) in hints {
        let _ = writeln!(out, " {arrow} {}  {what}", paint(command, bold()));
    }
    out
}

/// Why the scan exits with code 1, for the end of a CI log, with the link
/// to the HTML report when the summary above did not show it.
pub fn verdict(failing: usize, report: Option<&str>) -> String {
    let mut out = format!(
        "\n {} {} {}\n",
        paint("✖", rgb_red()),
        paint(
            format!(
                "{} {} the scan (exit code 1)",
                plural(failing, "finding"),
                if failing == 1 { "fails" } else { "fail" }
            ),
            bold()
        ),
        paint("· see --fail-on, --fail-severity", dim())
    );
    if let Some(report) = report {
        let _ = writeln!(out, "   {} {}", paint("Report", accent()), report);
    }
    out
}

fn summary(scan: &Scan) -> String {
    let summary = scan.summary();
    let label = paint(" Summary ", accent());
    let mut out = String::new();
    if summary.findings == 0 {
        let _ = writeln!(
            out,
            "\n{label} no quantum-vulnerable cryptography found in {}",
            plural(summary.files_scanned, "file")
        );
        return out;
    }
    let indent = " ".repeat(" Summary ".len());
    let _ = writeln!(
        out,
        "\n{label} {} in {} {} ({} scanned)",
        paint(plural(summary.findings, "finding"), bold()),
        summary.files_with_findings,
        if summary.files_with_findings == 1 {
            "file"
        } else {
            "files"
        },
        summary.files_scanned,
    );
    let severities: Vec<_> = summary
        .severities()
        .map(|(severity, n)| format!("{n} {}", severity_label(severity)))
        .collect();
    let _ = writeln!(out, "{indent} {}", paint(severities.join(" · "), bold()));
    let _ = writeln!(
        out,
        "{indent} {} vulnerable · {} in transition · {} auto-fixable",
        summary.vulnerable, summary.in_transition, summary.fixable
    );
    if summary.in_tests > 0 {
        let _ = writeln!(
            out,
            "{indent} {} in production code · {} in test code",
            summary.findings - summary.in_tests,
            summary.in_tests
        );
    }
    if scan.projects.len() > 1 {
        let with_findings: BTreeSet<_> = scan
            .findings
            .iter()
            .filter_map(|f| scan.project_of(&f.path))
            .collect();
        let projects = format!(
            "{} of {} projects with findings",
            with_findings.len(),
            scan.projects.len()
        );
        let _ = writeln!(out, "{indent} {}", paint(projects, dim()));
    }
    out
}

fn plural(n: usize, word: &str) -> String {
    if n == 1 {
        format!("{n} {word}")
    } else {
        format!("{n} {word}s")
    }
}
