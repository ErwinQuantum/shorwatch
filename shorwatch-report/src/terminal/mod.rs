//! The human-readable terminal report.
//!
//! [`render`] produces the findings (an overview, every finding in detail,
//! or one line each) and a summary;
//! [`banner`] is printed separately by the CLI, only on interactive terminals.

mod banner;
mod compact;
mod detailed;
mod overview;
mod style;
#[cfg(test)]
mod tests;
mod wrap;

use std::fmt::Write as _;

pub use banner::banner;
use style::{accent, bold, dim, paint};

use crate::Scan;
use crate::summary::severity_label;

#[derive(Debug, Clone, Copy, Default)]
pub struct Options {
    pub view: View,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum View {
    /// Files with findings, the most urgent ones explained, the summary.
    #[default]
    Overview,
    /// Every finding, explained.
    Details,
    /// One line per finding.
    Compact,
}

pub fn render(scan: &Scan, options: Options) -> String {
    let mut out = String::new();
    match options.view {
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
    if options.view == View::Overview {
        out.push_str(&overview::hints(scan));
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
    let severities: Vec<_> = summary
        .severities()
        .map(|(severity, n)| format!("{n} {}", severity_label(severity)))
        .collect();
    let _ = writeln!(out, "{indent} {}", paint(severities.join(" · "), dim()));
    out
}

fn plural(n: usize, word: &str) -> String {
    if n == 1 {
        format!("{n} {word}")
    } else {
        format!("{n} {word}s")
    }
}
