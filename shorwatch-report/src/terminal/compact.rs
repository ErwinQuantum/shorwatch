//! One line per finding, grouped by file (`--compact`).

use std::fmt::Write as _;

use super::style::{accent, bold, dim, paint, severity_badge, status};
use crate::Scan;

const EXCERPT_WIDTH: usize = 56;

pub(super) fn render(scan: &Scan) -> String {
    let mut out = String::new();
    let mut current: Option<&str> = None;
    for finding in &scan.findings {
        if current != Some(finding.path.as_str()) {
            if current.is_some() {
                out.push('\n');
            }
            let _ = writeln!(out, "{}", paint(&finding.path, bold()));
            current = Some(&finding.path);
        }
        let start = finding.location.start;
        let excerpt = scan
            .line(&finding.path, start.line)
            .map(|l| excerpt(l.trim()))
            .unwrap_or_default();
        let _ = writeln!(
            out,
            "  {} {} {:<16} {}  {}",
            paint(format!("{:>5}:{:<3}", start.line, start.column), accent()),
            severity_badge(finding.severity, "CRITICAL".len()),
            finding.algorithm,
            status(finding.status, "in transition".len()),
            paint(excerpt, dim()),
        );
    }
    out
}

fn excerpt(line: &str) -> String {
    if line.chars().count() <= EXCERPT_WIDTH {
        return line.to_owned();
    }
    let cut: String = line.chars().take(EXCERPT_WIDTH - 1).collect();
    format!("{cut}…")
}
