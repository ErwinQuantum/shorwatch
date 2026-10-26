//! One finding, rustc-style: header, clickable `path:line:col`, the source
//! line with the match underlined, then context and migration advice.

use std::fmt::Write as _;

use shorwatch_core::{CodeRole, Finding};

use super::style::{accent, bold, dim, paint, severity_badge, status};
use super::wrap::wrap;
use crate::Scan;

const TAB_WIDTH: usize = 4;
const TEXT_WIDTH: usize = 88;

pub(super) fn render(scan: &Scan, finding: &Finding) -> String {
    let start = finding.location.start;
    let gutter = start.line.to_string().len().max(2);
    let pad = " ".repeat(gutter);
    let bar = paint("│", accent());
    let eq = paint("=", accent());
    let mut out = String::new();

    // Writing to a String cannot fail.
    let _ = writeln!(
        out,
        "{} {} {} {} {} {}{}",
        severity_badge(finding.severity, 0),
        paint(&finding.algorithm, bold()),
        paint("·", dim()),
        paint(&finding.rule_id, dim()),
        paint("·", dim()),
        status(finding.status, 0),
        if finding.role == CodeRole::Test {
            format!(" {} {}", paint("·", dim()), paint("test code", dim()))
        } else {
            String::new()
        },
    );
    let _ = writeln!(
        out,
        "{pad}{} {}:{}:{}",
        paint("──▶", accent()),
        finding.path,
        start.line,
        start.column
    );

    if let Some(line) = scan.line(&finding.path, start.line) {
        let (shown, underline) = underline(line, finding);
        let _ = writeln!(out, "{pad} {bar}");
        let _ = writeln!(
            out,
            "{} {bar} {shown}",
            paint(format!("{:>gutter$}", start.line), accent())
        );
        let _ = writeln!(out, "{pad} {bar} {}", paint(underline, accent()));
    }
    let _ = writeln!(out, "{pad} {bar} {}", paint(&finding.title, bold()));

    if let Some(evidence) = &finding.hybrid_evidence {
        let _ = writeln!(
            out,
            "{pad} {eq} in transition: post-quantum code at line {} ({})",
            evidence.location.start.line, evidence.text
        );
    }
    if let Some(fix) = &finding.fix {
        let _ = writeln!(
            out,
            "{pad} {eq} fix: {} → `{}` at {}:{}",
            fix.description, fix.replacement, fix.location.start.line, fix.location.start.column
        );
    }
    let help_indent = format!("{pad}   {}", " ".repeat("help: ".len()));
    let help = wrap(
        &finding.suggestion,
        TEXT_WIDTH - help_indent.len(),
        &help_indent,
    );
    let _ = writeln!(
        out,
        "{pad} {eq} {}{}",
        paint("help: ", bold()),
        help.trim_start()
    );
    if let Some(reference) = finding.references.first() {
        let _ = writeln!(out, "{pad} {eq} ref: {}", paint(&reference.url, dim()));
    }
    out
}

/// The source line as displayed (tabs expanded, trailing space trimmed) and
/// the `^^^` marker under the matched span.
fn underline(line: &str, finding: &Finding) -> (String, String) {
    let display = |text: &str| -> String {
        text.chars()
            .flat_map(|c| {
                let n = if c == '\t' { TAB_WIDTH } else { 1 };
                std::iter::repeat_n(if c == '\t' { ' ' } else { c }, n)
            })
            .collect()
    };
    let start = finding.location.start;
    let end = finding.location.end;
    let chars: Vec<char> = line.chars().collect();
    let from = (start.column as usize).saturating_sub(1).min(chars.len());
    let to = if end.line == start.line {
        (end.column as usize)
            .saturating_sub(1)
            .clamp(from, chars.len())
    } else {
        chars.len()
    };
    let before: String = chars[..from].iter().collect();
    let span: String = chars[from..to].iter().collect();
    let offset = display(&before).chars().count();
    let width = display(&span).trim_end().chars().count().max(1);
    (
        display(line).trim_end().to_owned(),
        format!("{}{}", " ".repeat(offset), "^".repeat(width)),
    )
}
