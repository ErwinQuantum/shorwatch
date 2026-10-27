//! A Markdown summary for CI job summaries (`$GITHUB_STEP_SUMMARY`) and
//! pull-request comments.

use shorwatch_core::{CodeRole, Finding};
use std::fmt::Write as _;

use crate::Scan;
use crate::summary::{severity_label, status_label};

pub fn render(scan: &Scan) -> String {
    let summary = scan.summary();
    let mut out = String::new();
    if summary.findings == 0 {
        let _ = writeln!(
            out,
            "## 🛡️ Shorwatch: no {}quantum-vulnerable cryptography found\n\n{} files scanned.{}",
            if summary.in_baseline > 0 { "new " } else { "" },
            summary.files_scanned,
            suppressed_note(&summary)
        );
        return out;
    }

    let _ = writeln!(
        out,
        "## 🛡️ Shorwatch: {} quantum-vulnerable finding{}\n",
        summary.findings,
        if summary.findings == 1 { "" } else { "s" }
    );
    let _ = writeln!(out, "| | Count |\n|---|---:|");
    let _ = writeln!(out, "| Vulnerable | {} |", summary.vulnerable);
    let _ = writeln!(
        out,
        "| In transition (hybrid) | {} |",
        summary.in_transition
    );
    let _ = writeln!(out, "| Auto-fixable | {} |", summary.fixable);
    if summary.in_tests > 0 {
        let _ = writeln!(out, "| In test code | {} |", summary.in_tests);
    }
    for (severity, n) in summary.severities() {
        let _ = writeln!(out, "| Severity {} | {n} |", severity_label(severity));
    }
    if summary.ignored_in_code > 0 {
        let _ = writeln!(out, "| Ignored in the code | {} |", summary.ignored_in_code);
    }
    if summary.in_baseline > 0 {
        let _ = writeln!(out, "| Known (baseline) | {} |", summary.in_baseline);
    }
    let _ = writeln!(
        out,
        "| Files with findings / scanned | {} / {} |\n",
        summary.files_with_findings, summary.files_scanned
    );

    let _ = writeln!(
        out,
        "### Findings\n\n| Severity | Algorithm | Location | Status | Rule |\n|---|---|---|---|---|"
    );
    for f in &scan.findings {
        let _ = writeln!(
            out,
            "| {} | {} | {}{} | {} | `{}` |",
            severity_label(f.severity),
            cell(&f.algorithm),
            location(scan, f),
            match (&f.detail, f.flow.first()) {
                (Some(detail), _) => format!(" ({})", cell(detail)),
                (None, Some(origin)) => match &origin.path {
                    Some(path) => format!(
                        " (value from `{}:{}`)",
                        cell(path),
                        origin.location.start.line
                    ),
                    None => format!(" (value from line {})", origin.location.start.line),
                },
                (None, None) => String::new(),
            },
            match f.role {
                CodeRole::Production => status_label(f.status).to_owned(),
                CodeRole::Test => format!("{} (test code)", status_label(f.status)),
            },
            f.rule_id,
        );
    }
    out
}

/// Findings left out, said where a clean result is announced.
fn suppressed_note(summary: &crate::Summary) -> String {
    let mut parts = Vec::new();
    if summary.ignored_in_code > 0 {
        parts.push(format!("{} ignored in the code", summary.ignored_in_code));
    }
    if summary.in_baseline > 0 {
        parts.push(format!("{} known from the baseline", summary.in_baseline));
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!(" Not counted: {}.", parts.join(", "))
    }
}

/// `path:line`, linked to the lines on the repository host when known.
fn location(scan: &Scan, f: &Finding) -> String {
    let text = format!("`{}:{}`", cell(&f.path), f.location.start.line);
    let url = scan
        .links
        .web
        .as_ref()
        .and_then(|web| web.file(&f.path, f.location.start.line, f.location.end.line));
    match url {
        Some(url) => format!("[{text}]({url})"),
        None => text,
    }
}

/// Escapes characters that would break a table cell.
fn cell(text: &str) -> String {
    text.replace('|', "\\|").replace('\n', " ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::scan;

    #[test]
    fn markdown_report() {
        insta::assert_snapshot!(render(&scan()));
    }

    #[test]
    fn locations_link_to_the_repository_host() {
        let mut scan = scan();
        scan.links.web = Some(crate::WebLinks {
            host: "GitHub".into(),
            file: "https://github.com/acme/auth/blob/abc/{path}#L{line}-L{end}".into(),
            editor: None,
        });
        let report = render(&scan);
        assert!(
            report.contains(
                "[`src/main/java/com/acme/auth/AuthConfig.java:5`](https://github.com/acme/auth/blob/abc/src/main/java/com/acme/auth/AuthConfig.java#L5-L5)"
            ),
            "{report}"
        );
    }

    #[test]
    fn clean_scan_says_so() {
        let clean = Scan {
            files_scanned: 3,
            ..Default::default()
        };
        assert!(render(&clean).contains("no quantum-vulnerable cryptography found"));
    }
}
