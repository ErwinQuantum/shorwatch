//! A self-contained HTML report: one file with its styles, script and data,
//! that opens offline (CI artifacts, e-mail) and loads nothing from the
//! network. The page renders the scan client-side from embedded JSON: a
//! summary, charts, filters, and every finding with its code, explanation
//! and data-flow path.
//!
//! All source text reaches the page as data and is inserted with
//! `textContent`, never as markup.

use serde::Serialize;
use shorwatch_core::Finding;

use crate::{Scan, Summary};

const TEMPLATE: &str = include_str!("report.html");
const STYLE: &str = include_str!("report.css");
const SCRIPT: &str = include_str!("report.js");

/// Source lines shown around a finding.
const CONTEXT_LINES: u32 = 2;

pub fn render(scan: &Scan) -> String {
    let payload = Payload {
        tool_version: &scan.tool_version,
        summary: scan.summary(),
        findings: scan.findings.iter().map(|f| entry(scan, f)).collect(),
    };
    let data = serde_json::to_string(&payload).expect("a scan always serializes");
    TEMPLATE
        .replace("/*{{STYLE}}*/", STYLE)
        .replace("/*{{SCRIPT}}*/", SCRIPT)
        .replace("{{VERSION}}", &scan.tool_version)
        .replace("{{DATA}}", &script_safe(&data))
}

/// JSON inside `<script>`: no `<` may start a closing tag or a comment.
fn script_safe(json: &str) -> String {
    json.replace('<', &format!("{}u003c", '\\'))
}

fn entry<'a>(scan: &'a Scan, finding: &'a Finding) -> Entry<'a> {
    let start = finding.location.start.line;
    let end = finding.location.end.line.max(start);
    let first = start.saturating_sub(CONTEXT_LINES).max(1);
    let lines: Vec<&str> = (first..=end + CONTEXT_LINES)
        .map_while(|line| scan.line(&finding.path, line))
        .collect();
    Entry {
        finding,
        snippet: Snippet {
            first_line: first,
            lines,
        },
        flow_lines: finding
            .flow
            .iter()
            .map(|step| {
                let path = step.path.as_deref().unwrap_or(&finding.path);
                scan.line(path, step.location.start.line)
            })
            .collect(),
    }
}

#[derive(Serialize)]
struct Payload<'a> {
    tool_version: &'a str,
    summary: Summary,
    findings: Vec<Entry<'a>>,
}

#[derive(Serialize)]
struct Entry<'a> {
    #[serde(flatten)]
    finding: &'a Finding,
    snippet: Snippet<'a>,
    /// The source line of each data-flow step, when known.
    flow_lines: Vec<Option<&'a str>>,
}

#[derive(Serialize)]
struct Snippet<'a> {
    first_line: u32,
    lines: Vec<&'a str>,
}

#[cfg(test)]
mod tests;
