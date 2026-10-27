//! `shorwatch:ignore` comments: on the finding's line, or alone on the line
//! above it.
//!
//! ```text
//! KeyPairGenerator.getInstance("RSA"); // shorwatch:ignore jvm.jca.rsa -- partner API, until Q3
//! # shorwatch:ignore rsa -- legacy clients
//! jwt.algorithm: RS256
//! ```
//!
//! Rules are named by id or by profile (`rsa` covers every `*.rsa` rule);
//! none means every rule on that line. What follows `--` is the reason,
//! carried into the reports.

use shorwatch_core::Finding;
use shorwatch_report::Suppression;

const MARKER: &str = "shorwatch:ignore";

pub fn suppression(
    finding: &Finding,
    line: Option<&str>,
    above: Option<&str>,
) -> Option<Suppression> {
    let directive = line
        .and_then(directive)
        .or_else(|| above.filter(|l| is_comment(l)).and_then(directive))?;
    directive
        .covers(&finding.rule_id)
        .then_some(Suppression::InSource {
            justification: directive.reason,
        })
}

struct Directive {
    rules: Vec<String>,
    reason: Option<String>,
}

impl Directive {
    fn covers(&self, rule_id: &str) -> bool {
        self.rules.is_empty()
            || self.rules.iter().any(|rule| {
                rule == rule_id
                    || rule_id
                        .strip_suffix(rule.as_str())
                        .is_some_and(|rest| rest.ends_with('.'))
            })
    }
}

fn directive(line: &str) -> Option<Directive> {
    let start = line.find(MARKER)? + MARKER.len();
    let rest = &line[start..];
    // `shorwatch:ignored` or `shorwatch:ignore-me` is not the marker.
    if rest.starts_with(|c: char| !c.is_whitespace()) {
        return None;
    }
    let rest = rest
        .trim()
        .trim_end_matches("*/")
        .trim_end_matches("-->")
        .trim();
    let (rules, reason) = match rest.split_once("--") {
        Some((rules, reason)) => (rules, Some(reason.trim())),
        None => (rest, None),
    };
    Some(Directive {
        rules: rules
            .split([',', ' '])
            .filter(|rule| !rule.is_empty())
            .map(str::to_owned)
            .collect(),
        reason: reason.filter(|r| !r.is_empty()).map(str::to_owned),
    })
}

/// A line that is only a comment (Java, Kotlin, YAML, properties, XML).
fn is_comment(line: &str) -> bool {
    let line = line.trim_start();
    ["//", "/*", "*", "#", "!", "<!--"]
        .iter()
        .any(|start| line.starts_with(start))
}
