//! Snapshot tests for the built-in rules against real Java sources.
//!
//! Each rule has a folder under `tests/fixtures/<language>/<rule>/`; every
//! file there is lowered, analyzed with all built-in rules, and its findings
//! snapshotted in a compact, reviewable form.

use std::fs;
use std::path::Path;

use serde::Serialize;
use shorwatch_core::{Finding, Status, analyze};
use shorwatch_langs::{Frontend, JavaFrontend};

#[derive(Serialize)]
struct Compact {
    rule: String,
    at: String,
    status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    hybrid_evidence: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fix: Option<String>,
}

impl From<Finding> for Compact {
    fn from(f: Finding) -> Self {
        Self {
            rule: f.rule_id,
            at: format!("{}:{}", f.location.start.line, f.location.start.column),
            status: f.status,
            hybrid_evidence: f
                .hybrid_evidence
                .map(|e| format!("{} @ {}", e.text, e.location.start.line)),
            fix: f
                .fix
                .map(|fix| format!("{} @ {}", fix.replacement, fix.location.start.line)),
        }
    }
}

fn findings(fixture: &str) -> Vec<Compact> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(fixture);
    let source = fs::read_to_string(&path).unwrap();
    let unit = JavaFrontend.lower(fixture, &source).unwrap();
    let rules = shorwatch_rules::builtin().unwrap();
    analyze(&unit, &rules)
        .into_iter()
        .map(Compact::from)
        .collect()
}

#[test]
fn rsa_vulnerable() {
    insta::assert_yaml_snapshot!(findings("java/rsa/Vulnerable.java"));
}

#[test]
fn rsa_hybrid() {
    insta::assert_yaml_snapshot!(findings("java/rsa/Hybrid.java"));
}

#[test]
fn rsa_clean() {
    assert!(findings("java/rsa/Clean.java").is_empty());
}
