//! Snapshot tests for the built-in rules against real sources.
//!
//! Every folder under `tests/fixtures/` is a small project: all its files
//! (Java, Kotlin, YAML, `.properties`) are lowered and [`link`]ed together, so values
//! injected with `@Value` resolve against the folder's config files. Each file
//! is then analyzed with *all* built-in rules (so overlaps between rules show
//! up) and its findings snapshotted in a compact, reviewable form. Files named
//! `Clean.*` must produce no findings at all.
//!
//! A Kotlin file next to a Java file of the same name is its twin: JVM rules
//! describe library APIs, so both must yield the same findings.
//!
//! Adding a fixture needs no code here: run `cargo insta test` and review.

use std::fs;
use std::path::Path;
use std::sync::OnceLock;

use serde::Serialize;
use shorwatch_core::{Finding, RuleSet, SourceUnit, Status, analyze, link};

#[derive(Serialize)]
struct Compact {
    rule: String,
    at: String,
    status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    hybrid_evidence: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fix: Option<String>,
    /// The data-flow path, one `[file:]line: note` per step.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    flow: Vec<String>,
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
            flow: f
                .flow
                .iter()
                .map(|s| match &s.path {
                    Some(path) => format!("{path}:{}: {}", s.location.start.line, s.note),
                    None => format!("{}: {}", s.location.start.line, s.note),
                })
                .collect(),
        }
    }
}

fn lower(path: &Path) -> Option<SourceUnit> {
    let extension = path.extension()?.to_str()?;
    let frontend = shorwatch_langs::for_extension(extension)?;
    let source = fs::read_to_string(path).unwrap();
    let name = path.file_name().unwrap().to_string_lossy();
    Some(frontend.lower(&name, &source).unwrap())
}

/// Compiled once: every fixture is analyzed with all built-in rules.
fn rules() -> &'static RuleSet {
    static RULES: OnceLock<RuleSet> = OnceLock::new();
    RULES.get_or_init(|| shorwatch_rules::builtin().unwrap())
}

/// Lowers and links every file next to `path`, then analyzes `path` alone.
fn findings(path: &Path) -> Vec<Compact> {
    let mut siblings: Vec<_> = fs::read_dir(path.parent().unwrap())
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    siblings.sort();
    let mut units: Vec<_> = siblings.iter().filter_map(|p| lower(p)).collect();
    link(&mut units);

    let name = path.file_name().unwrap().to_string_lossy();
    let unit = units.iter().find(|u| u.path() == name).unwrap();
    analyze(unit, rules())
        .into_iter()
        .map(Compact::from)
        .collect()
}

#[test]
fn fixtures() {
    insta::glob!("fixtures/**/*.{java,kt,yml,yaml,properties}", |path| {
        let findings = findings(path);
        if path.file_stem().is_some_and(|s| s == "Clean") {
            assert!(
                findings.is_empty(),
                "{} should be clean, got {} finding(s)",
                path.display(),
                findings.len()
            );
        }
        insta::assert_yaml_snapshot!(findings);
    });
}

/// What a finding means, without where it is: twins differ in layout.
fn meaning(findings: Vec<Compact>) -> Vec<(String, Status, bool, bool)> {
    let mut meaning: Vec<_> = findings
        .into_iter()
        .map(|f| {
            (
                f.rule,
                f.status,
                f.hybrid_evidence.is_some(),
                f.fix.is_some(),
            )
        })
        .collect();
    meaning.sort_by(|a, b| format!("{a:?}").cmp(&format!("{b:?}")));
    meaning
}

#[test]
fn kotlin_twins_find_what_java_finds() {
    let mut twins = 0;
    insta::glob!("fixtures/**/*.kt", |kotlin| {
        let java = kotlin.with_extension("java");
        if !java.exists() {
            return;
        }
        twins += 1;
        assert_eq!(
            meaning(findings(kotlin)),
            meaning(findings(&java)),
            "{} and its Java twin disagree",
            kotlin.display()
        );
    });
    assert!(twins > 0, "no Kotlin twins found");
}
