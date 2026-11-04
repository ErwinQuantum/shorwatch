//! Loading the rule set (built-in plus `--rules` directories) and the
//! `shorwatch rules` listing.

use std::fmt::Write as _;

use anyhow::{Context, Result};
use shorwatch_core::{Category, LibraryCatalog, Rule, RuleSet, Severity};

use crate::args::RuleSource;

pub fn load(source: &RuleSource) -> Result<RuleSet> {
    let mut rules = shorwatch_rules::builtin_rules().context("loading built-in rules")?;
    for dir in &source.dirs {
        let extra = shorwatch_rules::load_dir(dir)
            .with_context(|| format!("loading rules from `{}`", dir.display()))?;
        rules.extend(extra);
    }
    RuleSet::compile(rules).context("validating rules")
}

/// The known cryptographic libraries (built-in plus the `libraries/` of
/// `--rules` directories), for the dependency inventory.
pub fn libraries(source: &RuleSource) -> Result<LibraryCatalog> {
    let mut specs =
        shorwatch_rules::builtin_library_specs().context("loading built-in libraries")?;
    for dir in &source.dirs {
        let extra = shorwatch_rules::load_dir_libraries(dir)
            .with_context(|| format!("loading libraries from `{}`", dir.display()))?;
        specs.extend(extra);
    }
    LibraryCatalog::compile(specs).context("validating libraries")
}

/// A plain table of the rules, sorted by id.
pub fn listing(rules: &RuleSet) -> String {
    let mut rules: Vec<&Rule> = rules.rules().collect();
    rules.sort_by(|a, b| a.id.cmp(&b.id));
    let width = rules.iter().map(|r| r.id.len()).max().unwrap_or(0);
    let mut out = String::new();
    for rule in &rules {
        let category = match rule.category {
            Category::Shor => "shor",
            Category::Grover => "grover",
        };
        let severity = match rule.severity {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        };
        let fix = if rule.fix.is_some() { "fix" } else { "" };
        let _ = writeln!(
            out,
            "{:<width$}  {category:<6}  {severity:<8}  {:<3}  {}",
            rule.id, fix, rule.algorithm
        );
    }
    let _ = writeln!(out, "\n{} rules", rules.len());
    out
}
