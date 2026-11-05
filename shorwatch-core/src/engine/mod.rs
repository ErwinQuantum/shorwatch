//! The evaluation engine: runs compiled rules over a unit's facts.
//!
//! [`matching`] decides whether a pattern matches a fact, [`hybrid`] looks for
//! post-quantum code nearby, [`fix`] derives safe mechanical edits; this module
//! ties them into [`Finding`]s.

use std::collections::HashSet;

use crate::finding::{Finding, Status};
use crate::ir::{Fact, FactKind, SourceUnit};
use crate::rule::{CompiledRule, RuleSet};

mod fix;
mod hybrid;
mod matching;
#[cfg(test)]
mod tests;

use fix::suggested_fix;
use hybrid::hybrid_evidence;
use matching::{Match, match_pattern};

/// Evaluates every rule for the unit's platform against the unit.
///
/// Pure and deterministic: findings are ordered by position, then rule id.
/// A rule reports a line once, however many matching values it holds
/// (`Family.EC.contains(a)` next to `new ECDSAVerifier(k)`, a cipher suite
/// written under its IANA and OpenSSL names): it is one place to fix, and the
/// baseline already treats it as one (see `report::fingerprint`). Findings
/// with a fix, or about a key (their line is not where the key is), stay.
pub fn analyze(unit: &SourceUnit, rules: &RuleSet) -> Vec<Finding> {
    let platform = unit.language().platform();
    let mut findings = Vec::new();
    for rule in rules.rules.iter().filter(|r| r.rule.platform == platform) {
        for fact in unit.facts() {
            if let Some(matched) = rule
                .patterns
                .iter()
                .find_map(|p| match_pattern(p, fact, unit))
            {
                findings.push(build_finding(unit, rule, fact, matched));
            }
        }
    }
    findings.sort_by(|a, b| (a.location.start, &a.rule_id).cmp(&(b.location.start, &b.rule_id)));
    let mut reported = HashSet::new();
    findings.retain(|f| {
        f.fix.is_some()
            || f.detail.is_some()
            || reported.insert((f.rule_id.clone(), f.location.start.line))
    });
    findings
}

fn build_finding(unit: &SourceUnit, rule: &CompiledRule, fact: &Fact, matched: Match) -> Finding {
    let hybrid_evidence = hybrid_evidence(unit, rule, fact);
    let spec = &rule.rule;
    Finding {
        rule_id: spec.id.clone(),
        algorithm: spec.algorithm.clone(),
        category: spec.category,
        severity: spec.severity,
        status: if hybrid_evidence.is_some() {
            Status::InTransition
        } else {
            Status::Vulnerable
        },
        title: spec.title.clone(),
        message: spec.message.clone(),
        suggestion: spec.suggestion.clone(),
        references: spec.references.clone(),
        path: unit.path().to_owned(),
        role: unit.role(),
        location: fact.location,
        detail: match &fact.kind {
            FactKind::Key { label, .. } => Some(label.clone()),
            _ => None,
        },
        flow: matched.flow.clone(),
        hybrid_evidence,
        fix: suggested_fix(rule, &matched),
        crypto: spec.crypto.clone(),
    }
}
