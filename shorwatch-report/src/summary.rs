//! Counts shared by every report format.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use shorwatch_core::inventory::Support;
use shorwatch_core::{CodeRole, Severity, Status};

use crate::{LanguageFiles, Scan, Suppression};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Summary {
    pub files_scanned: usize,
    /// The scanned files by language.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub languages: Vec<LanguageFiles>,
    /// Source files skipped for want of a frontend.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub unanalyzed: Vec<LanguageFiles>,
    /// Files with at least one finding.
    pub files_with_findings: usize,
    pub findings: usize,
    pub vulnerable: usize,
    pub in_transition: usize,
    /// Findings that come with a mechanical fix.
    pub fixable: usize,
    /// Findings in test code (the rest are in production code).
    pub in_tests: usize,
    /// Most severe first.
    pub by_severity: BTreeMap<Severity, usize>,
    /// Findings a `shorwatch:ignore` comment leaves out.
    pub ignored_in_code: usize,
    /// Findings already in the baseline, left out.
    pub in_baseline: usize,
    /// Cryptographic libraries the build files declare (see
    /// [`Scan::dependencies`]).
    #[serde(skip_serializing_if = "is_zero")]
    pub libraries: usize,
    /// Of those, the ones whose declared version predates the library's
    /// post-quantum algorithms.
    #[serde(skip_serializing_if = "is_zero")]
    pub libraries_too_old: usize,
}

/// `120 Java · 40 Kotlin`.
pub fn language_counts(languages: &[LanguageFiles]) -> String {
    languages
        .iter()
        .map(|l| format!("{} {}", l.files, l.language))
        .collect::<Vec<_>>()
        .join(" · ")
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

impl Summary {
    pub fn of(scan: &Scan) -> Self {
        let findings = &scan.findings;
        let count = |status| findings.iter().filter(|f| f.status == status).count();
        let mut by_severity = BTreeMap::new();
        for finding in findings {
            *by_severity.entry(finding.severity).or_default() += 1;
        }
        Self {
            files_scanned: scan.files_scanned,
            languages: scan.languages.clone(),
            unanalyzed: scan.unanalyzed.clone(),
            files_with_findings: findings
                .iter()
                .map(|f| f.path.as_str())
                .collect::<BTreeSet<_>>()
                .len(),
            findings: findings.len(),
            vulnerable: count(Status::Vulnerable),
            in_transition: count(Status::InTransition),
            fixable: findings.iter().filter(|f| f.fix.is_some()).count(),
            in_tests: findings.iter().filter(|f| f.role == CodeRole::Test).count(),
            by_severity,
            ignored_in_code: scan
                .suppressed
                .iter()
                .filter(|s| matches!(s.suppression, Suppression::InSource { .. }))
                .count(),
            in_baseline: scan
                .suppressed
                .iter()
                .filter(|s| s.suppression == Suppression::Baseline)
                .count(),
            libraries: scan.dependencies.len(),
            libraries_too_old: scan
                .dependencies
                .iter()
                .filter(|d| {
                    d.post_quantum
                        .as_ref()
                        .is_some_and(|pq| pq.support == Support::TooOld)
                })
                .count(),
        }
    }

    /// Severities with findings, most severe first.
    pub fn severities(&self) -> impl Iterator<Item = (Severity, usize)> + '_ {
        self.by_severity.iter().rev().map(|(s, n)| (*s, *n))
    }
}

pub(crate) fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

pub(crate) fn status_label(status: Status) -> &'static str {
    match status {
        Status::Vulnerable => "vulnerable",
        Status::InTransition => "in transition",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::scan;

    #[test]
    fn counts_the_libraries_and_the_ones_before_post_quantum_support() {
        let mut scan = scan();
        assert_eq!(scan.summary().libraries, 0);
        scan.dependencies = crate::fixtures::dependencies();
        let summary = scan.summary();
        assert_eq!(summary.libraries, 4);
        assert_eq!(summary.libraries_too_old, 2);
    }

    #[test]
    fn counts_findings_by_status_severity_and_file() {
        let summary = scan().summary();
        assert_eq!(summary.findings, 5);
        assert_eq!(summary.files_with_findings, 4);
        assert_eq!(summary.vulnerable, 4);
        assert_eq!(summary.in_transition, 1);
        assert_eq!(summary.fixable, 1);
        assert_eq!(summary.in_tests, 1);
        assert_eq!(
            summary.severities().collect::<Vec<_>>(),
            [(Severity::High, 4), (Severity::Low, 1)]
        );
    }
}
