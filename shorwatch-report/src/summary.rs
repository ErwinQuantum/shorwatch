//! Counts shared by every report format.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use shorwatch_core::{CodeRole, Severity, Status};

use crate::Scan;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Summary {
    pub files_scanned: usize,
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
