//! When a scan fails: `--fail-on`, `--fail-severity` and `--fail-usage`.

use std::process::ExitCode;

use shorwatch_core::{Severity, Status, Usage};
use shorwatch_report::Scan;

use crate::args::{FailOn, Gate};

/// The findings that fail the scan.
pub fn failing(scan: &Scan, gate: &Gate) -> usize {
    let threshold = Severity::from(gate.fail_severity);
    scan.findings
        .iter()
        .filter(|f| f.severity >= threshold)
        .filter(|f| match gate.fail_on {
            FailOn::Vulnerable => f.status == Status::Vulnerable,
            FailOn::Any => true,
            FailOn::Never => false,
        })
        .filter(|f| match (f.usage, gate.fail_usage.is_empty()) {
            // No `--fail-usage`, or a finding with no usage (symmetric).
            (_, true) | (None, _) => true,
            (Some(usage), false) => gate.fail_usage.iter().any(|&u| Usage::from(u) == usage),
        })
        .count()
}

pub fn exit_code(failing: usize) -> ExitCode {
    if failing == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
