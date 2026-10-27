//! When a scan fails: `--fail-on` and `--fail-severity`.

use std::process::ExitCode;

use shorwatch_core::{Severity, Status};
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
        .count()
}

pub fn exit_code(failing: usize) -> ExitCode {
    if failing == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
