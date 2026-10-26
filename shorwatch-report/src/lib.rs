//! # shorwatch-report
//!
//! Output adapters for [`Finding`]s. Every renderer is pure: it takes a
//! [`Scan`] and returns the report as a `String`, and the caller decides where
//! it goes (a terminal, a file, a CI job summary). That keeps each format
//! testable with snapshots and free of I/O.
//!
//! - [`terminal`]: colored, human-readable report and the banner.
//! - [`sarif`]: SARIF 2.1.0 for GitHub code scanning, GitLab and IDEs.
//! - [`json`]: the findings as JSON, for scripts and other tools.
//! - [`markdown`]: a summary for CI job summaries and pull-request comments.

use std::collections::BTreeMap;

use shorwatch_core::Finding;

pub mod json;
pub mod markdown;
pub mod sarif;
pub mod summary;
pub mod terminal;

pub use summary::Summary;

/// Everything a report needs about one scan.
#[derive(Debug, Clone, Default)]
pub struct Scan {
    /// Version of the tool that produced the findings.
    pub tool_version: String,
    /// Findings, in the order they should be reported.
    pub findings: Vec<Finding>,
    /// Contents of the files that have findings, keyed by finding path, so
    /// reports can show the offending line.
    pub sources: BTreeMap<String, String>,
    /// How many files were analyzed, findings or not.
    pub files_scanned: usize,
}

impl Scan {
    pub fn summary(&self) -> Summary {
        Summary::of(self)
    }

    /// The source line `line` (1-based) of `path`, if known.
    pub(crate) fn line(&self, path: &str, line: u32) -> Option<&str> {
        let index = usize::try_from(line).ok()?.checked_sub(1)?;
        self.sources.get(path)?.lines().nth(index)
    }
}

#[cfg(test)]
pub(crate) mod fixtures;
