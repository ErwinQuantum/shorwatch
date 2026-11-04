//! # shorwatch-report
//!
//! Output adapters for [`Finding`]s. Every renderer is pure: it takes a
//! [`Scan`] and returns the report as a `String`, and the caller decides where
//! it goes (a terminal, a file, a CI job summary). That keeps each format
//! testable with snapshots and free of I/O.
//!
//! - [`terminal`]: colored, human-readable report and the banner.
//! - [`sarif`]: SARIF 2.1.0 for GitHub code scanning, GitLab and IDEs.
//! - [`cbom`]: a CycloneDX 1.6 Cryptography Bill of Materials (inventory).
//! - [`json`]: the findings as JSON, for scripts and other tools.
//! - [`markdown`]: a summary for CI job summaries and pull-request comments.
//! - [`html`]: a self-contained page with charts, filters, code and data-flow
//!   paths, to read or share.

use std::collections::BTreeMap;

use shorwatch_core::{Dependency, Finding};

pub mod cbom;
pub mod html;
pub mod json;
pub mod links;
pub mod markdown;
pub mod sarif;
pub mod summary;
pub mod suppression;
pub mod terminal;

pub use links::{SourceLinks, WebLinks};
pub use summary::Summary;
pub use suppression::{Suppressed, Suppression, fingerprint};

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
    /// The projects scanned together, such as the services of a folder of
    /// microservices. Empty or a single entry for one project; reports
    /// split findings by project only when there are several.
    pub projects: Vec<Project>,
    /// Where findings open outside the report (editor, repository host).
    pub links: SourceLinks,
    /// Findings found but not reported: ignored in the code, or already in
    /// the baseline. Reports count them so nothing disappears silently.
    pub suppressed: Vec<Suppressed>,
    /// The cryptographic libraries the build files declare. An inventory
    /// next to the findings: it feeds no gate, baseline or SARIF result.
    pub dependencies: Vec<Dependency>,
}

/// The index of the project `path` belongs to: the one with the longest
/// root `path` is under.
pub fn project_of(projects: &[Project], path: &str) -> Option<usize> {
    projects
        .iter()
        .enumerate()
        .filter(|(_, p)| {
            p.root.is_empty()
                || path
                    .strip_prefix(p.root.as_str())
                    .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
        })
        .max_by_key(|(_, p)| p.root.len())
        .map(|(i, _)| i)
}

/// A project of a scan: the findings whose path is under `root`.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct Project {
    pub name: String,
    /// Directory as findings name it (`services/billing`), `/`-separated and
    /// without a trailing slash; empty for files that belong to no project.
    pub root: String,
    pub files_scanned: usize,
}

impl Scan {
    pub fn summary(&self) -> Summary {
        Summary::of(self)
    }

    /// The index in [`Scan::projects`] of the project `path` belongs to:
    /// the one with the longest matching root.
    pub fn project_of(&self, path: &str) -> Option<usize> {
        project_of(&self.projects, path)
    }

    /// The source line `line` (1-based) of `path`, if known.
    pub fn line(&self, path: &str, line: u32) -> Option<&str> {
        let index = usize::try_from(line).ok()?.checked_sub(1)?;
        self.sources.get(path)?.lines().nth(index)
    }
}

#[cfg(test)]
pub(crate) mod fixtures;
