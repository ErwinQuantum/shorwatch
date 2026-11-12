//! The cryptographic libraries a project declares in its build files.
//!
//! A dependency is not a finding: using BouncyCastle is neither vulnerable nor
//! safe by itself. So the inventory sits next to the findings, never among
//! them (it feeds no gate, no baseline and no SARIF result). What it adds is
//! what source code cannot say: which libraries the build brings, in which
//! version, and whether that version can do post-quantum cryptography at all.
//! Which libraries are known, and from which version they can, is data (see
//! [`LibrarySpec`]); a version of a library that offers no post-quantum
//! algorithm is not marked either way.

use serde::Serialize;

use crate::ir::{FactKind, Language, Location, SourceUnit};

mod spec;
#[cfg(test)]
mod tests;
mod version;

pub use spec::{Coordinates, LibraryCatalog, LibraryError, LibrarySpec, PostQuantumSpec, Role};

/// A known cryptographic library found in a build file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Dependency {
    /// How the catalog names it (`BouncyCastle`).
    pub library: String,
    pub library_id: String,
    pub role: Role,
    pub ecosystem: Ecosystem,
    /// Maven group; empty for NuGet, whose packages have only an id.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub group: String,
    /// Maven artifact, or the NuGet package id.
    pub artifact: String,
    /// As the file declares it; see [`FactKind::Dependency`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// The build file.
    pub path: String,
    pub location: Location,
    /// Whether this version can do post-quantum cryptography; only for the
    /// libraries the catalog knows a first version for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_quantum: Option<PostQuantum>,
}

/// Where a dependency's coordinates come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Ecosystem {
    Maven,
    NuGet,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PostQuantum {
    pub support: Support,
    /// The first release that has it.
    pub since: String,
    pub algorithms: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Support {
    /// The declared version is at or after the first one with the algorithms.
    Ready,
    /// The declared version predates them: upgrading the library comes first.
    TooOld,
    /// The file does not say which version it uses (managed elsewhere, a
    /// range, an unresolved property).
    Unknown,
}

/// The known libraries `unit` declares, in file order.
pub fn dependencies(unit: &SourceUnit, catalog: &LibraryCatalog) -> Vec<Dependency> {
    unit.facts()
        .iter()
        .filter_map(|fact| {
            let FactKind::Dependency {
                group,
                artifact,
                version,
                scope,
            } = &fact.kind
            else {
                return None;
            };
            let ecosystem = if unit.language() == Language::NuGet {
                Ecosystem::NuGet
            } else {
                Ecosystem::Maven
            };
            let library = match ecosystem {
                Ecosystem::NuGet => catalog.find_package(artifact),
                Ecosystem::Maven => catalog.find(group, artifact),
            }?;
            let post_quantum = library.post_quantum.as_ref().map(|pq| PostQuantum {
                support: match version
                    .as_deref()
                    .and_then(|v| version::at_least(v, &pq.since))
                {
                    Some(true) => Support::Ready,
                    Some(false) => Support::TooOld,
                    None => Support::Unknown,
                },
                since: pq.since.clone(),
                algorithms: pq.algorithms.clone(),
            });
            Some(Dependency {
                library: library.name.clone(),
                library_id: library.id.clone(),
                role: library.role,
                ecosystem,
                group: group.clone(),
                artifact: artifact.clone(),
                version: version.clone(),
                scope: scope.clone(),
                path: unit.path().to_owned(),
                location: fact.location,
                post_quantum,
            })
        })
        .collect()
}
