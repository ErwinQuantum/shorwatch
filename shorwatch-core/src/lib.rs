//! # shorwatch-core
//!
//! The pure domain of Shorwatch. It knows nothing about parsers, files,
//! command lines or output formats:
//!
//! - [`ir`]: the language-neutral model that frontends produce.
//! - [`rule`]: the declarative rule model and its validation.
//! - [`analyze`]: evaluates a [`RuleSet`] against a [`SourceUnit`].
//! - [`link`]: cross-file resolution (config values injected into code).
//! - [`finding`]: what the engine reports.
//! - [`inventory`]: the cryptographic libraries a build file declares.

pub mod finding;
pub mod inventory;
pub mod ir;
pub mod rule;

mod engine;
mod link;

pub use engine::analyze;
pub use finding::{Finding, HybridEvidence, Status, SuggestedFix};
pub use inventory::{
    Dependency, Ecosystem, LibraryCatalog, LibraryError, LibrarySpec, dependencies,
};
pub use ir::{CodeRole, Language, Library, Platform, SourceUnit};
pub use link::link;
pub use rule::{
    Category, CryptoFunction, CryptoProperties, Primitive, Rule, RuleError, RuleSet, Severity,
};
