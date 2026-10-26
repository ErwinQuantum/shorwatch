//! # shorwatch-langs
//!
//! Language frontends: each one parses source text with tree-sitter and lowers
//! it into a [`shorwatch_core::SourceUnit`]. Nothing tree-sitter-specific
//! crosses this crate's public API.

use shorwatch_core::{Language, SourceUnit};
use thiserror::Error;

pub mod config;
pub mod java;
mod jvm;
pub mod kotlin;
mod span;

pub use config::{PropertiesFrontend, YamlFrontend};
pub use java::JavaFrontend;
pub use kotlin::KotlinFrontend;

#[derive(Debug, Error)]
pub enum LangError {
    #[error("failed to load the {0:?} grammar: {1}")]
    Grammar(Language, String),
    #[error("parser gave up on `{0}`")]
    Parse(String),
}

/// Lowers source text of one language into the core's intermediate model.
pub trait Frontend: Send + Sync {
    fn language(&self) -> Language;

    /// File extensions (without the dot) this frontend handles.
    fn extensions(&self) -> &'static [&'static str];

    /// `path` is only used as the unit's identifier; nothing is read from disk.
    fn lower(&self, path: &str, source: &str) -> Result<SourceUnit, LangError>;
}

/// Every built-in frontend.
pub fn frontends() -> Vec<Box<dyn Frontend>> {
    vec![
        Box::new(JavaFrontend),
        Box::new(KotlinFrontend),
        Box::new(PropertiesFrontend),
        Box::new(YamlFrontend),
    ]
}

/// The frontend registered for a file extension, if any.
pub fn for_extension(extension: &str) -> Option<Box<dyn Frontend>> {
    frontends().into_iter().find(|f| {
        f.extensions()
            .iter()
            .any(|e| e.eq_ignore_ascii_case(extension))
    })
}
