//! # shorwatch-langs
//!
//! Language frontends: each one parses source text with tree-sitter and lowers
//! it into a [`shorwatch_core::SourceUnit`]. Nothing tree-sitter-specific
//! crosses this crate's public API. [`bytecode`] reads the declarations of
//! compiled dependencies.

use shorwatch_core::{Language, SourceUnit};
use thiserror::Error;

pub mod bytecode;
pub mod config;
mod depth;
pub mod java;
mod jvm;
pub mod keys;
pub mod kotlin;
mod span;

pub use config::{PropertiesFrontend, YamlFrontend};
pub use java::JavaFrontend;
pub use keys::KeyMaterialFrontend;
pub use kotlin::KotlinFrontend;

#[derive(Debug, Error)]
pub enum LangError {
    #[error("failed to load the {0:?} grammar: {1}")]
    Grammar(Language, String),
    #[error("parser gave up on `{0}`")]
    Parse(String),
    #[error("`{0}` nests deeper than {1} levels")]
    TooDeep(String, usize),
    #[error("malformed class file: {0}")]
    Class(String),
}

/// Lowers source text of one language into the core's intermediate model.
pub trait Frontend: Send + Sync {
    fn language(&self) -> Language;

    /// File extensions (without the dot) this frontend handles.
    fn extensions(&self) -> &'static [&'static str];

    /// `path` is only used as the unit's identifier; nothing is read from disk.
    fn lower(&self, path: &str, source: &str) -> Result<SourceUnit, LangError>;

    /// Lowers a file's bytes, returning the text reports show alongside
    /// findings. Text formats [`decode`] them; binary ones keep no text.
    fn lower_bytes(
        &self,
        path: &str,
        bytes: Vec<u8>,
    ) -> Result<(SourceUnit, Option<String>), LangError> {
        let source = decode(bytes);
        let unit = self.lower(path, &source)?;
        Ok((unit, Some(source)))
    }
}

/// UTF-8, or else ISO-8859-1: the historical encoding of `.properties` files
/// and of older Java sources. Every byte is a Latin-1 character, so decoding
/// never fails; algorithm names and keys are ASCII either way.
pub fn decode(bytes: Vec<u8>) -> String {
    String::from_utf8(bytes)
        .unwrap_or_else(|error| error.into_bytes().into_iter().map(char::from).collect())
}

/// Every built-in frontend.
pub fn frontends() -> Vec<Box<dyn Frontend>> {
    vec![
        Box::new(JavaFrontend),
        Box::new(KotlinFrontend),
        Box::new(KeyMaterialFrontend),
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
