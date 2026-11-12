//! # shorwatch-langs
//!
//! Language frontends: each one parses source text with tree-sitter and lowers
//! it into a [`shorwatch_core::SourceUnit`]. Nothing tree-sitter-specific
//! crosses this crate's public API. [`bytecode`] reads the declarations of
//! compiled dependencies.

use std::path::Path;

use shorwatch_core::{Language, SourceUnit};
use thiserror::Error;

pub mod build;
pub mod bytecode;
pub mod config;
pub mod csharp;
mod depth;
pub mod java;
pub mod keys;
pub mod kotlin;
mod managed;
mod span;
mod unsupported;

pub use build::{GradleFrontend, MavenFrontend, NuGetFrontend, VersionCatalogFrontend};
pub use config::{JsonFrontend, PropertiesFrontend, YamlFrontend};
pub use csharp::CSharpFrontend;
pub use java::JavaFrontend;
pub use keys::KeyMaterialFrontend;
pub use kotlin::KotlinFrontend;
pub use unsupported::unsupported_language;

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

    /// Exact file names it handles whatever their extension (`pom.xml`): for
    /// files too common in kind to claim by extension.
    fn file_names(&self) -> &'static [&'static str] {
        &[]
    }

    /// Whether this frontend handles a file of this exact name. By default,
    /// the names in [`Frontend::file_names`]; a family of names
    /// (`appsettings.*.json`) overrides it.
    fn accepts(&self, name: &str) -> bool {
        self.file_names().contains(&name)
    }

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
        Box::new(CSharpFrontend),
        Box::new(KeyMaterialFrontend),
        Box::new(PropertiesFrontend),
        Box::new(YamlFrontend),
        Box::new(JsonFrontend),
        Box::new(MavenFrontend),
        Box::new(GradleFrontend),
        Box::new(VersionCatalogFrontend),
        Box::new(NuGetFrontend),
    ]
}

/// The frontend for a file: by its exact name (`pom.xml`) or else by its
/// extension.
pub fn for_path(path: &Path) -> Option<Box<dyn Frontend>> {
    let name = path.file_name()?.to_str()?;
    frontends()
        .into_iter()
        .find(|f| f.accepts(name))
        .or_else(|| for_extension(path.extension()?.to_str()?))
}

/// The frontend registered for a file extension, if any.
pub fn for_extension(extension: &str) -> Option<Box<dyn Frontend>> {
    frontends().into_iter().find(|f| {
        f.extensions()
            .iter()
            .any(|e| e.eq_ignore_ascii_case(extension))
    })
}
