//! # shorwatch-rules
//!
//! Detection rules are data. This crate ships the built-in YAML rules
//! (embedded at compile time) and loads additional rule files from disk, so a
//! new detection never requires touching or recompiling the engine.
//!
//! A rules directory has four kinds of files, told apart by their location:
//!
//! - `algorithms/<profile>.yaml`: what an algorithm is and why it matters
//!   (category, severity, message, migration advice, references, hybrid
//!   markers). Written once per algorithm.
//! - `markers/<name>.yaml`: a named set of hybrid markers, referenced from
//!   profiles as `hybrid: <name>`.
//! - `libraries/<id>.yaml`: a cryptographic library a build file may declare
//!   (its Maven coordinates, and from which version it offers post-quantum
//!   algorithms, if it does). Not a rule: it feeds the dependency inventory.
//! - anything else, e.g. `jvm/nimbus/jose-rsa.yaml`: a rule, i.e. the patterns
//!   one library exposes, plus `profile: <profile>`. Its fields override the
//!   profile's, and a rule may also be fully self-contained.
//!
//! Schema validation happens in two layers: the assembled YAML must
//! deserialize into [`Rule`] (unknown fields are rejected), and the resulting
//! rules must pass [`RuleSet::compile`], which enforces the domain invariants.

use std::path::Path;

use serde_yaml_ng::Value;
pub use shorwatch_core::{LibraryCatalog, LibrarySpec, Rule, RuleError, RuleSet};

mod catalog;
mod error;
#[cfg(test)]
mod tests;

pub use catalog::Catalog;
use catalog::deserialize;
pub use error::LoadError;

/// Parses one self-contained rule (no profile). `origin` names the source in
/// error messages.
pub fn parse(origin: &str, yaml: &str) -> Result<Rule, LoadError> {
    let value: Value = serde_yaml_ng::from_str(yaml).map_err(|e| LoadError::Parse {
        origin: origin.to_owned(),
        message: e.to_string(),
    })?;
    deserialize(origin, value)
}

/// The rules shipped with Shorwatch.
pub fn builtin_rules() -> Result<Vec<Rule>, LoadError> {
    Catalog::builtin()?.rules()
}

/// The built-in rules, compiled.
pub fn builtin() -> Result<RuleSet, LoadError> {
    Ok(RuleSet::compile(builtin_rules()?)?)
}

/// The known libraries shipped with Shorwatch.
pub fn builtin_library_specs() -> Result<Vec<LibrarySpec>, LoadError> {
    Catalog::builtin()?.libraries()
}

/// The known libraries shipped with Shorwatch, compiled.
pub fn builtin_libraries() -> Result<LibraryCatalog, LoadError> {
    Ok(LibraryCatalog::compile(builtin_library_specs()?)?)
}

/// The libraries under `dir` (`libraries/<id>.yaml`), to add to the built-in ones.
pub fn load_dir_libraries(dir: &Path) -> Result<Vec<LibrarySpec>, LoadError> {
    let mut catalog = Catalog::default();
    catalog.add_dir(dir)?;
    catalog.libraries()
}

/// The rules under `dir`. They may use the built-in profiles and markers as
/// well as their own.
pub fn load_dir(dir: &Path) -> Result<Vec<Rule>, LoadError> {
    let mut catalog = Catalog::builtin()?;
    let builtin = catalog.rules.len();
    catalog.add_dir(dir)?;
    catalog.rules[builtin..]
        .iter()
        .map(|r| catalog.assemble(r))
        .collect()
}
